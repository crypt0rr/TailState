package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestOutboxDestinationCountsUseIndexedPlan asserts that the per-destination
// delivery counts reach outbox rows through outbox_destination_status. Without
// that index SQLite builds a temporary automatic index over the outbox on every
// status-page refresh, so the cost grows with the whole outbox.
func TestOutboxDestinationCountsUseIndexedPlan(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if !storeIndexNames(t, st)["outbox_destination_status"] {
		t.Fatal("outbox_destination_status index is missing")
	}
	rows, err := st.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+destinationDeliveriesSQL())
	if err != nil {
		t.Fatalf("explain destination deliveries: %v", err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	searched := false
	for _, step := range plan {
		if strings.Contains(step, "AUTOMATIC") || strings.Contains(step, "TEMP B-TREE") {
			t.Errorf("plan step %q builds a temporary index or sort; plan=%q", step, plan)
		}
		if strings.HasPrefix(step, "SCAN o") {
			t.Errorf("plan step %q scans the outbox; plan=%q", step, plan)
		}
		if strings.HasPrefix(step, "SEARCH ") && strings.Contains(step, "outbox_destination_status") {
			searched = true
		}
	}
	if !searched {
		t.Errorf("plan does not search the outbox through outbox_destination_status; plan=%q", plan)
	}
}

// TestOutboxDestinationCountsExcludeDeliveredAndRemovedDestinations pins the
// per-destination counts behind the status page and notification settings.
// Delivered rows are never counted, a destination with no counted rows is still
// listed with zeros, and a removed destination is not listed at all.
func TestOutboxDestinationCountsExcludeDeliveredAndRemovedDestinations(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	// SaveSettings creates the Mattermost destination from settings(). It has no
	// rows, so it is listed with zero counts like Idle.
	var mattermost int64
	if err := st.db.QueryRowContext(ctx, "SELECT id FROM notification_destinations WHERE name='Mattermost' AND deleted_at IS NULL").Scan(&mattermost); err != nil {
		t.Fatal(err)
	}
	saveDestination := func(name string) int64 {
		t.Helper()
		id, err := st.SaveDestination(ctx, NotificationDestination{Name: name, ServiceURL: "generic://" + strings.ToLower(name) + ".example/hook", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	pager := saveDestination("Pager")
	chat := saveDestination("Chat")
	idle := saveDestination("Idle")
	removed := saveDestination("Removed")

	old := time.Now().UTC().Add(-30 * time.Hour).Format(time.RFC3339Nano)
	insertBatch := func(gen int64) int64 {
		t.Helper()
		result, err := st.db.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(?,?,1,?)", gen, old, old)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		return id
	}
	current := insertBatch(generation)
	previous := insertBatch(generation - 1)
	insertOutbox := func(destinationID int64, batch any, status, lastError string) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,status,attempts,next_attempt,first_attempt,last_error,created_at) VALUES(?,?,?,?,1,?,?,?,?)", batch, destinationID, "payload", status, old, old, lastError, old); err != nil {
			t.Fatal(err)
		}
	}
	// Pager: two pending, one processing, and four dead rows. Two of the dead
	// rows are retryable (a system notification without a batch, and one from
	// the current generation); the identity-changed and previous-generation rows
	// are not. Its two delivered rows must not be counted.
	insertOutbox(pager, current, "pending", "")
	insertOutbox(pager, nil, "pending", "")
	insertOutbox(pager, current, "processing", "")
	insertOutbox(pager, current, "dead", "delivery retry window expired")
	insertOutbox(pager, nil, "dead", "notification rejected by provider (HTTP 401)")
	insertOutbox(pager, current, "dead", "monitoring identity changed")
	insertOutbox(pager, previous, "dead", "delivery retry window expired")
	insertOutbox(pager, current, "delivered", "")
	insertOutbox(pager, current, "delivered", "")
	// Chat holds only delivered rows, so every count is zero.
	insertOutbox(chat, current, "delivered", "")
	// Removing Removed dead-letters its pending row and drops it from the list.
	insertOutbox(removed, current, "pending", "")
	if err := st.DeleteDestination(ctx, removed); err != nil {
		t.Fatal(err)
	}

	deliveries, err := st.DestinationDeliveries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []DestinationDelivery{
		{ID: mattermost, Name: "Mattermost", Enabled: true},
		{ID: pager, Name: "Pager", Enabled: true, Pending: 2, Processing: 1, Dead: 4, RetryableDead: 2},
		{ID: chat, Name: "Chat", Enabled: true},
		{ID: idle, Name: "Idle", Enabled: true},
	}
	if len(deliveries) != len(want) {
		t.Fatalf("deliveries=%#v, want %d active destinations", deliveries, len(want))
	}
	for i := range want {
		if deliveries[i] != want[i] {
			t.Fatalf("delivery %d=%#v, want %#v", i, deliveries[i], want[i])
		}
	}
}

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestOldestPendingQueueAgesReadTheQueueHead pins what the queue-age gauges
// report: each active destination's lowest pending row, ignoring delivered and
// dead rows, the oldest pending webhook trigger, and an empty zero time when
// nothing is pending. It also checks that the per-destination lookup is served
// by the destination index.
func TestOldestPendingQueueAgesReadTheQueueHead(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
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

	insertOutbox := func(destinationID int64, status string, created time.Time) {
		t.Helper()
		value := formatTimestamp(created)
		if _, err := st.db.ExecContext(ctx, "INSERT INTO outbox(destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(?,?,?,?,?,?)", destinationID, "payload", status, value, value, value); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	// Pager's delivered and dead rows come first in ID order, so only the
	// pending rows decide its head. The head is the 5-hour-old row, not the
	// younger row queued after it.
	insertOutbox(pager, "delivered", now.Add(-10*time.Hour))
	insertOutbox(pager, "dead", now.Add(-9*time.Hour))
	head := now.Add(-5 * time.Hour)
	insertOutbox(pager, "pending", head)
	insertOutbox(pager, "pending", now.Add(-1*time.Hour))
	insertOutbox(chat, "dead", now.Add(-8*time.Hour))
	insertOutbox(removed, "pending", now.Add(-7*time.Hour))
	if err := st.DeleteDestination(ctx, removed); err != nil {
		t.Fatal(err)
	}

	deadTrigger, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("0", 64), []string{"node.updated"}, []string{"devices"})
	if err != nil {
		t.Fatal(err)
	}
	pendingTrigger, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("1", 64), []string{"node.updated"}, []string{"devices"})
	if err != nil {
		t.Fatal(err)
	}
	// The older trigger is dead, so the head is the 4-hour-old pending one.
	triggerHead := now.Add(-4 * time.Hour)
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=?,status='dead' WHERE id=?", formatTimestamp(now.Add(-9*time.Hour)), deadTrigger.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=? WHERE id=?", formatTimestamp(triggerHead), pendingTrigger.ID); err != nil {
		t.Fatal(err)
	}

	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.WebhookOldestPending.Equal(triggerHead) {
		t.Fatalf("webhook oldest pending = %v, want %v", status.WebhookOldestPending, triggerHead)
	}
	want := []DestinationOldestPending{
		{DestinationID: pager, Enqueued: head},
		{DestinationID: chat},
		{DestinationID: idle},
	}
	got := status.OutboxOldestPending
	if len(got) != len(want) {
		t.Fatalf("outbox oldest pending = %+v, want %d active destinations", got, len(want))
	}
	for i := range want {
		if got[i].DestinationID != want[i].DestinationID || !got[i].Enqueued.Equal(want[i].Enqueued) {
			t.Fatalf("outbox oldest pending %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	rows, err := st.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+oldestPendingOutboxSQL())
	if err != nil {
		t.Fatalf("explain oldest pending outbox: %v", err)
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
		if strings.Contains(step, "AUTOMATIC") {
			t.Errorf("plan step %q builds a temporary index; plan=%q", step, plan)
		}
		if strings.HasPrefix(step, "SCAN o") {
			t.Errorf("plan step %q scans the outbox; plan=%q", step, plan)
		}
		if strings.Contains(step, "outbox_destination_status") {
			searched = true
		}
	}
	if !searched {
		t.Errorf("plan does not search the outbox through outbox_destination_status; plan=%q", plan)
	}
}

// TestOldestPendingQueueAgesRejectCorruptTimestamps checks that a timestamp the
// store cannot read fails the status read, so the metrics scrape fails cleanly
// instead of reporting a false age.
func TestOldestPendingQueueAgesRejectCorruptTimestamps(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, corrupt, want string }{
		{"outbox created_at", "UPDATE outbox SET created_at='not-a-time'", "parse outbox created_at timestamp"},
		{"webhook received_at", "UPDATE webhook_triggers SET received_at='not-a-time'", "parse webhook received_at timestamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := testStore(t)
			if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "Corrupt", ServiceURL: "generic://corrupt.example/hook", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if err := st.EnqueueSystem(ctx, "payload"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("2", 64), []string{"node.updated"}, []string{"devices"}); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, tc.corrupt); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Status(ctx); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("status with a corrupt %s: err=%v, want %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestCleanupLastSuccessMovesOnlyForCompletedPasses checks that the cleanup
// timestamp is zero before any pass, moves when a pass completes, and stays
// where it was when a pass fails before it starts.
func TestCleanupLastSuccessMovesOnlyForCompletedPasses(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if got := st.LastCleanupSuccess(); !got.IsZero() {
		t.Fatalf("last cleanup success before any pass = %v, want zero", got)
	}
	before := time.Now()
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	completed := st.LastCleanupSuccess()
	if completed.Before(before) || completed.After(time.Now()) {
		t.Fatalf("last cleanup success = %v after a pass started at %v", completed, before)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := st.Cleanup(cancelled, 30*24*time.Hour); err == nil {
		t.Fatal("cleanup with a cancelled context reported success")
	}
	if got := st.LastCleanupSuccess(); !got.Equal(completed) {
		t.Fatalf("cancelled pass moved last cleanup success to %v, want %v", got, completed)
	}
}

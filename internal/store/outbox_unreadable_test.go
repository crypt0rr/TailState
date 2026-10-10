package store

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// TestUndecryptableDestinationDoesNotBlockDelivery guards R-055: a
// destination whose URL was sealed under another master key must not stop
// the claim. Its due row is dead-lettered with a reason naming it, the other
// destination's row is still claimed and delivered, and the destination stays
// listed (flagged) so it can be repaired, disabled, or removed.
func TestUndecryptableDestinationDoesNotBlockDelivery(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	existing, err := st.ListDestinations(ctx)
	if err != nil || len(existing) != 1 {
		t.Fatalf("settings destination=%#v err=%v", existing, err)
	}
	good := existing[0].ID
	bad, err := st.SaveDestination(ctx, NotificationDestination{Name: "stale key", ServiceURL: "generic://stale.example/path", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := secret.NewBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := foreign.Seal(destinationBinding(bad), "generic://stale.example/path")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc=? WHERE id=?", sealed, bad); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{"first", "second"} {
		if err := st.EnqueueSystem(ctx, payload); err != nil {
			t.Fatal(err)
		}
	}

	items, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("one undecryptable destination failed the claim: %v", err)
	}
	if len(items) != 2 || items[0].DestinationID != good || items[1].DestinationID != good || items[0].Destination.ServiceURL == "" {
		t.Fatalf("claimed=%#v", items)
	}
	for _, item := range items {
		if delivered, err := st.DeliveredClaimedResult(ctx, item); err != nil || !delivered {
			t.Fatalf("deliver good row delivered=%v err=%v", delivered, err)
		}
	}
	rows, err := st.db.QueryContext(ctx, "SELECT status,last_error FROM outbox WHERE destination_id=? ORDER BY id", bad)
	if err != nil {
		t.Fatal(err)
	}
	dead := 0
	for rows.Next() {
		var status, reason string
		if err := rows.Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		if status != "dead" || !strings.Contains(reason, "destination "+strconv.FormatInt(bad, 10)+" (stale key)") || !strings.Contains(reason, "cannot be decrypted") {
			t.Fatalf("undecryptable row status=%q reason=%q", status, reason)
		}
		dead++
	}
	if err := rows.Close(); err != nil || dead != 2 {
		t.Fatalf("dead rows=%d err=%v", dead, err)
	}
	if again, err := st.ClaimDueOutbox(ctx, 10); err != nil || len(again) != 0 {
		t.Fatalf("second claim=%#v err=%v", again, err)
	}

	list, err := st.ListDestinations(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("destinations=%#v err=%v", list, err)
	}
	for _, destination := range list {
		if unreadable := destination.ID == bad; destination.ServiceURLUnreadable != unreadable || (destination.ServiceURL == "") != unreadable {
			t.Fatalf("destination %d flagged=%v url=%q", destination.ID, destination.ServiceURLUnreadable, destination.ServiceURL)
		}
	}
	deliveries, err := st.DestinationDeliveries(ctx)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries=%#v err=%v", deliveries, err)
	}
	for _, delivery := range deliveries {
		if unreadable := delivery.ID == bad; delivery.ServiceURLUnreadable != unreadable {
			t.Fatalf("delivery state %#v", delivery)
		}
		if delivery.ID == bad && (delivery.Dead != 2 || delivery.RetryableDead != 2 || delivery.Pending != 0) {
			t.Fatalf("undecryptable destination counts %#v", delivery)
		}
	}

	// Saving the destination with its URL again re-seals it under the
	// current key; its dead letters can then be retried and delivered.
	if _, err := st.SaveDestination(ctx, NotificationDestination{ID: bad, Name: "stale key", ServiceURL: "generic://stale.example/path", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if requeued, err := st.RetryDeadOutbox(ctx, bad); err != nil || requeued != 2 {
		t.Fatalf("requeued=%d err=%v", requeued, err)
	}
	items, err = st.ClaimDueOutbox(ctx, 10)
	if err != nil || len(items) != 2 || items[0].DestinationID != bad || items[0].Destination.ServiceURL != "generic://stale.example/path" {
		t.Fatalf("repaired claim=%#v err=%v", items, err)
	}
	if deliveries, err := st.DestinationDeliveries(ctx); err != nil || deliveries[1].ServiceURLUnreadable {
		t.Fatalf("repaired delivery state=%#v err=%v", deliveries, err)
	}
}

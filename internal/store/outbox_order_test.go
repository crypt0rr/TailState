package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

func claimedPayloads(items []OutboxItem, destinationID int64) []string {
	var payloads []string
	for _, item := range items {
		if item.DestinationID == destinationID {
			payloads = append(payloads, item.Payload)
		}
	}
	return payloads
}

// TestClaimDueOutboxKeepsDestinationOrder checks that a destination's younger
// rows are never claimed ahead of an older live row: a row backing off after
// a failure, or still in flight, holds them back, while other destinations
// are unaffected. Released rows do not count an attempt.
func TestClaimDueOutboxKeepsDestinationOrder(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	other, err := st.SaveDestination(ctx, NotificationDestination{Name: "Other", ServiceURL: "generic://other.example/path", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if err := st.EnqueueSystem(ctx, fmt.Sprintf("msg-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	items, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 6 {
		t.Fatalf("claimed %d rows, want 6", len(items))
	}
	var primary int64
	for _, item := range items {
		if item.DestinationID != other {
			primary = item.DestinationID
		}
	}
	want := []string{"msg-0", "msg-1", "msg-2"}
	if got := claimedPayloads(items, primary); !slices.Equal(got, want) {
		t.Fatalf("primary claim order=%v", got)
	}
	// The oldest primary row fails and backs off; its younger rows were not
	// sent and are released. The other destination succeeds.
	var held []OutboxItem
	for _, item := range items {
		switch {
		case item.DestinationID == other:
			if err := st.DeliveredClaimed(ctx, item); err != nil {
				t.Fatal(err)
			}
		case item.Payload == "msg-0":
			if err := st.RetryClaimed(ctx, item, time.Now().Add(time.Hour), "down", false); err != nil {
				t.Fatal(err)
			}
		default:
			released, err := st.ReleaseClaimed(ctx, item)
			if err != nil || !released {
				t.Fatalf("release row %d released=%t err=%v", item.ID, released, err)
			}
			held = append(held, item)
		}
	}
	if released, err := st.ReleaseClaimed(ctx, held[0]); err != nil || released {
		t.Fatalf("second release with a stale token released=%t err=%v", released, err)
	}
	if released, err := st.ReleaseClaimed(ctx, OutboxItem{}); err != nil || released {
		t.Fatalf("release without a claim released=%t err=%v", released, err)
	}
	var attempts int
	if err := st.db.QueryRowContext(ctx, "SELECT attempts FROM outbox WHERE id=?", held[0].ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("released row attempts=%d, want 0", attempts)
	}

	if err := st.EnqueueSystem(ctx, "msg-3"); err != nil {
		t.Fatal(err)
	}
	items, err = st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := claimedPayloads(items, primary); len(got) != 0 {
		t.Fatalf("younger rows were claimed past a backing-off row: %v", got)
	}
	if got := claimedPayloads(items, other); !slices.Equal(got, []string{"msg-3"}) {
		t.Fatalf("other destination was held back: %v", got)
	}
	for _, item := range items {
		if err := st.DeliveredClaimed(ctx, item); err != nil {
			t.Fatal(err)
		}
	}

	// Once the old row is due, the destination's rows come back in order. A
	// limit of one leaves msg-0 in flight, which also holds the rest back.
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET next_attempt=? WHERE destination_id=? AND payload='msg-0'", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), primary); err != nil {
		t.Fatal(err)
	}
	first, err := st.ClaimDueOutbox(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := claimedPayloads(first, primary); !slices.Equal(got, []string{"msg-0"}) {
		t.Fatalf("first claim after recovery=%v", got)
	}
	blocked, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 0 {
		t.Fatalf("rows were claimed past an in-flight row: %d", len(blocked))
	}
	if err := st.DeliveredClaimed(ctx, first[0]); err != nil {
		t.Fatal(err)
	}
	rest, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := claimedPayloads(rest, primary); !slices.Equal(got, []string{"msg-1", "msg-2", "msg-3"}) {
		t.Fatalf("recovered claim order=%v", got)
	}
}

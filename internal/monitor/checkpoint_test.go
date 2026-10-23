package monitor

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestLedgerCheckpointNotificationCarriesSignedHead runs the scheduler against
// a real ledger. The queued notification must name the sequence, head, and key
// ID that the store reports, and the scheduler must not send again inside the
// interval.
func TestLedgerCheckpointNotificationCarriesSignedHead(t *testing.T) {
	st, settings := monitorTestStore(t)
	ctx := context.Background()
	engine := engineWithStore(st)
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) == 0 {
		t.Fatalf("destinations=%d err=%v", len(destinations), err)
	}
	if err := st.SetEvidenceCheckpointDestination(ctx, destinations[0].ID); err != nil {
		t.Fatal(err)
	}
	// The first poll is a silent baseline, so the second one provides the ledger entry.
	expires := time.Now().Add(365 * 24 * time.Hour)
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{expiryDevice("n1", "first", expires, nil)}, nil)
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{expiryDevice("n1", "second", expires, nil)}, nil)
	now := time.Now().UTC()
	if sent, err := engine.CheckLedgerCheckpoint(ctx, now); err != nil || !sent {
		t.Fatalf("first checkpoint sent=%t err=%v", sent, err)
	}
	if sent, err := engine.CheckLedgerCheckpoint(ctx, now.Add(time.Minute)); err != nil || sent {
		t.Fatalf("checkpoint inside the interval sent=%t err=%v", sent, err)
	}
	status, err := st.EvidenceCheckpointStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := st.EvidenceSigningKeyID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var rendered string
	for _, payload := range pendingPayloads(t, st) {
		if strings.Contains(payload, "TailState evidence checkpoint") {
			rendered = payload
		}
	}
	for _, want := range []string{"Sequence:", strconv.FormatInt(status.LastSequence, 10), "Ledger head:", status.LastHead, "Signing key:", keyID, "Signature:"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("checkpoint notification lacks %q:\n%s", want, rendered)
		}
	}
}

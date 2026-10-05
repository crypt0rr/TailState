package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

var testTime = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func pendingPayloads(t *testing.T, st *Store, batchID int64) []string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), "SELECT payload FROM outbox WHERE COALESCE(batch_id,0)=? ORDER BY id", batchID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, payload)
	}
	return out
}

// TestDigestLinksItsHistoryBatchOnlyWhenPublicURLIsSet guards E-010: with
// TAILSTATE_PUBLIC_URL configured, a queued digest links to exactly the
// History batch it describes, and that link resolves through the History
// batch filter; without a public URL no link is emitted.
func TestDigestLinksItsHistoryBatchOnlyWhenPublicURLIsSet(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	linked := notify.Context{Tailnet: "example.com", PublicURL: "https://tailstate.example"}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("one", "100.64.0.1")}, linked.Digest); err != nil {
		t.Fatal(err)
	}
	first, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("two", "100.64.0.1")}, linked.Digest)
	if err != nil || first.ID == 0 {
		t.Fatalf("first batch=%+v err=%v", first, err)
	}
	payloads := pendingPayloads(t, st, first.ID)
	if len(payloads) != 1 || !strings.Contains(payloads[0], fmt.Sprintf("(https://tailstate.example/history?batch=%d)", first.ID)) || !strings.Contains(payloads[0], "· example.com") || !strings.Contains(payloads[0], "Observed at "+first.ObservedAt.UTC().Format("2006-01-02T15:04:05Z")) {
		t.Fatalf("digest payload does not link its batch: %q", payloads)
	}
	unlinked := notify.Context{Tailnet: "example.com"}
	second, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("three", "100.64.0.1")}, unlinked.Digest)
	if err != nil || second.ID == 0 {
		t.Fatalf("second batch=%+v err=%v", second, err)
	}
	if payloads := pendingPayloads(t, st, second.ID); len(payloads) != 1 || strings.Contains(payloads[0], "/history?batch=") {
		t.Fatalf("digest without a public URL contains a link: %q", payloads)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{BatchID: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 1 || page.Batches[0].ID != first.ID || page.HasNext {
		t.Fatalf("batch filter returned %+v", page.Batches)
	}
	pack, err := st.ExportEvidencePack(ctx, HistoryFilter{BatchID: second.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(pack); err != nil {
		t.Fatalf("batch-filtered evidence pack did not verify: %v", err)
	}
	if !strings.Contains(string(pack), fmt.Sprintf(`"batch": %d`, second.ID)) {
		t.Fatalf("evidence pack does not record the batch filter")
	}
}

func TestEnqueueMessageAndUpdateNotificationCarryContext(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueMessage(ctx, notify.Context{Tailnet: "corp.example"}.CollectorsRecovered([]string{"devices"}, testTime)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TrackAppVersion(ctx, "1.0.0", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TrackAppVersion(ctx, "1.1.0", func(previous, current string) notify.Message {
		return notify.Context{Tailnet: "corp.example"}.Update(previous, current, testTime)
	}); err != nil {
		t.Fatal(err)
	}
	payloads := pendingPayloads(t, st, 0)
	if len(payloads) != 2 {
		t.Fatalf("payloads=%q", payloads)
	}
	for _, payload := range payloads {
		if !strings.Contains(payload, "· corp.example") || !strings.Contains(payload, "Observed at 2026-10-05T12:00:00Z") {
			t.Fatalf("system message lacks context: %q", payload)
		}
	}
}

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

// scanRenderedPayload reads payload_format and payload and renders the row
// as Markdown, the format a generic destination receives.
func scanRenderedPayload(t *testing.T, rows interface{ Scan(...any) error }, extra ...any) string {
	t.Helper()
	var format, payload string
	if err := rows.Scan(append(extra, &format, &payload)...); err != nil {
		t.Fatal(err)
	}
	rendered, err := notify.Prepare(format, payload, "", notify.FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

func pendingPayloads(t *testing.T, st *Store, batchID int64) []string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), "SELECT payload_format,payload FROM outbox WHERE COALESCE(batch_id,0)=? ORDER BY id", batchID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		out = append(out, scanRenderedPayload(t, rows))
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
	if len(payloads) != 1 || !strings.Contains(payloads[0], fmt.Sprintf("(https://tailstate.example/history?batch=%d)", first.ID)) || !strings.Contains(payloads[0], "· example.com") || !strings.Contains(payloads[0], "\n"+first.ObservedAt.UTC().Format("2 Jan 2006 15:04 UTC")) {
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
		if !strings.Contains(payload, "· corp.example") || !strings.Contains(payload, "Observed at 5 Oct 2026 12:00 UTC") {
			t.Fatalf("system message lacks context: %q", payload)
		}
	}
}

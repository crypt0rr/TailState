package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

func historyBatchIDs(page HistoryPage) []int64 {
	ids := make([]int64, 0, len(page.Batches))
	for _, batch := range page.Batches {
		ids = append(ids, batch.ID)
	}
	return ids
}

func seedHistoryBatches(t *testing.T, st *Store, count int) []int64 {
	t.Helper()
	ctx := context.Background()
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, notify.TextDigest("baseline")); err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, count)
	for index := range count {
		batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource(fmt.Sprintf("server-%d", index), "100.64.0.1")}, notify.TextDigest("change"))
		if err != nil {
			t.Fatal(err)
		}
		if batch.ID == 0 {
			t.Fatalf("change %d produced no batch", index)
		}
		ids = append(ids, batch.ID)
	}
	return ids
}

func TestHistoryPagesInBothDirections(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	ids := seedHistoryBatches(t, st, 5) // ids[0] oldest ... ids[4] newest

	newest, err := st.ListHistory(ctx, HistoryFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(newest); fmt.Sprint(got) != fmt.Sprint([]int64{ids[4], ids[3]}) || !newest.HasNext || newest.HasPrev {
		t.Fatalf("newest page=%v hasNext=%v hasPrev=%v", got, newest.HasNext, newest.HasPrev)
	}
	middle, err := st.ListHistory(ctx, HistoryFilter{Limit: 2, Cursor: newest.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(middle); fmt.Sprint(got) != fmt.Sprint([]int64{ids[2], ids[1]}) || !middle.HasNext || !middle.HasPrev || middle.PrevCursor != ids[2] {
		t.Fatalf("middle page=%v hasNext=%v hasPrev=%v prev=%d", got, middle.HasNext, middle.HasPrev, middle.PrevCursor)
	}
	oldest, err := st.ListHistory(ctx, HistoryFilter{Limit: 2, Cursor: middle.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(oldest); fmt.Sprint(got) != fmt.Sprint([]int64{ids[0]}) || oldest.HasNext || !oldest.HasPrev || oldest.PrevCursor != ids[0] {
		t.Fatalf("oldest page=%v hasNext=%v hasPrev=%v prev=%d", got, oldest.HasNext, oldest.HasPrev, oldest.PrevCursor)
	}

	// Paging back towards newer batches returns the adjacent page, newest
	// first, and links both ways.
	back, err := st.ListHistory(ctx, HistoryFilter{Limit: 2, After: oldest.PrevCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(back); fmt.Sprint(got) != fmt.Sprint([]int64{ids[2], ids[1]}) || !back.HasPrev || back.PrevCursor != ids[2] || !back.HasNext || back.NextCursor != ids[1] {
		t.Fatalf("newer page=%v hasPrev=%v prev=%d hasNext=%v next=%d", got, back.HasPrev, back.PrevCursor, back.HasNext, back.NextCursor)
	}
	top, err := st.ListHistory(ctx, HistoryFilter{Limit: 2, After: back.PrevCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(top); fmt.Sprint(got) != fmt.Sprint([]int64{ids[4], ids[3]}) || top.HasPrev || !top.HasNext || top.NextCursor != ids[3] {
		t.Fatalf("top page=%v hasPrev=%v hasNext=%v next=%d", got, top.HasPrev, top.HasNext, top.NextCursor)
	}
	// Cursor wins over After, so a malformed URL cannot mix directions.
	mixed, err := st.ListHistory(ctx, HistoryFilter{Limit: 2, Cursor: ids[2], After: ids[4]})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(mixed); fmt.Sprint(got) != fmt.Sprint([]int64{ids[1], ids[0]}) {
		t.Fatalf("cursor+after page=%v", got)
	}
}

func TestHistoryNewerPageRespectsByteBudget(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	ids := seedHistoryBatches(t, st, 3)
	estimate, err := st.historyBatchByteEstimate(ctx, ids[1], HistoryFilter{}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Room for exactly one batch: the newer page loads the batch nearest the
	// cursor and offers the rest through the newer link.
	page, err := st.listHistory(ctx, HistoryFilter{Limit: 5, After: ids[0]}, estimate+estimate/2, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(page); fmt.Sprint(got) != fmt.Sprint([]int64{ids[1]}) || !page.Truncated || !page.HasPrev || page.PrevCursor != ids[1] || !page.HasNext {
		t.Fatalf("budgeted newer page=%v truncated=%v hasPrev=%v prev=%d hasNext=%v", got, page.Truncated, page.HasPrev, page.PrevCursor, page.HasNext)
	}
	// A budget below one batch keeps a retry cursor just below it.
	tiny, err := st.listHistory(ctx, HistoryFilter{Limit: 5, After: ids[0]}, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tiny.Batches) != 0 || !tiny.Truncated || tiny.PrevCursor != ids[1]-1 {
		t.Fatalf("tiny newer page=%#v", tiny)
	}
}

func TestHistoryDateRangeFilter(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	ids := seedHistoryBatches(t, st, 4)
	// A fractional second just after midnight, a batch exactly at the
	// exclusive end, and batches outside the range on either side.
	for index, observed := range []string{"2026-09-30T23:59:59.999Z", "2026-10-01T00:00:00.5Z", "2026-10-01T23:59:59.25Z", "2026-10-02T00:00:00Z"} {
		if _, err := st.db.ExecContext(ctx, "UPDATE event_batches SET observed_at=? WHERE id=?", observed, ids[index]); err != nil {
			t.Fatal(err)
		}
	}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	until := from.Add(24 * time.Hour)
	page, err := st.ListHistory(ctx, HistoryFilter{From: from, Until: until, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(page); fmt.Sprint(got) != fmt.Sprint([]int64{ids[2], ids[1]}) {
		t.Fatalf("one-day range returned %v, want %v", got, []int64{ids[2], ids[1]})
	}
	openEnded, err := st.ListHistory(ctx, HistoryFilter{From: from, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(openEnded); fmt.Sprint(got) != fmt.Sprint([]int64{ids[3], ids[2], ids[1]}) {
		t.Fatalf("from-only range returned %v", got)
	}
	untilOnly, err := st.ListHistory(ctx, HistoryFilter{Until: from, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := historyBatchIDs(untilOnly); fmt.Sprint(got) != fmt.Sprint([]int64{ids[0]}) {
		t.Fatalf("until-only range returned %v", got)
	}
	// Paging within a range never leaves it.
	first, err := st.ListHistory(ctx, HistoryFilter{From: from, Until: until, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.ListHistory(ctx, HistoryFilter{From: from, Until: until, Limit: 1, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if !first.HasNext || second.HasNext || !second.HasPrev || historyBatchIDs(second)[0] != ids[1] {
		t.Fatalf("ranged paging first=%v/%v second=%v/%v/%v", historyBatchIDs(first), first.HasNext, historyBatchIDs(second), second.HasNext, second.HasPrev)
	}
}

func TestHistoryDateRangeEvidencePackVerifies(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	ids := seedHistoryBatches(t, st, 2)
	from := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	until := from.Add(2 * time.Hour)
	// After is ignored by exports, which always page towards older batches.
	pack, err := st.ExportEvidencePack(ctx, HistoryFilter{From: from, Until: until, After: ids[1]})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(pack); err != nil {
		t.Fatalf("ranged evidence pack does not verify: %v", err)
	}
	var decoded struct {
		Filter  map[string]any `json:"filter"`
		Batches []struct {
			ID int64 `json:"id"`
		} `json:"batches"`
	}
	if err := json.Unmarshal(pack, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Filter["from"] != from.Format(time.RFC3339) || decoded.Filter["until"] != until.Format(time.RFC3339) || len(decoded.Batches) != 2 {
		t.Fatalf("ranged evidence filter=%v batches=%d", decoded.Filter, len(decoded.Batches))
	}
	past, err := st.ExportEvidencePack(ctx, HistoryFilter{Until: from})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(past, &decoded); err != nil || len(decoded.Batches) != 0 {
		t.Fatalf("range before every batch exported %d batches err=%v", len(decoded.Batches), err)
	}
	unranged, err := st.ExportEvidencePack(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unranged), `"from"`) || strings.Contains(string(unranged), `"until"`) {
		t.Fatal("an unranged pack must keep its original filter shape")
	}
}

func TestRetryDeadOutboxRequeuesOnlyCurrentIdentityForEnabledDestination(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	destination, err := st.SaveDestination(ctx, NotificationDestination{Name: "Pager", ServiceURL: "generic://pager.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.SaveDestination(ctx, NotificationDestination{Name: "Chat", ServiceURL: "generic://chat.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-30 * time.Hour).Format(time.RFC3339Nano)
	insertBatch := func(gen int64) int64 {
		result, err := st.db.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(?,?,1,?)", gen, old, old)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		return id
	}
	current := insertBatch(generation)
	previous := insertBatch(generation - 1)
	insertOutbox := func(destinationID int64, batch any, status, lastError string) int64 {
		result, err := st.db.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,status,attempts,next_attempt,first_attempt,last_error,created_at) VALUES(?,?,?,?,7,?,?,?,?)", batch, destinationID, "payload", status, old, old, lastError, old)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		return id
	}
	retryable := []int64{
		insertOutbox(destination, current, "dead", "delivery retry window expired"),
		insertOutbox(destination, nil, "dead", "notification rejected by provider (HTTP 401)"),
	}
	identityChanged := insertOutbox(destination, current, "dead", "monitoring identity changed")
	previousGeneration := insertOutbox(destination, previous, "dead", "delivery retry window expired")
	pending := insertOutbox(destination, current, "pending", "")
	otherDead := insertOutbox(other, current, "dead", "delivery retry window expired")

	deliveries, err := st.DestinationDeliveries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]DestinationDelivery{}
	for _, delivery := range deliveries {
		byID[delivery.ID] = delivery
	}
	if got := byID[destination]; got.Name != "Pager" || !got.Enabled || got.Pending != 1 || got.Dead != 4 || got.RetryableDead != 2 {
		t.Fatalf("pager deliveries=%#v", got)
	}

	requeued, err := st.RetryDeadOutbox(ctx, destination)
	if err != nil || requeued != 2 {
		t.Fatalf("requeued=%d err=%v", requeued, err)
	}
	cutoff := time.Now().UTC().Add(-time.Minute)
	for _, id := range retryable {
		var status, firstAttempt, nextAttempt, lastError string
		var attempts int
		if err := st.db.QueryRowContext(ctx, "SELECT status,attempts,first_attempt,next_attempt,last_error FROM outbox WHERE id=?", id).Scan(&status, &attempts, &firstAttempt, &nextAttempt, &lastError); err != nil {
			t.Fatal(err)
		}
		first, _ := time.Parse(time.RFC3339Nano, firstAttempt)
		next, _ := time.Parse(time.RFC3339Nano, nextAttempt)
		if status != "pending" || attempts != 0 || lastError != "" || first.Before(cutoff) || next.Before(cutoff) {
			t.Fatalf("row %d not requeued with a fresh window: status=%s attempts=%d first=%s next=%s error=%q", id, status, attempts, firstAttempt, nextAttempt, lastError)
		}
	}
	for _, id := range []int64{identityChanged, previousGeneration, otherDead} {
		var status string
		if err := st.db.QueryRowContext(ctx, "SELECT status FROM outbox WHERE id=?", id).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "dead" {
			t.Fatalf("row %d must stay dead, got %s", id, status)
		}
	}
	var pendingAttempts int
	if err := st.db.QueryRowContext(ctx, "SELECT attempts FROM outbox WHERE id=?", pending).Scan(&pendingAttempts); err != nil || pendingAttempts != 7 {
		t.Fatalf("pending row changed: attempts=%d err=%v", pendingAttempts, err)
	}
	// The requeued rows are claimable immediately despite their old age.
	claimed, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	claimedIDs := map[int64]bool{}
	for _, item := range claimed {
		claimedIDs[item.ID] = true
	}
	for _, id := range retryable {
		if !claimedIDs[id] {
			t.Fatalf("requeued row %d was not claimable (claimed %v)", id, claimedIDs)
		}
	}

	if err := st.SetDestinationEnabled(ctx, other, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RetryDeadOutbox(ctx, other); !errors.Is(err, ErrDestinationDisabled) {
		t.Fatalf("disabled destination retry err=%v", err)
	}
	if err := st.DeleteDestination(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RetryDeadOutbox(ctx, other); err == nil || err.Error() != "notification destination not found" {
		t.Fatalf("removed destination retry err=%v", err)
	}
	if _, err := st.RetryDeadOutbox(ctx, 999999); err == nil {
		t.Fatal("unknown destination retry succeeded")
	}
}

func TestWebhookStatusReportsSecretPresenceAndLastAcceptedDelivery(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	state, err := st.WebhookStatus(ctx)
	if err != nil || state.Enabled || state.LastAccepted != nil {
		t.Fatalf("unconfigured webhook status=%#v err=%v", state, err)
	}
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if state, err = st.WebhookStatus(ctx); err != nil || state.Enabled {
		t.Fatalf("secretless webhook status=%#v err=%v", state, err)
	}
	withSecret := settings()
	withSecret.WebhookSecret = "webhook-secret"
	if _, err := st.SaveSettings(ctx, withSecret); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), []string{"nodeCreated"}, nil); err != nil {
		t.Fatal(err)
	}
	state, err = st.WebhookStatus(ctx)
	if err != nil || !state.Enabled || state.LastAccepted == nil || time.Since(*state.LastAccepted) > time.Minute {
		t.Fatalf("configured webhook status=%#v err=%v", state, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at='not-a-time'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.WebhookStatus(ctx); err == nil {
		t.Fatal("corrupt received_at was accepted")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.WebhookStatus(ctx); err == nil {
		t.Fatal("closed store returned webhook status")
	}
	if _, err := st.DestinationDeliveries(ctx); err == nil {
		t.Fatal("closed store returned destination deliveries")
	}
	if _, err := st.RetryDeadOutbox(ctx, 1); err == nil {
		t.Fatal("closed store retried dead letters")
	}
}

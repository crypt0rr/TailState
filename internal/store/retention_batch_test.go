package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

// retentionBatchFixture records one signed event batch per entry in sizes,
// each changing that many devices, and returns the event count per batch.
func retentionBatchFixture(t *testing.T, sizes ...int) (*Store, map[int64]int) {
	t.Helper()
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	devices := 0
	for _, size := range sizes {
		devices = max(devices, size)
	}
	hostnames := make([]string, devices)
	collected := func(round, changed int) []model.Collected {
		resources := make([]model.Resource, 0, devices)
		for i := range devices {
			if hostnames[i] == "" || i < changed {
				hostnames[i] = fmt.Sprintf("host-%d-round-%d", i, round)
			}
			resources = append(resources, model.Resource{ID: fmt.Sprintf("device-%d", i), Type: "device", Name: fmt.Sprintf("device-%d", i), Data: map[string]any{"hostname": hostnames[i]}})
		}
		return []model.Collected{{Collector: "devices", Resources: resources}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, collected(0, 0), notify.TextDigest("baseline")); err != nil {
		t.Fatal(err)
	}
	for round, size := range sizes {
		if _, err := st.ApplyBatchWithBatch(ctx, generation, collected(round+1, size), notify.TextDigest("changed")); err != nil {
			t.Fatal(err)
		}
	}
	counts := batchEventCounts(t, st)
	if len(counts) != len(sizes) {
		t.Fatalf("fixture batches=%v want %d", counts, len(sizes))
	}
	return st, counts
}

func batchEventCounts(t *testing.T, st *Store) map[int64]int {
	t.Helper()
	rows, err := st.db.Query("SELECT b.id,(SELECT COUNT(*) FROM events e WHERE e.batch_id=b.id) FROM event_batches b ORDER BY b.id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := map[int64]int{}
	for rows.Next() {
		var id int64
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			t.Fatal(err)
		}
		counts[id] = count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return counts
}

func cleanupPhaseNamed(t *testing.T, stats *CleanupStats, now time.Time, name string) cleanupPhase {
	t.Helper()
	for _, phase := range cleanupPhases(stats, now, time.Nanosecond) {
		if phase.name == name {
			return phase
		}
	}
	t.Fatalf("no cleanup phase %q", name)
	return cleanupPhase{}
}

// auditWholeLedger audits every ledger entry and fails the test on any
// audit error, including a false canonical-payload mismatch.
func auditWholeLedger(t *testing.T, st *Store) EvidenceAuditResult {
	t.Helper()
	result, err := st.AuditEvidenceLedger(context.Background(), EvidenceAuditOptions{Limit: 1000})
	if err != nil {
		t.Fatalf("evidence audit failed: %v", err)
	}
	if !result.Complete || result.VerifiedEntries != result.Entries || result.UnverifiableEntries > result.Entries {
		t.Fatalf("evidence audit result=%+v", result)
	}
	return result
}

// TestRetentionRemovesLargeBatchAtomically is the R-074 regression: a batch
// with more expired events than one cleanup transaction's row budget is
// removed with its events in a single transaction, so an audit right after
// that transaction counts the entry as unverifiable instead of reporting a
// canonical payload mismatch for a half-deleted batch.
func TestRetentionRemovesLargeBatchAtomically(t *testing.T) {
	st, counts := retentionBatchFixture(t, 300)
	for id, count := range counts {
		if count != 300 {
			t.Fatalf("batch %d has %d events, want 300", id, count)
		}
	}
	if result := auditWholeLedger(t, st); result.Entries != 1 || result.UnverifiableEntries != 0 {
		t.Fatalf("audit before cleanup=%+v", result)
	}
	var stats CleanupStats
	phase := cleanupPhaseNamed(t, &stats, time.Now().Add(time.Hour), "event_batches")
	changed, err := st.cleanupTransaction(context.Background(), &stats, phase, defaultCleanupBatchSize, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 301 || stats.EventsDeleted != 300 || stats.EventBatchesDeleted != 1 || stats.Transactions != 1 {
		t.Fatalf("one cleanup transaction changed=%d stats=%+v", changed, stats)
	}
	if remaining := batchEventCounts(t, st); len(remaining) != 0 {
		t.Fatalf("batch survived its transaction: %v", remaining)
	}
	var events int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events); err != nil || events != 0 {
		t.Fatalf("events=%d err=%v", events, err)
	}
	if result := auditWholeLedger(t, st); result.UnverifiableEntries != 1 {
		t.Fatalf("audit after cleanup=%+v", result)
	}
}

// TestRetentionKeepsEveryBatchCompleteOrAbsent runs retention one
// transaction at a time and checks after each that every batch still holds
// all of its events, that the ledger audit passes, and that an evidence pack
// exported at that point verifies.
func TestRetentionKeepsEveryBatchCompleteOrAbsent(t *testing.T) {
	ctx := context.Background()
	st, original := retentionBatchFixture(t, 100, 100, 1, 200)
	var stats CleanupStats
	now := time.Now().Add(time.Hour)
	transactions := 0
	for _, name := range []string{"event_batches", "events", "event_batch_triggers"} {
		phase := cleanupPhaseNamed(t, &stats, now, name)
		for {
			changed, err := st.cleanupTransaction(ctx, &stats, phase, defaultCleanupBatchSize, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			transactions++
			for id, count := range batchEventCounts(t, st) {
				if count != original[id] {
					t.Fatalf("after transaction %d batch %d holds %d of its %d events", transactions, id, count, original[id])
				}
			}
			auditWholeLedger(t, st)
			if len(batchEventCounts(t, st)) > 0 {
				pack, err := st.ExportEvidencePack(ctx, HistoryFilter{})
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyEvidencePack(pack); err != nil {
					t.Fatalf("evidence pack exported after transaction %d does not verify: %v", transactions, err)
				}
			}
			if changed == 0 {
				break
			}
		}
	}
	// 100 and 100 do not fit one 128-row transaction together, 1 joins the
	// second, and 200 is taken alone; then one empty probe per phase.
	if stats.EventBatchesDeleted != 4 || stats.EventsDeleted != 401 || transactions != 3+3 {
		t.Fatalf("stats=%+v transactions=%d", stats, transactions)
	}
	if result := auditWholeLedger(t, st); result.UnverifiableEntries != 4 {
		t.Fatalf("final audit=%+v", result)
	}
}

// TestRetentionRemovesEventsWithoutABatch keeps the legacy path: expired
// events whose batch row is missing, or that never had one, still expire.
func TestRetentionRemovesEventsWithoutABatch(t *testing.T) {
	ctx := context.Background()
	st, _ := retentionBatchFixture(t, 2)
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, batch := range []any{nil, int64(999999)} {
		if _, err := st.db.ExecContext(ctx, "INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,1,?,'devices','changed','r','n','[]')", batch, old); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: time.Minute})
	if err != nil || stats.EventsDeleted != 2 || stats.EventBatchesDeleted != 0 {
		t.Fatalf("orphan cleanup stats=%+v err=%v", stats, err)
	}
	if counts := batchEventCounts(t, st); len(counts) != 1 {
		t.Fatalf("batch inside the retention window was touched: %v", counts)
	}
	stats, err = st.CleanupWithOptions(ctx, CleanupOptions{Retention: -time.Hour})
	if err != nil || stats.EventsDeleted != 2 || stats.EventBatchesDeleted != 1 || stats.Remaining {
		t.Fatalf("expired batch cleanup stats=%+v err=%v", stats, err)
	}
}

// insertExpiredBacklog writes batches expired event batches of eventsEach
// events each directly into the tables. The snapshot pipeline would make a
// backlog of this size too slow to build.
func insertExpiredBacklog(t *testing.T, st *Store, batches, eventsEach int) {
	t.Helper()
	observed := formatTimestamp(time.Now().UTC().Add(-48 * time.Hour))
	if _, err := st.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO event_batches(id,generation,observed_at,change_count,created_at) SELECT i,1,?,?,? FROM n`, batches, observed, eventsEach, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`WITH RECURSIVE b(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM b WHERE i<?), e(j) AS (SELECT 1 UNION ALL SELECT j+1 FROM e WHERE j<?) INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) SELECT b.i,1,?,'devices','changed','r',e.j,'[]' FROM b CROSS JOIN e`, batches, eventsEach, observed); err != nil {
		t.Fatal(err)
	}
}

// TestRetentionRemovesOversizedBatchUnderTightBudget is the acceptance probe
// for an oversized batch: its 3,000 events cannot fit a 5 ms transaction
// budget. No pass may fail, the batch must stay complete or go entirely, and
// repeated passes must also remove the expired orphan event, API token, and
// administrative audit row that sit in phases after the batch.
func TestRetentionRemovesOversizedBatchUnderTightBudget(t *testing.T) {
	ctx := context.Background()
	st, counts := retentionBatchFixture(t, 3000)
	for id, count := range counts {
		if count != 3000 {
			t.Fatalf("batch %d has %d events, want 3000", id, count)
		}
	}
	expired := formatTimestamp(time.Now().UTC().Add(-48 * time.Hour))
	auditExpired := formatTimestamp(time.Now().UTC().Add(-AdminAuditRetention - 24*time.Hour))
	for _, fixture := range []struct {
		statement string
		args      []any
	}{
		{`INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(NULL,1,?,'devices','changed','orphan','orphan','[]')`, []any{expired}},
		{`INSERT INTO api_tokens(name,token_hash,scopes,created_at,expires_at) VALUES('expired','expired-token-hash','read',?,?)`, []any{expired, expired}},
		{`INSERT INTO admin_audit(created_at,event) VALUES(?,'expired.test')`, []any{auditExpired}},
	} {
		if _, err := st.db.Exec(fixture.statement, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	drained := func() bool {
		var batches, events, tokens, audit int
		if err := st.db.QueryRow(`SELECT (SELECT COUNT(*) FROM event_batches),(SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM api_tokens WHERE token_hash='expired-token-hash'),(SELECT COUNT(*) FROM admin_audit WHERE event='expired.test')`).Scan(&batches, &events, &tokens, &audit); err != nil {
			t.Fatal(err)
		}
		return batches+events+tokens+audit == 0
	}
	options := CleanupOptions{Retention: -time.Hour, TransactionBudget: 5 * time.Millisecond}
	for pass := 1; !drained(); pass++ {
		if pass > 500 {
			t.Fatalf("retention still had work after %d passes", pass-1)
		}
		if _, err := st.CleanupWithOptions(ctx, options); err != nil {
			t.Fatalf("pass %d failed: %v", pass, err)
		}
		for id, count := range batchEventCounts(t, st) {
			if count != 3000 {
				t.Fatalf("pass %d left batch %d holding %d of its 3000 events", pass, id, count)
			}
		}
	}
	if result := auditWholeLedger(t, st); result.UnverifiableEntries != 1 {
		t.Fatalf("audit after cleanup=%+v", result)
	}
}

// TestRetentionBacklogPassesEndWithoutError drains 1,500 expired batches of
// 100 events under a 300 ms pass budget. Each batch fits one transaction, so
// every pass that leaves work behind must end on its budget with Remaining set
// and no error, and the backlog must drain completely.
//
// The transaction budget is 100 ms rather than the 250 ms default. A
// transaction starts only while a full transaction budget remains, so the
// default leaves a 50 ms window per pass. On a -race build the five empty
// phases ahead of event_batches alone take about 50-60 ms, so with the default
// no batch ever starts (150 batches needed 998 passes in a probe). At 100 ms
// the window is 200 ms and the same backlog drains in about 11 passes.
func TestRetentionBacklogPassesEndWithoutError(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	insertExpiredBacklog(t, st, 1500, 100)
	options := CleanupOptions{Retention: -time.Hour, TransactionBudget: 100 * time.Millisecond, PassBudget: 300 * time.Millisecond}
	passes := 0
	for {
		passes++
		stats, err := st.CleanupWithOptions(ctx, options)
		if err != nil {
			t.Fatalf("pass %d failed: %v (stats=%+v)", passes, err, stats)
		}
		if !stats.Remaining {
			break
		}
		if passes > 20000 {
			t.Fatalf("backlog still pending after %d passes: %+v", passes, stats)
		}
	}
	if passes < 2 {
		t.Fatal("backlog drained in one pass; the pass budget was never exercised")
	}
	var batches, events int
	if err := st.db.QueryRow(`SELECT (SELECT COUNT(*) FROM event_batches),(SELECT COUNT(*) FROM events)`).Scan(&batches, &events); err != nil || batches != 0 || events != 0 {
		t.Fatalf("backlog left batches=%d events=%d err=%v", batches, events, err)
	}
}

// TestRetentionEscalatesOneOversizedBatchPerPass gives a transaction budget no
// transaction can meet, so every transaction overruns. A pass spends its one
// escalated retry on the first oversized batch; the second batch stays whole,
// the pass reports Remaining without an error, and the next pass removes it.
func TestRetentionEscalatesOneOversizedBatchPerPass(t *testing.T) {
	ctx := context.Background()
	st, _ := retentionBatchFixture(t, 3000, 3000)
	options := CleanupOptions{Retention: -time.Hour, TransactionBudget: time.Nanosecond}
	stats, err := st.CleanupWithOptions(ctx, options)
	if err != nil || !stats.Remaining || stats.EventBatchesDeleted != 1 || stats.EventsDeleted != 3000 {
		t.Fatalf("first pass stats=%+v err=%v", stats, err)
	}
	recorded := false
	for _, overrun := range stats.Overruns {
		recorded = recorded || (overrun.Phase == "event_batches" && !overrun.Escalated)
	}
	if !recorded {
		t.Fatalf("first pass did not record the oversized batch overrun: %+v", stats.Overruns)
	}
	remaining := batchEventCounts(t, st)
	if len(remaining) != 1 {
		t.Fatalf("first pass left batches=%v, want exactly one", remaining)
	}
	for id, count := range remaining {
		if count != 3000 {
			t.Fatalf("batch %d holds %d of its 3000 events", id, count)
		}
	}
	stats, err = st.CleanupWithOptions(ctx, options)
	if err != nil || stats.EventBatchesDeleted != 1 || len(batchEventCounts(t, st)) != 0 {
		t.Fatalf("second pass stats=%+v err=%v", stats, err)
	}
}

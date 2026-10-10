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

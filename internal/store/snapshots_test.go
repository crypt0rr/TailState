package store

import (
	"context"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// snapshotWriteCounter installs test-only triggers that count every row
// written to snapshots, so a test can assert on physical writes rather than on
// reported changes.
func snapshotWriteCounter(t *testing.T, st *Store) func() int {
	t.Helper()
	for _, statement := range []string{
		"CREATE TABLE test_snapshot_writes (n INTEGER NOT NULL)",
		"INSERT INTO test_snapshot_writes(n) VALUES(0)",
		"CREATE TRIGGER test_snapshot_insert AFTER INSERT ON snapshots BEGIN UPDATE test_snapshot_writes SET n=n+1; END",
		"CREATE TRIGGER test_snapshot_update AFTER UPDATE ON snapshots BEGIN UPDATE test_snapshot_writes SET n=n+1; END",
	} {
		if _, err := st.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return func() int {
		t.Helper()
		var n int
		if err := st.db.QueryRow("SELECT n FROM test_snapshot_writes").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec("UPDATE test_snapshot_writes SET n=0"); err != nil {
			t.Fatal(err)
		}
		return n
	}
}

func snapshotPollResources(name string, count int) []model.Collected {
	resources := make([]model.Resource, 0, count)
	for i := 0; i < count; i++ {
		id := string(rune('a' + i))
		resources = append(resources, model.Resource{ID: "device-" + id, Type: "device", Name: name + id, Data: map[string]any{"hostname": "host-" + id, "addresses": []any{"100.64.0." + id}}})
	}
	return []model.Collected{{Collector: "devices", Resources: resources}}
}

// TestIdenticalPollDoesNotRewriteSnapshots asserts that a poll whose
// resources are unchanged performs zero row writes to snapshots, while every
// state transition that does need persisting still rewrites the row.
func TestIdenticalPollDoesNotRewriteSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	digest := func([]model.Change) string { return "digest" }
	if _, err := st.ApplyBatchWithBatch(ctx, generation, snapshotPollResources("server-", 3), digest); err != nil {
		t.Fatal(err)
	}
	writes := snapshotWriteCounter(t, st)

	for poll := 0; poll < 2; poll++ {
		batch, err := st.ApplyBatchWithBatch(ctx, generation, snapshotPollResources("server-", 3), digest)
		if err != nil || len(batch.Changes) != 0 {
			t.Fatalf("identical poll changes=%v err=%v", batch.Changes, err)
		}
		if n := writes(); n != 0 {
			t.Fatalf("identical poll %d wrote %d snapshot rows, want 0", poll, n)
		}
	}

	// A rename (same content) must still be persisted.
	if _, err := st.ApplyBatchWithBatch(ctx, generation, snapshotPollResources("renamed-", 3), digest); err != nil {
		t.Fatal(err)
	}
	if n := writes(); n != 3 {
		t.Fatalf("rename wrote %d snapshot rows, want 3", n)
	}

	// A resource that was missing once and reappears must reset its counter.
	if _, err := st.db.Exec("UPDATE snapshots SET missing_count=1 WHERE resource_id='device-a'"); err != nil {
		t.Fatal(err)
	}
	writes()
	if _, err := st.ApplyBatchWithBatch(ctx, generation, snapshotPollResources("renamed-", 3), digest); err != nil {
		t.Fatal(err)
	}
	if n := writes(); n != 1 {
		t.Fatalf("missing_count reset wrote %d snapshot rows, want 1", n)
	}
	var missing int
	if err := st.db.QueryRow("SELECT missing_count FROM snapshots WHERE resource_id='device-a'").Scan(&missing); err != nil || missing != 0 {
		t.Fatalf("missing_count=%d err=%v", missing, err)
	}

	// A stored value in a non-canonical form (older normaliser) whose
	// re-normalised hash matches must be rewritten in the current form even
	// though no change is reported.
	var canonical []byte
	if err := st.db.QueryRow("SELECT canonical_json FROM snapshots WHERE resource_id='device-b'").Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(" " + string(canonical))
	if _, err := st.db.Exec("UPDATE snapshots SET canonical_json=?,content_hash=?,content_bytes=? WHERE resource_id='device-b'", legacy, valueHash(legacy), len(legacy)); err != nil {
		t.Fatal(err)
	}
	writes()
	batch, err := st.ApplyBatchWithBatch(ctx, generation, snapshotPollResources("renamed-", 3), digest)
	if err != nil || len(batch.Changes) != 0 {
		t.Fatalf("re-normalised poll changes=%v err=%v", batch.Changes, err)
	}
	if n := writes(); n != 1 {
		t.Fatalf("re-normalised stored value wrote %d snapshot rows, want 1", n)
	}
	var restored []byte
	if err := st.db.QueryRow("SELECT canonical_json FROM snapshots WHERE resource_id='device-b'").Scan(&restored); err != nil || string(restored) != string(canonical) {
		t.Fatalf("stored value after rewrite=%s err=%v", restored, err)
	}
}

// TestRaisingSnapshotLimitRewritesTruncatedSnapshot verifies that the
// write-skip does not pin a truncation marker after the operator raises the
// snapshot budget, and that an unchanged truncated value is not rewritten.
func TestRaisingSnapshotLimitRewritesTruncatedSnapshot(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	small := StorageLimits{SnapshotBytes: 1024, EventValueBytes: 1024, HistoryPageBytes: 4096, RejectBytes: 1 << 20, DatabaseBytes: 1 << 30}
	if err := st.SetStorageLimits(small); err != nil {
		t.Fatal(err)
	}
	large := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": strings.Repeat("x", 4096)},
	}}}}
	digest := func([]model.Change) string { return "digest" }
	if _, err := st.ApplyBatchWithBatch(ctx, generation, large, digest); err != nil {
		t.Fatal(err)
	}
	writes := snapshotWriteCounter(t, st)
	if _, err := st.ApplyBatchWithBatch(ctx, generation, large, digest); err != nil {
		t.Fatal(err)
	}
	if n := writes(); n != 0 {
		t.Fatalf("unchanged truncated snapshot wrote %d rows, want 0", n)
	}
	raised := small
	raised.SnapshotBytes = 1 << 20
	if err := st.SetStorageLimits(raised); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, large, digest)
	if err != nil || len(batch.Changes) != 0 {
		t.Fatalf("raised-limit poll changes=%v err=%v", batch.Changes, err)
	}
	if n := writes(); n != 1 {
		t.Fatalf("raising the limit wrote %d snapshot rows, want 1", n)
	}
	var truncated int
	var stored []byte
	if err := st.db.QueryRow("SELECT content_truncated,canonical_json FROM snapshots WHERE resource_id='device-1'").Scan(&truncated, &stored); err != nil {
		t.Fatal(err)
	}
	if truncated != 0 || len(stored) < 4096 {
		t.Fatalf("snapshot still truncated=%d bytes=%d after raising the limit", truncated, len(stored))
	}
}

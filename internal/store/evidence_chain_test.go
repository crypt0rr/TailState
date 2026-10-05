package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// insertEvidenceBatches writes count batches of eventsPerBatch events with
// the given after_json payload directly, newest last, and returns their IDs
// newest first (the order exports list them). Resource IDs are
// "<resource>-<batch>-<event>".
func insertEvidenceBatches(t *testing.T, st *Store, count, eventsPerBatch int, after, resource string) []int64 {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ids := make([]int64, 0, count)
	for batch := 0; batch < count; batch++ {
		result, err := tx.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,?,?)", now, eventsPerBatch, now)
		if err != nil {
			t.Fatal(err)
		}
		batchID, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		for event := 0; event < eventsPerBatch; event++ {
			if _, err := tx.ExecContext(ctx, "INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,after_json) VALUES(?,1,?,'devices','changed',?,'server','[]',?)", batchID, now, fmt.Sprintf("%s-%d-%d", resource, batchID, event), after); err != nil {
				t.Fatal(err)
			}
		}
		ids = append(ids, batchID)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(ids)
	return ids
}

// exportEvidenceChain follows NextCursor from filter until a complete pack,
// verifying every part exactly as `tailstate evidence verify` does.
func exportEvidenceChain(t *testing.T, st *Store, filter HistoryFilter) []EvidencePack {
	t.Helper()
	var packs []EvidencePack
	for part := 0; ; part++ {
		if part > 200 {
			t.Fatal("evidence pack chain did not terminate")
		}
		data, err := st.ExportEvidencePack(context.Background(), filter)
		if err != nil {
			t.Fatalf("export part %d (cursor %d): %v", part, filter.Cursor, err)
		}
		if len(data) > EvidencePackLimitBytes {
			t.Fatalf("part %d is %d bytes, above the %d-byte limit", part, len(data), EvidencePackLimitBytes)
		}
		if err := VerifyEvidencePack(data); err != nil {
			t.Fatalf("part %d (cursor %d) did not verify: %v", part, filter.Cursor, err)
		}
		if err := VerifyEvidencePackWithKey(data, st.evidenceKey.public); err != nil {
			t.Fatalf("part %d did not verify against the instance key: %v", part, err)
		}
		var pack EvidencePack
		if err := json.Unmarshal(data, &pack); err != nil {
			t.Fatal(err)
		}
		if pack.Filter.Cursor != filter.Cursor {
			t.Fatalf("part %d records cursor %d, want %d", part, pack.Filter.Cursor, filter.Cursor)
		}
		packs = append(packs, pack)
		if !pack.Truncated {
			return packs
		}
		filter.Cursor = pack.NextCursor
	}
}

// assertEvidenceChainCovers checks that the chain lists want (newest first)
// with every batch exactly once.
func assertEvidenceChainCovers(t *testing.T, packs []EvidencePack, want []int64) {
	t.Helper()
	got := make([]int64, 0, len(want))
	for _, pack := range packs {
		for _, batch := range pack.Batches {
			got = append(got, batch.ID)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("evidence chain batches=%v, want %v (sizes %v)", got, want, evidenceChainSizes(packs))
	}
}

func evidenceChainSizes(packs []EvidencePack) []int {
	sizes := make([]int, 0, len(packs))
	for _, pack := range packs {
		sizes = append(sizes, len(pack.Batches))
	}
	return sizes
}

// TestEvidenceExportChainCoversEveryBatchOnce reproduces the review's large
// history (101 batches of five ~4 KB events). The read budget ends the first
// pack early; following NextCursor yields a chain of packs that each verify
// and together hold every batch exactly once.
func TestEvidenceExportChainCoversEveryBatchOnce(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ids := insertEvidenceBatches(t, st, 101, 5, `"`+strings.Repeat("a", 4096)+`"`, "device")
	if err := st.backfillEvidenceLedger(ctx); err != nil {
		t.Fatal(err)
	}
	packs := exportEvidenceChain(t, st, HistoryFilter{})
	assertEvidenceChainCovers(t, packs, ids)
	if len(packs) < 2 || len(packs[0].Batches) >= maxEvidenceBatches {
		t.Fatalf("chain sizes=%v, want the byte budget to end the first pack early", evidenceChainSizes(packs))
	}
	first := packs[0]
	if !first.Truncated || first.NextCursor != first.Batches[len(first.Batches)-1].ID || first.Filter.Limit != maxEvidenceBatches {
		t.Fatalf("first part truncated=%t next=%d limit=%d", first.Truncated, first.NextCursor, first.Filter.Limit)
	}
	if last := packs[len(packs)-1]; last.Truncated || last.NextCursor != 0 {
		t.Fatalf("last part truncated=%t next=%d", last.Truncated, last.NextCursor)
	}
	for index, pack := range packs {
		if len(pack.LedgerLinks) == 0 || pack.Batches[0].LedgerSequence == 0 {
			t.Fatalf("part %d carries no ledger proof", index)
		}
	}
}

// TestEvidenceExportDropsBatchesOverEncodedSize covers the final size check:
// the read estimate admits these batches, but HTML escaping of "<" makes
// each one ~1.8 MiB encoded, so trailing batches move to the next part.
func TestEvidenceExportDropsBatchesOverEncodedSize(t *testing.T) {
	st := testStore(t)
	ids := insertEvidenceBatches(t, st, 5, 1, `"`+strings.Repeat("<", 300<<10)+`"`, "device")
	packs := exportEvidenceChain(t, st, HistoryFilter{})
	assertEvidenceChainCovers(t, packs, ids)
	if sizes := evidenceChainSizes(packs); !slices.Equal(sizes, []int{2, 2, 1}) {
		t.Fatalf("encoded-size chain sizes=%v, want [2 2 1]", sizes)
	}
}

// TestEvidenceExportRespectsSmallerLimit honors a caller's smaller batch
// limit and records it in the signed filter; larger limits are capped.
func TestEvidenceExportRespectsSmallerLimit(t *testing.T) {
	st := testStore(t)
	ids := insertEvidenceBatches(t, st, 7, 1, "", "device")
	if err := st.backfillEvidenceLedger(context.Background()); err != nil {
		t.Fatal(err)
	}
	packs := exportEvidenceChain(t, st, HistoryFilter{Limit: 3})
	assertEvidenceChainCovers(t, packs, ids)
	if sizes := evidenceChainSizes(packs); !slices.Equal(sizes, []int{3, 3, 1}) {
		t.Fatalf("limited chain sizes=%v, want [3 3 1]", sizes)
	}
	for _, pack := range packs {
		if pack.Filter.Limit != 3 {
			t.Fatalf("signed filter limit=%d, want 3", pack.Filter.Limit)
		}
	}
	capped := exportEvidenceChain(t, st, HistoryFilter{Limit: 1000})
	if len(capped) != 1 || capped[0].Filter.Limit != maxEvidenceBatches {
		t.Fatalf("over-limit export parts=%d limit=%d", len(capped), capped[0].Filter.Limit)
	}
}

// TestEvidenceExportSplitsAtLedgerLinkLimit pages a sparse, filtered export
// whose ledger span exceeds the per-pack link limit instead of failing.
func TestEvidenceExportSplitsAtLedgerLinkLimit(t *testing.T) {
	previous := evidenceLedgerLinkLimit
	evidenceLedgerLinkLimit = 5
	t.Cleanup(func() { evidenceLedgerLinkLimit = previous })
	st := testStore(t)
	var want []int64
	for index := 0; index < 10; index++ {
		resource := "other"
		if index%3 == 0 {
			resource = "target"
		}
		ids := insertEvidenceBatches(t, st, 1, 1, "", resource)
		if resource == "target" {
			want = append(ids, want...)
		}
	}
	if err := st.backfillEvidenceLedger(context.Background()); err != nil {
		t.Fatal(err)
	}
	packs := exportEvidenceChain(t, st, HistoryFilter{ResourceID: "target"})
	assertEvidenceChainCovers(t, packs, want)
	if sizes := evidenceChainSizes(packs); !slices.Equal(sizes, []int{2, 2}) {
		t.Fatalf("link-limited chain sizes=%v, want [2 2]", sizes)
	}
	for index, pack := range packs {
		if len(pack.LedgerLinks) > evidenceLedgerLinkLimit {
			t.Fatalf("part %d carries %d ledger links, above the limit", index, len(pack.LedgerLinks))
		}
	}
}

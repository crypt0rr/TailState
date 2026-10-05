package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEvidenceJSONNormalizesEmptyAndInvalidValues(t *testing.T) {
	if got := evidenceJSON(""); got != nil {
		t.Fatalf("empty evidence JSON=%s", got)
	}
	if got := string(evidenceJSON(`{"field":true}`)); got != `{"field":true}` {
		t.Fatalf("valid evidence JSON=%q", got)
	}
	invalid := evidenceJSON("not-json")
	if string(invalid) != `"not-json"` {
		t.Fatalf("invalid evidence JSON=%q", invalid)
	}
	long := strings.Repeat("x", 32)
	if string(evidenceJSON(long)) != `"`+long+`"` {
		t.Fatalf("plain evidence value=%q", evidenceJSON(long))
	}
}

// TestEvidenceExportChainsPacksAtEventCap replaces the old "too many
// events" failure: the event cap now ends a pack early instead of refusing
// the export, and the continuation part holds the remaining batches.
func TestEvidenceExportChainsPacksAtEventCap(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ids := insertEvidenceBatches(t, st, 100, 21, "[]", "device")
	if err := st.backfillEvidenceLedger(ctx); err != nil {
		t.Fatal(err)
	}
	packs := exportEvidenceChain(t, st, HistoryFilter{})
	assertEvidenceChainCovers(t, packs, ids)
	perPack := maxEvidenceEvents / 21
	if len(packs) != 2 || len(packs[0].Batches) != perPack || len(packs[1].Batches) != 100-perPack {
		t.Fatalf("event-capped chain sizes=%v, want [%d %d]", evidenceChainSizes(packs), perPack, 100-perPack)
	}
	for _, pack := range packs {
		events := 0
		for _, batch := range pack.Batches {
			events += len(batch.Events)
		}
		if events > maxEvidenceEvents {
			t.Fatalf("pack carries %d events, above the %d cap", events, maxEvidenceEvents)
		}
	}
}

// TestEvidenceExportRejectsOnlyAnUnexportableNewestBatch keeps the error for
// the one case that cannot make progress: the newest matching batch alone
// is over a budget.
func TestEvidenceExportRejectsOnlyAnUnexportableNewestBatch(t *testing.T) {
	ctx := context.Background()
	oversized := testStore(t)
	insertEvidenceBatches(t, oversized, 1, 1, `"`+strings.Repeat("x", 6<<20)+`"`, "device")
	if _, err := oversized.ExportEvidencePack(ctx, HistoryFilter{}); !errors.Is(err, ErrEvidencePackTooLarge) {
		t.Fatalf("oversized newest batch export error=%v, want %v", err, ErrEvidencePackTooLarge)
	}

	crowded := testStore(t)
	insertEvidenceBatches(t, crowded, 1, maxEvidenceEvents+1, "[]", "device")
	if _, err := crowded.ExportEvidencePack(ctx, HistoryFilter{}); !errors.Is(err, ErrEvidencePackTooLarge) {
		t.Fatalf("over-cap newest batch export error=%v, want %v", err, ErrEvidencePackTooLarge)
	}

	// The read budget passes this batch (its estimate counts raw bytes), but
	// HTML escaping makes the encoded pack six times larger.
	escaped := testStore(t)
	insertEvidenceBatches(t, escaped, 1, 1, `"`+strings.Repeat("<", 1<<20)+`"`, "device")
	if _, err := escaped.ExportEvidencePack(ctx, HistoryFilter{}); !errors.Is(err, ErrEvidencePackTooLarge) {
		t.Fatalf("over-size encoded newest batch export error=%v, want %v", err, ErrEvidencePackTooLarge)
	}
}

func TestExportEvidencePackLedgerAndDecodeErrors(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.db.ExecContext(ctx, "DROP TABLE evidence_ledger"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ExportEvidencePack(ctx, HistoryFilter{}); err == nil {
		t.Fatal("ExportEvidencePack succeeded without the evidence ledger")
	}
	if err := VerifyEvidencePack([]byte("{")); err == nil || !strings.Contains(err.Error(), "decode evidence pack") {
		t.Fatalf("malformed evidence pack error=%v", err)
	}
}

func TestVerifyEvidencePackRejectsOversizedInput(t *testing.T) {
	if err := VerifyEvidencePack(make([]byte, EvidencePackLimitBytes+1)); !errors.Is(err, ErrEvidencePackTooLarge) {
		t.Fatalf("oversized evidence input error=%v", err)
	}
	if _, err := ParseEvidencePublicKey(make([]byte, EvidencePublicKeyLimitBytes+1)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized public key error=%v", err)
	}
}

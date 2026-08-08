package store

import (
	"context"
	"strings"
	"testing"
	"time"
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

func TestExportEvidencePackRejectsTooManyEvents(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for batch := 0; batch < 100; batch++ {
		result, err := tx.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,?,?)", now, 21, now)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		batchID, err := result.LastInsertId()
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		for event := 0; event < 21; event++ {
			if _, err := tx.ExecContext(ctx, "INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,1,?,'devices','changed',?,?,?)", batchID, now, "device-"+string(rune(event)), "server", "[]"); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ExportEvidencePack(ctx, HistoryFilter{}); err != ErrEvidencePackTooLarge {
		t.Fatalf("large evidence export error=%v, want %v", err, ErrEvidencePackTooLarge)
	}
}

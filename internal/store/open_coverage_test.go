package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func openCoverageDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open coverage database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenReportsMasterKeyCheckInsertError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}
	db := openCoverageDB(t, path)
	if _, err := db.ExecContext(context.Background(), "DELETE FROM meta WHERE key='master_key_check'"); err != nil {
		t.Fatalf("delete master key check: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TRIGGER fail_master_key_check BEFORE INSERT ON meta
		WHEN NEW.key='master_key_check'
		BEGIN SELECT RAISE(ABORT,'master key check insert failed'); END`); err != nil {
		t.Fatalf("create master key trigger: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close trigger database: %v", err)
	}
	if _, err := Open(path, box); err == nil || !strings.Contains(err.Error(), "master key check insert failed") {
		t.Fatalf("Open error = %v", err)
	}
}

func TestOpenRejectsMismatchedMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	firstBox, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, firstBox)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}
	secondKey := make([]byte, 32)
	secondKey[0] = 1
	secondBox, err := secret.NewBox(secondKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, secondBox); err == nil || !strings.Contains(err.Error(), "master key does not match") {
		t.Fatalf("mismatched key Open error = %v", err)
	}
}

func TestOpenReportsConflictingMetaObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	db := openCoverageDB(t, path)
	if _, err := db.ExecContext(context.Background(), "CREATE VIEW meta AS SELECT 1 AS key, 1 AS value"); err != nil {
		t.Fatalf("create conflicting meta view: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close conflicting database: %v", err)
	}
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, box); err == nil || !strings.Contains(err.Error(), "cannot modify meta") {
		t.Fatalf("conflicting meta Open error = %v", err)
	}
}

func TestOpenReportsEvidenceLedgerBackfillError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}
	db := openCoverageDB(t, path)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(context.Background(), "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,?,?)", now, 0, now); err != nil {
		t.Fatalf("insert event batch: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TRIGGER fail_backfill_ledger BEFORE INSERT ON evidence_ledger
		BEGIN SELECT RAISE(ABORT,'backfill ledger insert failed'); END`); err != nil {
		t.Fatalf("create ledger trigger: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close trigger database: %v", err)
	}
	if _, err := Open(path, box); err == nil || !strings.Contains(err.Error(), "backfill evidence ledger") {
		t.Fatalf("Open error = %v", err)
	}
}

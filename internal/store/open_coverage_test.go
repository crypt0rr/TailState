package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
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

func TestOpenCreatesHistoryLookupIndexes(t *testing.T) {
	st := testStore(t)
	for _, index := range []struct {
		table string
		name  string
	}{
		{table: "events", name: "events_batch_id"},
		{table: "outbox", name: "outbox_batch_id"},
	} {
		var found int
		if err := st.db.QueryRow("SELECT COUNT(*) FROM pragma_index_list(?) WHERE name=?", index.table, index.name).Scan(&found); err != nil {
			t.Fatalf("inspect %s: %v", index.name, err)
		}
		if found != 1 {
			t.Fatalf("index %s missing", index.name)
		}
	}
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
	db := openCoverageDB(t, path)
	var beforeVersion, beforeMeta int
	if err := db.QueryRowContext(context.Background(), "SELECT version FROM schema_version").Scan(&beforeVersion); err != nil {
		t.Fatalf("read schema version before wrong-key open: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM meta").Scan(&beforeMeta); err != nil {
		t.Fatalf("read metadata before wrong-key open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close inspection database: %v", err)
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
	db = openCoverageDB(t, path)
	defer db.Close()
	var afterVersion, afterMeta int
	if err := db.QueryRowContext(context.Background(), "SELECT version FROM schema_version").Scan(&afterVersion); err != nil {
		t.Fatalf("read schema version after wrong-key open: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM meta").Scan(&afterMeta); err != nil {
		t.Fatalf("read metadata after wrong-key open: %v", err)
	}
	if afterVersion != beforeVersion || afterMeta != beforeMeta {
		t.Fatalf("wrong-key startup mutated database: schema %d->%d metadata %d->%d", beforeVersion, afterVersion, beforeMeta, afterMeta)
	}
}

func TestOpenRejectsWrongKeyWithMissingMasterKeyMarkerBeforeDDL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	firstKey := make([]byte, 32)
	firstKey[0] = 11
	firstBox, err := secret.NewBox(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, firstBox)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	ctx := context.Background()
	if _, err := st.SaveSettings(ctx, Settings{
		Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "oauth-secret",
		MattermostURL:  "https://mattermost.example/hooks/token",
		DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute,
	}); err != nil {
		st.Close()
		t.Fatalf("save settings: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	db := openCoverageDB(t, path)
	var beforeVersion int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&beforeVersion); err != nil {
		t.Fatal(err)
	}
	var beforeDestination string
	if err := db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations LIMIT 1").Scan(&beforeDestination); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM meta WHERE key='master_key_check'"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	wrongKey[0] = 12
	wrongBox, err := secret.NewBox(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, wrongBox); err == nil || !strings.Contains(err.Error(), "master key does not match") {
		t.Fatalf("wrong-key Open with missing marker error = %v", err)
	}

	inspection := openCoverageDB(t, path)
	defer inspection.Close()
	var afterVersion int
	if err := inspection.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&afterVersion); err != nil {
		t.Fatal(err)
	}
	var afterDestination string
	if err := inspection.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations LIMIT 1").Scan(&afterDestination); err != nil {
		t.Fatal(err)
	}
	if afterVersion != beforeVersion || afterDestination != beforeDestination {
		t.Fatalf("wrong-key startup mutated data with missing marker: schema %d->%d destination changed=%t", beforeVersion, afterVersion, beforeDestination != afterDestination)
	}
}

func TestOpenRejectsWrongKeyBeforeLegacyBootstrapDDL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	firstKey := make([]byte, 32)
	firstKey[0] = 7
	firstBox, err := secret.NewBox(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := firstBox.Encrypt("oauth-secret")
	if err != nil {
		t.Fatal(err)
	}
	mattermost, err := firstBox.Encrypt("https://mattermost.example/hooks/token")
	if err != nil {
		t.Fatal(err)
	}
	db := openCoverageDB(t, path)
	if _, err := db.ExecContext(context.Background(), `
CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(1);
CREATE TABLE settings(
  id INTEGER PRIMARY KEY,
  tailnet TEXT NOT NULL,
  oauth_client_id TEXT NOT NULL,
  oauth_secret_enc TEXT NOT NULL,
  mattermost_url_enc TEXT NOT NULL,
  device_interval_seconds INTEGER NOT NULL,
  inventory_interval_seconds INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  configured_at TEXT NOT NULL,
  baseline_at TEXT
);
CREATE TABLE outbox(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt TEXT NOT NULL,
  first_attempt TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  delivered_at TEXT
);
INSERT INTO settings VALUES(1,'-','client',?,?,60,300,1,'2026-01-01T00:00:00Z',NULL);`, oauth, mattermost); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	wrongKey[0] = 8
	wrongBox, err := secret.NewBox(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, wrongBox); err == nil || !strings.Contains(err.Error(), "master key does not match") {
		t.Fatalf("wrong-key legacy Open error = %v", err)
	}

	inspection := openCoverageDB(t, path)
	defer inspection.Close()
	var version int
	if err := inspection.QueryRowContext(context.Background(), "SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("legacy schema version changed to %d", version)
	}
	var currentTables int
	if err := inspection.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('notification_destinations','event_batches','events','webhook_triggers','evidence_ledger')`).Scan(&currentTables); err != nil {
		t.Fatal(err)
	}
	if currentTables != 0 {
		t.Fatalf("wrong-key legacy startup created %d current-schema tables", currentTables)
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
	if _, err := db.ExecContext(context.Background(), "DELETE FROM meta WHERE key IN (?,?)", evidenceLedgerBackfilledMeta, evidenceLedgerBackfillCutoff); err != nil {
		t.Fatalf("clear ledger backfill marker: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := db.ExecContext(context.Background(), "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,?,?)", now, 1, now)
	if err != nil {
		t.Fatalf("insert event batch: %v", err)
	}
	batchID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("event batch id: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json)
		VALUES(?,?,?,?,?,?,?,?)`, batchID, 1, now, "devices", "changed", "device-1", "server", `[]`); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "INSERT INTO meta(key,value) VALUES(?,?)", evidenceLedgerBackfillCutoff, strconv.FormatInt(batchID, 10)); err != nil {
		t.Fatalf("insert ledger backfill cutoff: %v", err)
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

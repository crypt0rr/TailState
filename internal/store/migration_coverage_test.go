package store

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"
)

func migrationV2WriteFixture(t *testing.T) *sql.DB {
	t.Helper()
	db := migrationErrorDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(2);
CREATE TABLE event_batches(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 generation INTEGER NOT NULL,
 observed_at TEXT NOT NULL,
 change_count INTEGER NOT NULL,
 created_at TEXT NOT NULL,
 trigger_id INTEGER
);
CREATE TABLE events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 batch_id INTEGER,
 generation INTEGER NOT NULL,
 observed_at TEXT NOT NULL,
 before_json BLOB,
 after_json BLOB
);
CREATE TABLE outbox(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 created_at TEXT NOT NULL,
 batch_id INTEGER
);
INSERT INTO events(generation,observed_at,batch_id) VALUES(1,'2026-01-01T00:00:00Z',NULL);
INSERT INTO outbox(created_at,batch_id) VALUES('2026-01-01T00:00:00Z',NULL);`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMigrateSchemaV2ReportsWriteErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup string
		want  string
	}{
		{
			name: "backfill event batches",
			setup: `CREATE TRIGGER fail_event_batch_backfill BEFORE INSERT ON event_batches
				BEGIN SELECT RAISE(ABORT,'event batch backfill failed'); END`,
			want: "backfill event batches",
		},
		{
			name: "assign event batches",
			setup: `CREATE TRIGGER allow_event_batch_backfill AFTER INSERT ON event_batches BEGIN SELECT 1; END;
CREATE TRIGGER fail_event_batch_assignment BEFORE UPDATE OF batch_id ON events
				BEGIN SELECT RAISE(ABORT,'event batch assignment failed'); END`,
			want: "assign event batches",
		},
		{
			name: "assign outbox event batches",
			setup: `CREATE TRIGGER allow_event_batch_backfill AFTER INSERT ON event_batches BEGIN SELECT 1; END;
CREATE TRIGGER fail_outbox_batch_assignment BEFORE UPDATE OF batch_id ON outbox
				BEGIN SELECT RAISE(ABORT,'outbox batch assignment failed'); END`,
			want: "assign outbox event batches",
		},
		{
			name: "record schema version",
			setup: `CREATE TRIGGER allow_event_batch_backfill AFTER INSERT ON event_batches BEGIN SELECT 1; END;
CREATE TRIGGER fail_event_history_schema_version BEFORE UPDATE ON schema_version
				BEGIN SELECT RAISE(ABORT,'event history schema update failed'); END`,
			want: "record event history migration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := migrationV2WriteFixture(t)
			if _, err := db.Exec(tt.setup); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchemaV2ToV3(db); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func currentSchemaMigrationDB(t *testing.T, version int) *sql.DB {
	t.Helper()
	db := migrationErrorDB(t)
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE schema_version SET version=?", version); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestVersionedMigrationsReportSchemaWriteErrors(t *testing.T) {
	tests := []struct {
		version int
		call    func(*sql.DB) error
		trigger string
		want    string
	}{
		{version: 3, call: migrateSchemaV3ToV4, trigger: "fail_webhook_schema_version", want: "record webhook migration"},
		{version: 4, call: migrateSchemaV4ToV5, trigger: "fail_durable_webhook_schema_version", want: "record durable webhook migration"},
		{version: 5, call: migrateSchemaV5ToV6, trigger: "fail_evidence_schema_version", want: "record evidence ledger migration"},
		{version: 6, call: migrateSchemaV6ToV7, trigger: "fail_auth_schema_version", want: "record authentication token migration"},
	}
	for _, tt := range tests {
		t.Run("version "+strconv.Itoa(tt.version), func(t *testing.T) {
			db := currentSchemaMigrationDB(t, tt.version)
			if _, err := db.Exec("CREATE TRIGGER " + tt.trigger + " BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END"); err != nil {
				t.Fatal(err)
			}
			if err := tt.call(db); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestMigrateSchemaV6ToV7MigratesLegacyAuthenticationTokens(t *testing.T) {
	db := migrationErrorDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(6);
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT INTO meta(key,value) VALUES('setup_token_hash','setup-hash'),('reset_token_hash','reset-hash');`); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	if err := migrateSchemaV6ToV7(db); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 7 {
		t.Fatalf("schema version=%d, want 7", version)
	}
	rows, err := db.Query("SELECT kind,token_hash,created_at,expires_at FROM auth_tokens ORDER BY kind")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got int
	for rows.Next() {
		var kind, hash, created, expires string
		if err := rows.Scan(&kind, &hash, &created, &expires); err != nil {
			t.Fatal(err)
		}
		if hash == "" || (kind != "reset" && kind != "setup") {
			t.Fatalf("migrated token=%q hash=%q", kind, hash)
		}
		createdAt, err := time.Parse(time.RFC3339Nano, created)
		if err != nil || createdAt.Before(started) {
			t.Fatalf("created_at=%q err=%v", created, err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, expires)
		if err != nil || !expiresAt.After(createdAt) {
			t.Fatalf("expires_at=%q err=%v", expires, err)
		}
		got++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("migrated token count=%d, want 2", got)
	}
	var legacy int
	if err := db.QueryRow("SELECT COUNT(*) FROM meta WHERE key IN ('setup_token_hash','reset_token_hash')").Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 2 {
		t.Fatalf("legacy token count=%d, want 2", legacy)
	}
}

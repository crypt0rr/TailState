package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func migrationErrorDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestVersionedMigrationErrorPaths(t *testing.T) {
	tests := []struct {
		name string
		call func(*sql.DB) error
		want string
	}{
		{
			name: "event history missing events table",
			call: migrateSchemaV2ToV3,
			want: "add events.batch_id",
		},
		{
			name: "webhook missing settings table",
			call: migrateSchemaV3ToV4,
			want: "add settings.webhook_secret_enc",
		},
		{
			name: "durable webhook missing trigger table",
			call: migrateSchemaV4ToV5,
			want: "add webhook_triggers.attempts",
		},
		{
			name: "evidence ledger missing schema version",
			call: migrateSchemaV5ToV6,
			want: "record evidence ledger migration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := migrationErrorDB(t)
			if tt.name == "evidence ledger missing schema version" {
				if _, err := db.Exec("CREATE TABLE event_batches(id INTEGER PRIMARY KEY)"); err != nil {
					t.Fatal(err)
				}
			}
			err := tt.call(db)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestMigrateSchemaDispatchesVersionedErrors(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		version int
		setup   string
		want    string
	}{
		{version: 2, want: "add events.batch_id"},
		{version: 3, want: "add settings.webhook_secret_enc"},
		{version: 4, want: "add webhook_triggers.attempts"},
		{version: 5, setup: `CREATE TRIGGER fail_schema_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END`, want: "record evidence ledger migration"},
	}
	for _, tt := range tests {
		t.Run("version "+strconv.Itoa(tt.version), func(t *testing.T) {
			db := migrationErrorDB(t)
			if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(?)", tt.version); err != nil {
				t.Fatal(err)
			}
			if tt.setup != "" {
				if _, err := db.Exec(tt.setup); err != nil {
					t.Fatal(err)
				}
			}
			err := migrateSchema(db, box)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestInitialMigrationSchemaErrorPaths(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{name: "missing outbox", schema: "CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1);", want: "upgrade outbox destinations"},
		{name: "missing settings", schema: "CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1); CREATE TABLE outbox(id INTEGER);", want: "read legacy Mattermost setting"},
		{name: "legacy column missing", schema: "CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1); CREATE TABLE outbox(id INTEGER); CREATE TABLE settings(id INTEGER PRIMARY KEY);", want: "read legacy Mattermost setting"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := migrationErrorDB(t)
			if _, err := db.Exec(tt.schema); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLegacyMigrationDataAndWriteErrors(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	legacyDB := func(t *testing.T, legacyURL string) *sql.DB {
		t.Helper()
		db := migrationErrorDB(t)
		if _, err := db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1);
CREATE TABLE outbox(id INTEGER PRIMARY KEY,destination_id INTEGER,status TEXT NOT NULL DEFAULT 'pending',last_error TEXT NOT NULL DEFAULT '');
CREATE TABLE settings(id INTEGER PRIMARY KEY,mattermost_url_enc TEXT);`); err != nil {
			t.Fatal(err)
		}
		encrypted := ""
		if legacyURL != "" {
			var err error
			encrypted, err = box.Encrypt(legacyURL)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec("INSERT INTO settings(id,mattermost_url_enc) VALUES(1,?)", encrypted); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO outbox(id,destination_id) VALUES(1,NULL)"); err != nil {
			t.Fatal(err)
		}
		return db
	}

	t.Run("decrypt legacy URL", func(t *testing.T) {
		db := migrationErrorDB(t)
		if _, err := db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1);
CREATE TABLE outbox(id INTEGER PRIMARY KEY,destination_id INTEGER);
CREATE TABLE settings(id INTEGER PRIMARY KEY,mattermost_url_enc TEXT);
INSERT INTO settings(id,mattermost_url_enc) VALUES(1,'invalid-envelope');`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "decrypt legacy Mattermost setting") {
			t.Fatalf("decrypt migration error=%v", err)
		}
	})

	t.Run("convert legacy URL", func(t *testing.T) {
		db := legacyDB(t, "ftp://mattermost.example/hooks/token")
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "migrate legacy Mattermost setting") {
			t.Fatalf("convert migration error=%v", err)
		}
	})

	t.Run("destination insert", func(t *testing.T) {
		db := legacyDB(t, "https://mattermost.example/hooks/token")
		if _, err := db.Exec(`CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,service_url_enc TEXT NOT NULL,enabled INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE TRIGGER fail_migrated_destination BEFORE INSERT ON notification_destinations BEGIN SELECT RAISE(ABORT,'destination insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "store migrated notification destination") {
			t.Fatalf("destination insert migration error=%v", err)
		}
	})

	t.Run("outbox assignment", func(t *testing.T) {
		db := legacyDB(t, "https://mattermost.example/hooks/token")
		if _, err := db.Exec(`CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,service_url_enc TEXT NOT NULL,enabled INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE TRIGGER fail_migrated_outbox BEFORE UPDATE ON outbox BEGIN SELECT RAISE(ABORT,'outbox assignment failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "assign migrated outbox rows") {
			t.Fatalf("outbox assignment migration error=%v", err)
		}
	})

	t.Run("orphan outbox dead-letter", func(t *testing.T) {
		db := legacyDB(t, "")
		if _, err := db.Exec(`CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,service_url_enc TEXT NOT NULL,enabled INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE TRIGGER fail_orphan_outbox BEFORE UPDATE OF status ON outbox BEGIN SELECT RAISE(ABORT,'orphan dead-letter failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "dead-letter orphaned outbox rows") {
			t.Fatalf("orphan outbox migration error=%v", err)
		}
	})

	t.Run("schema version update", func(t *testing.T) {
		db := legacyDB(t, "")
		if _, err := db.Exec(`CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,service_url_enc TEXT NOT NULL,enabled INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE TRIGGER fail_legacy_schema_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "record schema migration") {
			t.Fatalf("schema update migration error=%v", err)
		}
	})
}

func TestOpenPathAndFilepathErrors(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(occupied, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(occupied, "tailstate.db"), box); err == nil {
		t.Fatal("Open succeeded below a regular file")
	}
	if got := filepathDir("database.db"); got != "." {
		t.Fatalf("filepathDir without directory=%q", got)
	}
	if got := filepathDir("/database.db"); got != "." {
		t.Fatalf("filepathDir root file=%q", got)
	}
	if got := filepathDir("data/database.db"); got != "data" {
		t.Fatalf("filepathDir nested=%q", got)
	}
}

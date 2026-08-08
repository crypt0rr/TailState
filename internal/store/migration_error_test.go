package store

import (
	"database/sql"
	"os"
	"path/filepath"
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

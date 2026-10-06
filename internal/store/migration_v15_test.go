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

// downgradeToV14 removes everything schema v15 adds, reproducing a database
// written by the previous release.
func downgradeToV14(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		"ALTER TABLE sessions DROP COLUMN last_seen_at",
		"DROP TABLE admin_audit",
		"DROP TABLE api_tokens",
		"UPDATE schema_version SET version=14",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// TestSchemaV15MigrationKeepsSessionsAndAddsSecurityState upgrades a schema
// v14 database: an existing session survives with its creation time as its
// last activity, so the idle timeout applies from the upgrade onwards.
func TestSchemaV15MigrationKeepsSessionsAndAddsSecurityState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "a secure password"); err != nil {
		t.Fatal(err)
	}
	downgradeToV14(t, st.db)
	recent := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339Nano)
	idle := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	for _, row := range []struct{ token, created string }{{"recent", recent}, {"idle", idle}} {
		if _, err := st.db.Exec("INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?)", secret.HashToken(row.token), secret.HashToken("csrf"), expires, row.created); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path, box)
	if err != nil {
		t.Fatalf("v14 database did not migrate: %v", err)
	}
	defer st.Close()
	var version int
	if err := st.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	var lastSeen string
	if err := st.db.QueryRow("SELECT last_seen_at FROM sessions WHERE token_hash=?", secret.HashToken("recent")).Scan(&lastSeen); err != nil || lastSeen != recent {
		t.Fatalf("session activity not backfilled: %q %v", lastSeen, err)
	}
	if !st.ValidateSession(ctx, "recent", "csrf", true) {
		t.Fatal("a recently used session was signed out by the upgrade")
	}
	if st.ValidateSession(ctx, "idle", "csrf", true) {
		t.Fatal("a session idle for longer than the timeout survived the upgrade")
	}
	if !st.Authenticate(ctx, "a secure password") {
		t.Fatal("administrator password lost in the upgrade")
	}
	if _, err := st.RecordAdminAudit(ctx, AdminAuditEntry{Event: AuditLoginSuccess}, nil); err != nil {
		t.Fatalf("administrative audit table missing after the upgrade: %v", err)
	}
	var indexes int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('admin_audit_created_at','api_tokens_expires_at')").Scan(&indexes); err != nil || indexes != 2 {
		t.Fatalf("retention indexes missing: %d %v", indexes, err)
	}
	if _, value, err := st.CreateAPIToken(ctx, "after upgrade", []string{ScopeStatusRead}, time.Hour); err != nil {
		t.Fatalf("API token table missing after the upgrade: %v", err)
	} else if _, err := st.AuthenticateAPIToken(ctx, value); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaV14ToV15ReportsErrors(t *testing.T) {
	t.Run("missing sessions table", func(t *testing.T) {
		db := migrationErrorDB(t)
		if err := migrateSchemaV14ToV15(db); err == nil || !strings.Contains(err.Error(), "sessions") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("session backfill", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 14)
		if _, err := db.Exec(`INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES('h','c','2030-01-01T00:00:00Z','2026-01-01T00:00:00Z');
CREATE TRIGGER fail_session_backfill BEFORE UPDATE OF last_seen_at ON sessions BEGIN SELECT RAISE(ABORT,'backfill failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV14ToV15(db); err == nil || !strings.Contains(err.Error(), "backfill session activity") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("audit table", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 14)
		if _, err := db.Exec("DROP TABLE admin_audit; CREATE VIEW admin_audit AS SELECT 1 AS created_at, 1 AS id"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV14ToV15(db); err == nil || !strings.Contains(err.Error(), "create administrative audit table") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("API token table", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 14)
		if _, err := db.Exec("DROP TABLE api_tokens; CREATE VIEW api_tokens AS SELECT 1 AS expires_at, 1 AS id"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV14ToV15(db); err == nil || !strings.Contains(err.Error(), "create API token table") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("schema version", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 14)
		if _, err := db.Exec(`CREATE TRIGGER fail_v15_schema_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV14ToV15(db); err == nil || !strings.Contains(err.Error(), "record administrative security migration") {
			t.Fatalf("migration error=%v", err)
		}
		var version int
		if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 14 {
			t.Fatalf("failed migration changed schema version to %d err=%v", version, err)
		}
	})
	t.Run("dispatch", func(t *testing.T) {
		box, _ := secret.NewBox(make([]byte, 32))
		db := migrationErrorDB(t)
		if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(14)"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "sessions") {
			t.Fatalf("dispatch error=%v", err)
		}
	})
}

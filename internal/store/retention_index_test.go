package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func storeIndexNames(t *testing.T, st *Store) map[string]bool {
	t.Helper()
	rows, err := st.db.Query("SELECT name FROM sqlite_master WHERE type='index'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

// TestSchemaV13MigrationReplacesRedundantIndexes upgrades a schema v12
// database that still carries the redundant events_observed_at and
// evidence_ledger_batch_id indexes, and asserts that fresh and migrated
// databases end with the same retention index set.
func TestSchemaV13MigrationReplacesRedundantIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	assertIndexes := func(stage string) {
		t.Helper()
		names := storeIndexNames(t, st)
		for _, removed := range []string{"events_observed_at", "evidence_ledger_batch_id"} {
			if names[removed] {
				t.Fatalf("%s: redundant index %s is present", stage, removed)
			}
		}
		for _, required := range []string{"events_retention", "event_batches_observed_at", "outbox_dead_retention", "auth_tokens_kind"} {
			if !names[required] {
				t.Fatalf("%s: index %s is missing", stage, required)
			}
		}
	}
	assertIndexes("fresh database")
	for _, statement := range []string{
		"CREATE INDEX events_observed_at ON events(observed_at)",
		"CREATE INDEX evidence_ledger_batch_id ON evidence_ledger(batch_id)",
		"DROP INDEX outbox_dead_retention",
		"DROP INDEX auth_tokens_kind",
		"UPDATE schema_version SET version=12",
	} {
		if _, err := st.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	assertIndexes("migrated database")
	var version int
	if err := st.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
}

func TestSchemaV12ToV13ReportsIndexErrors(t *testing.T) {
	db := currentSchemaMigrationDB(t, 12)
	if _, err := db.Exec("DROP TABLE outbox"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV12ToV13(db); err == nil || !strings.Contains(err.Error(), "update retention indexes") {
		t.Fatalf("missing outbox index migration error=%v", err)
	}
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 12 {
		t.Fatalf("failed migration changed schema version to %d err=%v", version, err)
	}
}

// TestOpenReportsRetentionIndexErrors covers the post-migration index
// creation that fresh databases rely on.
func TestOpenReportsRetentionIndexErrors(t *testing.T) {
	for _, test := range []struct {
		name, index, want string
	}{
		{name: "outbox", index: "outbox_dead_retention", want: "outbox dead-letter retention index"},
		{name: "auth tokens", index: "auth_tokens_kind", want: "authentication token kind index"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tailstate.db")
			box, _ := secret.NewBox(make([]byte, 32))
			st, err := Open(path, box)
			if err != nil {
				t.Fatal(err)
			}
			// A view with the index name makes CREATE INDEX IF NOT EXISTS fail.
			for _, statement := range []string{"DROP INDEX " + test.index, "CREATE VIEW " + test.index + " AS SELECT 1"} {
				if _, err := st.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, box); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("open error=%v, want %q", err, test.want)
			}
		})
	}
}

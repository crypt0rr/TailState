package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestVersionOneMigrationAddsDestinationAndPreservesLegacyOutbox(t *testing.T) {
	tests := []struct {
		name          string
		withLegacyURL bool
	}{
		{name: "legacy mattermost", withLegacyURL: true},
		{name: "without legacy setting", withLegacyURL: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tailstate.db")
			box, err := secret.NewBox(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			legacySecret, err := box.Encrypt("oauth-secret")
			if err != nil {
				t.Fatal(err)
			}
			legacyURL := ""
			if tt.withLegacyURL {
				legacyURL, err = box.Encrypt("https://mattermost.example/hooks/token")
				if err != nil {
					t.Fatal(err)
				}
			}
			db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
			if err != nil {
				t.Fatal(err)
			}
			legacySchema := `
CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(1);
CREATE TABLE settings(id INTEGER PRIMARY KEY,tailnet TEXT NOT NULL,oauth_client_id TEXT NOT NULL,oauth_secret_enc TEXT NOT NULL,mattermost_url_enc TEXT NOT NULL,device_interval_seconds INTEGER NOT NULL,inventory_interval_seconds INTEGER NOT NULL,generation INTEGER NOT NULL,configured_at TEXT NOT NULL,baseline_at TEXT);
CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_attempt TEXT NOT NULL,first_attempt TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,delivered_at TEXT);
`
			if _, err := db.Exec(legacySchema); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if _, err := db.Exec("INSERT INTO settings VALUES(1,'-',?,?,?,60,300,1,'2026-01-01T00:00:00Z',NULL)", "client", legacySecret, legacyURL); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if _, err := db.Exec("INSERT INTO outbox(payload,next_attempt,first_attempt,created_at) VALUES('legacy payload','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			st, err := Open(path, box)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			var version int
			if err := st.db.QueryRowContext(context.Background(), "SELECT version FROM schema_version").Scan(&version); err != nil {
				t.Fatal(err)
			}
			if version != currentSchemaVersion {
				t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
			}
			var destinationColumn int
			if err := st.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM pragma_table_info('outbox') WHERE name='destination_id'").Scan(&destinationColumn); err != nil {
				t.Fatal(err)
			}
			if destinationColumn != 1 {
				t.Fatal("v1 migration did not add outbox destination_id")
			}
			var destinationCount int
			if err := st.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM notification_destinations").Scan(&destinationCount); err != nil {
				t.Fatal(err)
			}
			if tt.withLegacyURL {
				if destinationCount != 1 {
					t.Fatalf("migrated destination count = %d", destinationCount)
				}
				destinations, err := st.ListDestinations(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(destinations) != 1 || !strings.HasPrefix(destinations[0].ServiceURL, "mattermost://TailState@mattermost.example/token") {
					t.Fatalf("migrated destinations = %#v", destinations)
				}
				var destinationID, outboxDestinationID int64
				if err := st.db.QueryRowContext(context.Background(), "SELECT id FROM notification_destinations LIMIT 1").Scan(&destinationID); err != nil {
					t.Fatal(err)
				}
				if err := st.db.QueryRowContext(context.Background(), "SELECT destination_id FROM outbox LIMIT 1").Scan(&outboxDestinationID); err != nil {
					t.Fatal(err)
				}
				if destinationID != outboxDestinationID {
					t.Fatalf("outbox destination = %d, migrated destination = %d", outboxDestinationID, destinationID)
				}
			} else if destinationCount != 0 {
				t.Fatalf("destination created without a legacy URL: %d", destinationCount)
			}
		})
	}
}

func TestMigrateSchemaRejectsUnknownAndMissingVersions(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	missing, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateSchema(missing, box); err == nil || !strings.Contains(err.Error(), "read database schema version") {
		t.Fatalf("missing schema version error = %v", err)
	}
	missing.Close()

	unknown, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unknown.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(0)"); err != nil {
		unknown.Close()
		t.Fatal(err)
	}
	if err := migrateSchema(unknown, box); err == nil || !strings.Contains(err.Error(), "requires a newer migration path") {
		t.Fatalf("unknown schema version error = %v", err)
	}
	unknown.Close()
}

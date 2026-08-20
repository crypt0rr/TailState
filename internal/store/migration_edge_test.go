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
			} else {
				if destinationCount != 0 {
					t.Fatalf("destination created without a legacy URL: %d", destinationCount)
				}
				var status, lastError string
				if err := st.db.QueryRowContext(context.Background(), "SELECT status,last_error FROM outbox LIMIT 1").Scan(&status, &lastError); err != nil {
					t.Fatal(err)
				}
				if status != "dead" || lastError != "no notification destination configured" {
					t.Fatalf("orphaned outbox status = %q/%q, want dead-letter reason", status, lastError)
				}
			}
		})
	}
}

func TestVersionFourMigrationThroughOpenPreservesDurableState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	secretValue, err := box.Encrypt("oauth-secret")
	if err != nil {
		t.Fatal(err)
	}
	mattermostURL, err := box.Encrypt("mattermost://TailState@mattermost.example/token")
	if err != nil {
		t.Fatal(err)
	}
	webhookSecret, err := box.Encrypt("webhook-secret")
	if err != nil {
		t.Fatal(err)
	}
	destinationURL, err := box.Encrypt("generic://notify.example/hooks/token")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := `
CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(4);
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE settings(id INTEGER PRIMARY KEY,tailnet TEXT NOT NULL,oauth_client_id TEXT NOT NULL,oauth_secret_enc TEXT NOT NULL,mattermost_url_enc TEXT NOT NULL,webhook_secret_enc TEXT NOT NULL DEFAULT '',device_interval_seconds INTEGER NOT NULL,inventory_interval_seconds INTEGER NOT NULL,generation INTEGER NOT NULL,configured_at TEXT NOT NULL,baseline_at TEXT);
CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,service_url_enc TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE TABLE event_batches(id INTEGER PRIMARY KEY AUTOINCREMENT,generation INTEGER NOT NULL,observed_at TEXT NOT NULL,change_count INTEGER NOT NULL,created_at TEXT NOT NULL,trigger_id INTEGER);
CREATE TABLE webhook_triggers(id INTEGER PRIMARY KEY AUTOINCREMENT,body_hash TEXT NOT NULL UNIQUE,received_at TEXT NOT NULL,event_types_json BLOB NOT NULL,collectors_json BLOB NOT NULL,status TEXT NOT NULL DEFAULT 'accepted',processed_at TEXT);
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,batch_id INTEGER,generation INTEGER NOT NULL,observed_at TEXT NOT NULL,collector TEXT NOT NULL,event_type TEXT NOT NULL,resource_id TEXT NOT NULL,name TEXT NOT NULL,changes_json BLOB NOT NULL,before_json BLOB,after_json BLOB);
CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,batch_id INTEGER,destination_id INTEGER NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_attempt TEXT NOT NULL,first_attempt TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,delivered_at TEXT);
`
	if _, err := db.Exec(legacySchema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err := db.Exec("INSERT INTO settings VALUES(1,'tailnet.example','client',?,?,?,?,?,?,?,NULL)", secretValue, mattermostURL, webhookSecret, 60, 300, 7, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO notification_destinations(name,service_url_enc,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", "Notifications", destinationURL, 1, now, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO webhook_triggers(body_hash,received_at,event_types_json,collectors_json) VALUES(?,?,?,?)", strings.Repeat("a", 64), now, `["policyUpdate"]`, `["policy"]`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO event_batches(generation,observed_at,change_count,created_at,trigger_id) VALUES(?,?,?,?,1)", 7, now, 1, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(1,?,?,?,?,?,?,?)", 7, now, "policy", "changed", "policy", "Tailnet policy", `[]`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO outbox(batch_id,destination_id,payload,next_attempt,first_attempt,created_at) VALUES(1,1,'legacy payload',?,?,?)", now, now, now); err != nil {
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
	assertVersionAndState := func(t *testing.T, st *Store) {
		t.Helper()
		var version int
		if err := st.db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version != currentSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
		}
		var status, nextAttempt string
		if err := st.db.QueryRowContext(ctx, "SELECT status,next_attempt_at FROM webhook_triggers WHERE id=1").Scan(&status, &nextAttempt); err != nil {
			t.Fatal(err)
		}
		if status != "pending" || nextAttempt != now {
			t.Fatalf("migrated webhook trigger = %q/%q", status, nextAttempt)
		}
		var linkedTrigger int64
		if err := st.db.QueryRowContext(ctx, "SELECT trigger_id FROM event_batch_triggers WHERE batch_id=1").Scan(&linkedTrigger); err != nil {
			t.Fatal(err)
		}
		if linkedTrigger != 1 {
			t.Fatalf("event batch trigger link = %d, want 1", linkedTrigger)
		}
		var payload string
		if err := st.db.QueryRowContext(ctx, "SELECT payload FROM outbox WHERE id=1").Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if payload != "legacy payload" {
			t.Fatalf("outbox payload = %q", payload)
		}
		settings, err := st.Settings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if settings.Tailnet != "tailnet.example" || settings.Generation != 7 {
			t.Fatalf("settings not preserved: %#v", settings)
		}
		page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Batches) != 1 || len(page.Batches[0].Events) != 1 {
			t.Fatalf("history not preserved: %#v", page)
		}
		var ledgerRows int
		if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&ledgerRows); err != nil {
			t.Fatal(err)
		}
		if ledgerRows != 1 {
			t.Fatalf("evidence ledger rows = %d, want 1", ledgerRows)
		}
	}
	assertVersionAndState(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertVersionAndState(t, reopened)
}

func TestVersionSixMigrationThroughOpenMigratesLegacyAuthenticationTokens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}

	setupToken := "legacy-setup-token"
	resetToken := "legacy-reset-token"
	db, err := sqlOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM auth_tokens; DELETE FROM meta WHERE key IN ('setup_token_hash','reset_token_hash'); UPDATE schema_version SET version=6"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO meta(key,value) VALUES('setup_token_hash',?),('reset_token_hash',?)", secret.HashToken(setupToken), secret.HashToken(resetToken)); err != nil {
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
	var migrated int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_tokens").Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != 2 {
		t.Fatalf("migrated authentication token count=%d, want 2", migrated)
	}
	if err := st.Claim(ctx, setupToken, "a secure password"); err != nil {
		t.Fatalf("migrated setup token was not usable: %v", err)
	}
	if err := st.ResetWithToken(ctx, resetToken, "another secure password"); err != nil {
		t.Fatalf("migrated reset token was not usable: %v", err)
	}
	var remaining int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_tokens").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("consumed migrated authentication tokens=%d, want 0", remaining)
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

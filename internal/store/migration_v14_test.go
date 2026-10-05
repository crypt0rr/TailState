package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
)

// v14Columns are the columns schema v14 adds; downgradeToV13 removes them to
// reproduce a database written by the previous release.
var v14Columns = []struct{ table, column string }{
	{"notification_destinations", "route_min_severity"},
	{"notification_destinations", "route_include_collectors"},
	{"notification_destinations", "route_exclude_collectors"},
	{"notification_destinations", "route_change_kinds"},
	{"events", "severity"},
	{"events", "muted"},
	{"notification_destinations", "message_format"},
	{"outbox", "payload_format"},
}

func downgradeToV13(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, column := range v14Columns {
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", column.table, column.column)); err != nil {
			t.Fatalf("drop %s.%s: %v", column.table, column.column, err)
		}
	}
	if _, err := db.Exec("DROP TABLE mute_rules"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE schema_version SET version=13"); err != nil {
		t.Fatal(err)
	}
}

func auditComplete(t *testing.T, st *Store) EvidenceAuditResult {
	t.Helper()
	result, err := st.AuditEvidenceLedger(context.Background(), EvidenceAuditOptions{Limit: 10000})
	if err != nil {
		t.Fatalf("evidence audit failed: %v", err)
	}
	if !result.Complete || !result.HeadMatches || result.VerifiedEntries != result.Entries || result.Entries == 0 {
		t.Fatalf("evidence audit incomplete: %+v", result)
	}
	return result
}

// TestSchemaV14MigrationKeepsDefaultsAndEvidence upgrades a schema v13
// database: existing destinations route every change (no behaviour change on
// upgrade), existing events are classified in resumable chunks, and the
// signed evidence ledger still verifies, including packs exported before the
// upgrade.
func TestSchemaV14MigrationKeepsDefaultsAndEvidence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	const devices = 70 // more than one migration chunk
	version := func(v string) func(int) map[string]any {
		return func(int) map[string]any { return map[string]any{"clientVersion": v} }
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(version("1.0"), devices)}, notify.TextDigest("baseline")); err != nil {
		t.Fatal(err)
	}
	upgrade, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(version("1.1"), devices)}, notify.TextDigest("upgrade"))
	if err != nil || len(upgrade.Changes) != devices {
		t.Fatalf("upgrade batch changes=%d err=%v", len(upgrade.Changes), err)
	}
	const legacyPayload = "### Tailscale inventory changed\n**1 change(s):** queued before the upgrade"
	if err := st.EnqueueSystem(ctx, legacyPayload); err != nil {
		t.Fatal(err)
	}
	preUpgradePack, err := st.ExportEvidencePack(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	before := auditComplete(t, st)
	downgradeToV13(t, st.db)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path, box)
	if err != nil {
		t.Fatalf("v13 database did not migrate: %v", err)
	}
	defer st.Close()
	var schemaVersion int
	if err := st.db.QueryRow("SELECT version FROM schema_version").Scan(&schemaVersion); err != nil || schemaVersion != 14 {
		t.Fatalf("schema version=%d err=%v", schemaVersion, err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 || !destinations[0].Routing.AllChanges() || destinations[0].Format != notify.FormatAuto {
		t.Fatalf("migrated destination routing=%+v err=%v", destinations, err)
	}
	// Rows queued before the upgrade are pre-rendered Markdown and are still
	// delivered exactly as stored, whatever format the destination uses.
	if err := st.SetDestinationFormat(ctx, destinations[0].ID, notify.FormatPlain); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimDueOutbox(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	legacyFound := false
	for _, item := range claimed {
		if item.PayloadFormat != notify.PayloadMarkdown {
			t.Fatalf("pre-upgrade row has payload format %q", item.PayloadFormat)
		}
		prepared, err := notify.Prepare(item.PayloadFormat, item.Payload, item.Destination.ServiceURL, item.Destination.Format)
		if err != nil || prepared != item.Payload {
			t.Fatalf("pre-upgrade row was not delivered unchanged: %q err=%v", prepared, err)
		}
		legacyFound = legacyFound || item.Payload == legacyPayload
	}
	if !legacyFound {
		t.Fatal("the pre-upgrade outbox row was not claimable after the migration")
	}
	var unclassified, low int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM events WHERE severity=''").Scan(&unclassified); err != nil || unclassified != 0 {
		t.Fatalf("unclassified events=%d err=%v", unclassified, err)
	}
	if err := st.db.QueryRow("SELECT COUNT(*) FROM events WHERE severity='low'").Scan(&low); err != nil || low != devices {
		t.Fatalf("low events=%d err=%v", low, err)
	}
	after := auditComplete(t, st)
	if after.ObservedHead != before.ObservedHead {
		t.Fatalf("migration changed the ledger head: %s -> %s", before.ObservedHead, after.ObservedHead)
	}
	if err := VerifyEvidencePack(preUpgradePack); err != nil {
		t.Fatalf("pre-upgrade evidence pack no longer verifies: %v", err)
	}
	next, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(version("1.2"), devices)}, notify.TextDigest("after upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	if deliveries := batchDeliveries(t, st, next.ID); len(deliveries) != 1 {
		t.Fatalf("migrated destination did not receive all changes: %v", deliveries)
	}
	pack, err := st.ExportEvidencePack(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(pack); err != nil {
		t.Fatalf("post-upgrade evidence pack does not verify: %v", err)
	}
	auditComplete(t, st)
}

func TestSchemaV13ToV14ReportsErrors(t *testing.T) {
	t.Run("missing destinations table", func(t *testing.T) {
		db := migrationErrorDB(t)
		if err := migrateSchemaV13ToV14(db); err == nil || !strings.Contains(err.Error(), "add notification_destinations.route_min_severity") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("severity backfill read", func(t *testing.T) {
		db := migrationErrorDB(t)
		if _, err := db.Exec(`CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY);
CREATE TABLE events(id INTEGER PRIMARY KEY, severity TEXT NOT NULL DEFAULT '');
CREATE TABLE outbox(id INTEGER PRIMARY KEY);
INSERT INTO events(id) VALUES(1);`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV13ToV14(db); err == nil || !strings.Contains(err.Error(), "read events for severity backfill") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("severity backfill write", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 13)
		if _, err := db.Exec(`INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(1,1,'2026-10-05T12:00:00Z','devices','created','d','d','[]');
CREATE TRIGGER fail_severity BEFORE UPDATE OF severity ON events BEGIN SELECT RAISE(ABORT,'severity update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV13ToV14(db); err == nil || !strings.Contains(err.Error(), "record event severity") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("schema version", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 13)
		if _, err := db.Exec(`CREATE TRIGGER fail_v14_schema_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV13ToV14(db); err == nil || !strings.Contains(err.Error(), "record notification routing migration") {
			t.Fatalf("migration error=%v", err)
		}
		var version int
		if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 13 {
			t.Fatalf("failed migration changed schema version to %d err=%v", version, err)
		}
	})
	t.Run("dispatch", func(t *testing.T) {
		box, _ := secret.NewBox(make([]byte, 32))
		db := migrationErrorDB(t)
		if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(13)"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "add notification_destinations.route_min_severity") {
			t.Fatalf("dispatch error=%v", err)
		}
	})
}

func TestClassifyStoredEventToleratesLegacyAndDamagedFields(t *testing.T) {
	if got := classifyStoredEvent("devices", "changed", []byte(`[{"field":"clientVersion","old":"1","new":"2"}]`)); got != model.SeverityLow {
		t.Fatalf("legacy array severity=%q", got)
	}
	if got := classifyStoredEvent("devices", "changed", []byte(`{"fields":[{"field":"clientVersion","old":"1","new":"2"}],"fields_truncated":true,"total_fields":30}`)); got != model.SeverityMedium {
		t.Fatalf("truncated envelope severity=%q", got)
	}
	if got := classifyStoredEvent("devices", "changed", []byte(`not json`)); got != model.SeverityMedium {
		t.Fatalf("damaged fields severity=%q", got)
	}
	if got := classifyStoredEvent("policy", "changed", nil); got != model.SeverityHigh {
		t.Fatalf("policy severity=%q", got)
	}
}

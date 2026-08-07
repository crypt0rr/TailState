package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func historyResource(hostname, address string) model.Collected {
	return model.Collected{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{
			"hostname":  hostname,
			"addresses": []any{address},
		},
	}}}
}

func TestHistoryPersistsExplainableChangesAndDeliveryState(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "digest" }, 12)
	if err != nil {
		t.Fatal(err)
	}
	if batch.ID == 0 || batch.ChangeCount != 1 || len(batch.Changes) != 1 {
		t.Fatalf("unexpected change batch: %#v", batch)
	}
	if batch.TriggerID != 12 {
		t.Fatalf("webhook trigger correlation was lost: %#v", batch)
	}

	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 1 || page.Batches[0].ID != batch.ID {
		t.Fatalf("unexpected history page: %#v", page)
	}
	history := page.Batches[0]
	if history.TriggerID != 12 {
		t.Fatalf("history did not retain webhook trigger correlation: %#v", history)
	}
	if len(history.Events) != 1 {
		t.Fatalf("unexpected history events: %#v", history.Events)
	}
	event := history.Events[0]
	if event.EventType != "changed" || event.BeforeJSON == "" || event.AfterJSON == "" {
		t.Fatalf("history event lost snapshots: %#v", event)
	}
	if strings.Contains(event.BeforeJSON, "mattermost.example") || strings.Contains(event.AfterJSON, "mattermost.example") {
		t.Fatal("notification destination leaked into normalized history")
	}
	foundHostname := false
	for _, field := range event.Fields {
		if field.Field == "hostname" {
			foundHostname = true
			if field.Old != `"server"` || field.New != `"server-new"` || !field.HasOld || !field.HasNew {
				t.Fatalf("unexpected hostname diff: %#v", field)
			}
		}
	}
	if !foundHostname {
		t.Fatalf("hostname diff missing: %#v", event.Fields)
	}
	if len(history.Deliveries) != 1 || history.Deliveries[0].Destination != "Mattermost" || history.Deliveries[0].Status != "pending" {
		t.Fatalf("unexpected delivery history: %#v", history.Deliveries)
	}
	items, err := st.DueOutbox(ctx, 10)
	if err != nil || len(items) != 1 || items[0].BatchID != batch.ID {
		t.Fatalf("outbox batch correlation missing: %#v %v", items, err)
	}
	if err := st.Retry(ctx, items[0].ID, time.Now().UTC().Add(time.Minute), "delivery failed for "+items[0].Destination.ServiceURL, false); err != nil {
		t.Fatal(err)
	}
	page, err = st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.Batches[0].Deliveries[0].LastError, items[0].Destination.ServiceURL) {
		t.Fatal("destination URL leaked into persisted delivery error")
	}

	if filtered, err := st.ListHistory(ctx, HistoryFilter{EventType: "created", Limit: 10}); err != nil {
		t.Fatal(err)
	} else if len(filtered.Batches) != 0 {
		t.Fatalf("event type filter returned unrelated batch: %#v", filtered)
	}
	if filtered, err := st.ListHistory(ctx, HistoryFilter{ResourceID: "device-1", Limit: 10}); err != nil {
		t.Fatal(err)
	} else if len(filtered.Batches) != 1 {
		t.Fatalf("resource filter missed event: %#v", filtered)
	}
}

func TestHistoryCorrelatesCoalescedWebhookTriggers(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	first, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), []string{"policyUpdate"}, []string{"devices"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("e", 64), []string{"deviceUpdate"}, []string{"devices"})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "digest" }, first.ID, second.ID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.TriggerIDs) != 2 || batch.TriggerIDs[0] != first.ID || batch.TriggerIDs[1] != second.ID {
		t.Fatalf("coalesced trigger IDs were not normalized: %#v", batch)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil || len(page.Batches) != 1 {
		t.Fatalf("load correlated history: %#v err=%v", page, err)
	}
	if len(page.Batches[0].TriggerIDs) != 2 || page.Batches[0].TriggerIDs[0] != first.ID || page.Batches[0].TriggerIDs[1] != second.ID {
		t.Fatalf("history lost coalesced trigger IDs: %#v", page.Batches[0])
	}
}

func TestEvidencePackExportIsRedactedAndVerifiable(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" })
	if err != nil {
		t.Fatal(err)
	}
	items, err := st.DueOutbox(ctx, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("expected one outbox item: %d %v", len(items), err)
	}
	if err := st.Retry(ctx, items[0].ID, time.Now().UTC().Add(time.Minute), "delivery failed for "+items[0].Destination.ServiceURL, true); err != nil {
		t.Fatal(err)
	}

	export, err := st.ExportEvidencePack(ctx, HistoryFilter{EventType: "changed", ResourceID: "device-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(export); err != nil {
		t.Fatalf("evidence pack did not verify: %v", err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(export, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Format != evidencePackFormat || pack.Version != evidencePackVersion || len(pack.Batches) != 1 || pack.Batches[0].ID != batch.ID {
		t.Fatalf("unexpected evidence pack: %#v", pack)
	}
	if len(pack.Batches[0].Events) != 1 || len(pack.Batches[0].Events[0].Fields) == 0 {
		t.Fatalf("evidence pack lost event details: %#v", pack.Batches)
	}
	if strings.Contains(string(export), "/hooks/") || strings.Contains(string(export), "super-secret") {
		t.Fatalf("evidence pack leaked destination credentials: %s", export)
	}
	tampered := strings.Replace(string(export), pack.ContentSHA256, strings.Repeat("0", len(pack.ContentSHA256)), 1)
	if err := VerifyEvidencePack([]byte(tampered)); err == nil {
		t.Fatal("tampered evidence pack unexpectedly verified")
	}
}

func TestHistoryPaginationAndRemovalSnapshot(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	first, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server-one", "100.64.0.1")}, func([]model.Change) string { return "first" })
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server-two", "100.64.0.1")}, func([]model.Change) string { return "second" })
	if err != nil {
		t.Fatal(err)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 1 || page.Batches[0].ID != second.ID || !page.HasNext || page.NextCursor != second.ID {
		t.Fatalf("unexpected first history page: %#v", page)
	}
	older, err := st.ListHistory(ctx, HistoryFilter{Limit: 1, Cursor: page.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(older.Batches) != 1 || older.Batches[0].ID != first.ID || older.HasNext {
		t.Fatalf("pagination skipped or repeated batch: %#v", older)
	}

	empty := []model.Collected{{Collector: "devices"}}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, empty, func([]model.Change) string { return "missing" }); err != nil {
		t.Fatal(err)
	}
	removed, err := st.ApplyBatchWithBatch(ctx, generation, empty, func([]model.Change) string { return "removed" })
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID == 0 || len(removed.Changes) != 1 || removed.Changes[0].Kind != "removed" {
		t.Fatalf("removal was not recorded: %#v", removed)
	}
	page, err = st.ListHistory(ctx, HistoryFilter{EventType: "removed", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 1 || len(page.Batches[0].Events) != 1 || page.Batches[0].Events[0].BeforeJSON == "" || page.Batches[0].Events[0].AfterJSON != "" {
		t.Fatalf("removal snapshot history is incomplete: %#v", page)
	}
}

func TestSchemaV2HistoryMigrationBackfillsBatchCorrelation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	legacySecret, _ := box.Encrypt("secret")
	legacyURL, _ := box.Encrypt("mattermost://TailState@mattermost.example/token")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := `
CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(2);
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE settings(id INTEGER PRIMARY KEY,tailnet TEXT NOT NULL,oauth_client_id TEXT NOT NULL,oauth_secret_enc TEXT NOT NULL,mattermost_url_enc TEXT NOT NULL,device_interval_seconds INTEGER NOT NULL,inventory_interval_seconds INTEGER NOT NULL,generation INTEGER NOT NULL,configured_at TEXT NOT NULL,baseline_at TEXT);
CREATE TABLE notification_destinations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,service_url_enc TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE TABLE snapshots(generation INTEGER NOT NULL,collector TEXT NOT NULL,resource_id TEXT NOT NULL,resource_type TEXT NOT NULL,name TEXT NOT NULL,canonical_json BLOB NOT NULL,content_hash TEXT NOT NULL,missing_count INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL,PRIMARY KEY(generation,collector,resource_id));
CREATE TABLE collector_state(generation INTEGER NOT NULL,collector TEXT NOT NULL,supported INTEGER NOT NULL DEFAULT 1,baseline INTEGER NOT NULL DEFAULT 0,last_success TEXT,last_error TEXT NOT NULL DEFAULT '',failure_count INTEGER NOT NULL DEFAULT 0,unhealthy_notified INTEGER NOT NULL DEFAULT 0,next_poll TEXT,PRIMARY KEY(generation,collector));
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,generation INTEGER NOT NULL,observed_at TEXT NOT NULL,collector TEXT NOT NULL,event_type TEXT NOT NULL,resource_id TEXT NOT NULL,name TEXT NOT NULL,changes_json BLOB NOT NULL);
CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,destination_id INTEGER NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_attempt TEXT NOT NULL,first_attempt TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,delivered_at TEXT);
`
	if _, err := db.Exec(legacySchema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec("INSERT INTO settings VALUES(1,'-',?,?,?,60,300,1,?,NULL)", "client", legacySecret, legacyURL, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO notification_destinations(name,service_url_enc,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", "Mattermost", legacyURL, 1, now, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events(generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(1,?,?,?,?,?,?)", now, "devices", "changed", "device-1", "server", `[]`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO outbox(destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(1,'digest','pending',?,?,?)", now, now, now); err != nil {
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
	if err := st.db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("migration left schema version %d", version)
	}
	var webhookColumn int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('settings') WHERE name='webhook_secret_enc'").Scan(&webhookColumn); err != nil {
		t.Fatal(err)
	}
	if webhookColumn != 1 {
		t.Fatal("schema migration did not add the encrypted webhook secret column")
	}
	var triggerTable int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='webhook_triggers'").Scan(&triggerTable); err != nil {
		t.Fatal(err)
	}
	if triggerTable != 1 {
		t.Fatal("schema migration did not create webhook trigger storage")
	}
	for _, column := range []string{"attempts", "next_attempt_at", "lease_until", "last_error"} {
		var found int
		if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('webhook_triggers') WHERE name=?", column).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found != 1 {
			t.Fatalf("schema migration did not add webhook trigger column %q", column)
		}
	}
	var linkTable int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='event_batch_triggers'").Scan(&linkTable); err != nil {
		t.Fatal(err)
	}
	if linkTable != 1 {
		t.Fatal("schema migration did not create event batch trigger links")
	}
	var batchID, eventBatchID, outboxBatchID int64
	if err := st.db.QueryRowContext(ctx, "SELECT id FROM event_batches LIMIT 1").Scan(&batchID); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT batch_id FROM events LIMIT 1").Scan(&eventBatchID); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT batch_id FROM outbox LIMIT 1").Scan(&outboxBatchID); err != nil {
		t.Fatal(err)
	}
	if batchID == 0 || eventBatchID != batchID || outboxBatchID != batchID {
		t.Fatalf("migration did not correlate legacy rows: batch=%d event=%d outbox=%d", batchID, eventBatchID, outboxBatchID)
	}
	var ledgerRows int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 1 {
		t.Fatalf("schema migration did not backfill the evidence ledger: %d", ledgerRows)
	}
}

func TestCleanupRemovesExpiredHistoryBatches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := historyResource("server", "100.64.0.1")
	changed := historyResource("server-new", "100.64.0.2")
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{baseline}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{changed}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE events SET observed_at=?", old); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var batches int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM event_batches").Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if batches != 0 {
		t.Fatalf("expired event batch was retained: %d", batches)
	}
}

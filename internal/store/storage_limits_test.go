package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestSchemaV11ToV12BackfillsSnapshotMetadata(t *testing.T) {
	db := migrationErrorDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(11);
CREATE TABLE snapshots(generation INTEGER NOT NULL,collector TEXT NOT NULL,resource_id TEXT NOT NULL,canonical_json BLOB NOT NULL,content_hash TEXT NOT NULL,PRIMARY KEY(generation,collector,resource_id));
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,before_json BLOB,after_json BLOB);`); err != nil {
		t.Fatal(err)
	}
	full := []byte(`{"hostname":"server"}`)
	marker := truncationJSON("full-hash", 10000, 4096, "byte limit")
	if _, err := db.Exec("INSERT INTO snapshots(generation,collector,resource_id,canonical_json,content_hash) VALUES(1,'devices','1',?,?)", marker, "full-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events(before_json,after_json) VALUES(?,?)", full, marker); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV11ToV12(db); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 12 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	var snapshotBytes int64
	var snapshotTruncated int
	if err := db.QueryRow("SELECT content_bytes,content_truncated FROM snapshots").Scan(&snapshotBytes, &snapshotTruncated); err != nil {
		t.Fatal(err)
	}
	if snapshotBytes != 10000 || snapshotTruncated != 1 {
		t.Fatalf("snapshot metadata=%d/%d", snapshotBytes, snapshotTruncated)
	}
	var beforeHash, afterHash string
	var beforeBytes, afterBytes int64
	var beforeTruncated, afterTruncated int
	if err := db.QueryRow("SELECT before_hash,after_hash,before_bytes,after_bytes,before_truncated,after_truncated FROM events").Scan(&beforeHash, &afterHash, &beforeBytes, &afterBytes, &beforeTruncated, &afterTruncated); err != nil {
		t.Fatal(err)
	}
	if beforeHash != valueHash(full) || beforeBytes != int64(len(full)) || beforeTruncated != 0 || afterHash != "full-hash" || afterBytes != 10000 || afterTruncated != 1 {
		t.Fatalf("event metadata=%q/%d/%d %q/%d/%d", beforeHash, beforeBytes, beforeTruncated, afterHash, afterBytes, afterTruncated)
	}
	if err := db.Close(); err != nil && err != sql.ErrConnDone {
		t.Fatal(err)
	}
}

func TestSchemaV11ToV12ReportsMissingTables(t *testing.T) {
	db := migrationErrorDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(11);`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV11ToV12(db); err == nil || !strings.Contains(err.Error(), "add snapshots.content_bytes") {
		t.Fatalf("missing-table migration error=%v", err)
	}
}

func TestSchemaV11ToV12ReportsBackfillErrors(t *testing.T) {
	tests := []struct {
		name    string
		trigger string
		setup   string
		want    string
	}{
		{
			name:    "snapshot metadata update",
			trigger: "fail_snapshot_metadata",
			setup: `INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,updated_at)
VALUES(1,'devices','device-1','device','server','{}','hash','2026-01-01T00:00:00Z');`,
			want: "backfill snapshot size metadata",
		},
		{
			name:    "event metadata update",
			trigger: "fail_event_metadata",
			setup: `INSERT INTO events(generation,observed_at,collector,event_type,resource_id,name,changes_json)
VALUES(1,'2026-01-01T00:00:00Z','devices','changed','device-1','server','{}');`,
			want: "backfill event snapshot metadata",
		},
		{
			name: "schema version update",
			want: "record bounded history migration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := currentSchemaMigrationDB(t, 11)
			if tt.setup != "" {
				if _, err := db.Exec(tt.setup); err != nil {
					t.Fatal(err)
				}
			}
			trigger := "CREATE TRIGGER " + tt.trigger + " BEFORE UPDATE ON "
			switch tt.name {
			case "snapshot metadata update":
				trigger += "snapshots"
			case "event metadata update":
				trigger += "events"
			default:
				trigger += "schema_version"
			}
			trigger += " BEGIN SELECT RAISE(ABORT,'bounded history migration failed'); END"
			if _, err := db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchemaV11ToV12(db); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
	db := currentSchemaMigrationDB(t, 11)
	if err := db.Close(); err != nil && err != sql.ErrConnDone {
		t.Fatal(err)
	}
	if err := migrateSchemaV11ToV12(db); err == nil || !strings.Contains(err.Error(), "begin bounded history migration") {
		t.Fatalf("closed database migration error=%v", err)
	}
}

func TestSchemaV11ToV12ReportsMetadataScanErrors(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{
			name: "snapshot metadata scan",
			schema: `CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(11);
CREATE TABLE snapshots(generation INTEGER,collector TEXT,resource_id TEXT,canonical_json BLOB,content_hash TEXT);
CREATE TABLE events(id INTEGER PRIMARY KEY,before_json BLOB,after_json BLOB);
INSERT INTO snapshots(generation,collector,resource_id,canonical_json,content_hash) VALUES(1,'devices','device-1','{}',NULL);`,
			want: "scan snapshot size metadata",
		},
		{
			name: "event metadata scan",
			schema: `CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(11);
CREATE TABLE snapshots(generation INTEGER,collector TEXT,resource_id TEXT,canonical_json BLOB,content_hash TEXT);
CREATE TABLE events(id TEXT PRIMARY KEY,before_json BLOB,after_json BLOB);
INSERT INTO events(id,before_json,after_json) VALUES('not-an-integer','{}',NULL);`,
			want: "scan event snapshot metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := migrationErrorDB(t)
			if _, err := db.Exec(tt.schema); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchemaV11ToV12(db); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("migration error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestSchemaV11ToV12ResumesAfterAChunkFailure(t *testing.T) {
	db := currentSchemaMigrationDB(t, 11)
	for i := 0; i < migrationChunkSize+1; i++ {
		if _, err := db.Exec("INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,updated_at) VALUES(1,'devices',?,?,?,?,?,?)", "device-"+strconv.Itoa(i), "device", "server", `{"hostname":"server"}`, "hash", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("CREATE TRIGGER fail_second_snapshot_chunk BEFORE UPDATE ON snapshots WHEN NEW.resource_id='device-" + strconv.Itoa(migrationChunkSize) + "' BEGIN SELECT RAISE(ABORT,'pause bounded migration'); END"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV11ToV12(db); err == nil || !strings.Contains(err.Error(), "backfill snapshot size metadata") {
		t.Fatalf("first migration error=%v", err)
	}
	var migrated int
	if err := db.QueryRow("SELECT COUNT(*) FROM snapshots WHERE content_bytes > 0").Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != migrationChunkSize {
		t.Fatalf("completed snapshot rows=%d, want %d", migrated, migrationChunkSize)
	}
	var cursor int64
	if err := db.QueryRow("SELECT cursor FROM schema_migration_progress WHERE migration=?", boundedHistoryMigration).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != migrationChunkSize {
		t.Fatalf("migration cursor=%d, want %d", cursor, migrationChunkSize)
	}
	if _, err := db.Exec("DROP TRIGGER fail_second_snapshot_chunk"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV11ToV12(db); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 12 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM snapshots WHERE content_bytes > 0").Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != migrationChunkSize+1 {
		t.Fatalf("resumed snapshot rows=%d, want %d", migrated, migrationChunkSize+1)
	}
}

func TestBoundedSnapshotsRetainHashAndTruncationMetadata(t *testing.T) {
	ctx := context.Background()
	st, generation := configuredCoverageStore(t)
	if err := st.SetStorageLimits(StorageLimits{
		SnapshotBytes:    4096,
		EventValueBytes:  2048,
		HistoryPageBytes: 4096,
		RejectBytes:      4096,
		DatabaseBytes:    1 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "small"},
	}}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("secret-free-value-", 500)
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": large},
	}}}}
	if _, err := testApplyBatch(st, ctx, generation, changed, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var hash string
	var bytes int64
	var truncated int
	if err := st.db.QueryRowContext(ctx, `SELECT canonical_json,content_hash,content_bytes,content_truncated
		FROM snapshots WHERE generation=? AND collector='devices' AND resource_id='device-1'`, generation).Scan(&stored, &hash, &bytes, &truncated); err != nil {
		t.Fatal(err)
	}
	if len(stored) >= len(large) || truncated != 1 || bytes <= int64(len(stored)) || hash == "" {
		t.Fatalf("snapshot was not bounded: stored=%d original=%d truncated=%d bytes=%d hash=%q", len(stored), len(large), truncated, bytes, hash)
	}
	var marker truncationMarker
	if err := json.Unmarshal(stored, &marker); err != nil || !marker.TailState.Truncated || marker.TailState.SHA256 != hash || marker.TailState.Bytes != bytes {
		t.Fatalf("snapshot marker=%s err=%v hash=%q bytes=%d", stored, err, hash, bytes)
	}
	var beforeHash, afterHash string
	var beforeBytes, afterBytes int64
	var beforeTruncated, afterTruncated int
	if err := st.db.QueryRowContext(ctx, `SELECT before_hash,after_hash,before_bytes,after_bytes,before_truncated,after_truncated
		FROM events ORDER BY id DESC LIMIT 1`).Scan(&beforeHash, &afterHash, &beforeBytes, &afterBytes, &beforeTruncated, &afterTruncated); err != nil {
		t.Fatal(err)
	}
	if beforeHash == "" || afterHash == "" || beforeBytes == 0 || afterBytes != bytes || beforeTruncated != 0 || afterTruncated != 1 {
		t.Fatalf("event metadata before=%q/%d/%d after=%q/%d/%d", beforeHash, beforeBytes, beforeTruncated, afterHash, afterBytes, afterTruncated)
	}
	metrics, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.SnapshotTruncations == 0 || metrics.EventValueTruncations == 0 || metrics.OversizedWritesRejected == 0 {
		t.Fatalf("truncation metrics=%#v", metrics)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil || len(page.Batches) != 1 || len(page.Batches[0].Events) != 1 {
		t.Fatalf("bounded history=%#v err=%v", page, err)
	}
	event := page.Batches[0].Events[0]
	if !event.AfterTruncated || event.AfterBytes != bytes || event.AfterHash != hash {
		t.Fatalf("history truncation metadata=%#v", event)
	}
	pack, err := st.ExportEvidencePack(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(pack); err != nil {
		t.Fatalf("truncated evidence did not verify: %v", err)
	}
}

func TestHistoryPageReportsByteBudget(t *testing.T) {
	ctx := context.Background()
	st, generation := configuredCoverageStore(t)
	if err := st.SetStorageLimits(StorageLimits{
		SnapshotBytes:    4096,
		EventValueBytes:  2048,
		HistoryPageBytes: 4096,
		RejectBytes:      1 << 20,
		DatabaseBytes:    1 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	resource := func(value string) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: []model.Resource{{
			ID: "device-1", Type: "device", Name: value, Data: map[string]any{"hostname": value},
		}}}}
	}
	if _, err := testApplyBatch(st, ctx, generation, resource("baseline"), func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := testApplyBatch(st, ctx, generation, resource(strings.Repeat("change", i+1)), func([]model.Change) string { return "changed" }); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || page.TruncationReason == "" || !page.HasNext || page.BytesRead > page.ByteLimit {
		t.Fatalf("history page did not report bounded read: %#v", page)
	}
	metrics, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.HistoryPageTruncations == 0 {
		t.Fatalf("history truncation metric=%#v", metrics)
	}
}

func TestHistoryPageReportsUnrenderableBatch(t *testing.T) {
	ctx := context.Background()
	st, generation := configuredCoverageStore(t)
	if err := st.SetStorageLimits(StorageLimits{SnapshotBytes: 4096, EventValueBytes: 2048, HistoryPageBytes: 4096, RejectBytes: 1 << 20, DatabaseBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := st.db.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(?,?,?,?)", generation, now, 20, now)
	if err != nil {
		t.Fatal(err)
	}
	batchID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := st.db.ExecContext(ctx, `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,?,?,?,?,?,?,?)`, batchID, generation, now, "devices", "changed", "device-"+strconv.Itoa(i), "server", `{"fields":[]}`); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Batches) != 0 || !page.HasNext || page.NextCursor != batchID+1 {
		t.Fatalf("unrenderable batch pagination=%#v", page)
	}
}

func TestHistoryLoadsLegacySnapshotMetadataFallbacks(t *testing.T) {
	ctx := context.Background()
	st, generation := configuredCoverageStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := st.db.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(?,?,?,?)", generation, now, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	batchID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	marker := truncationJSON("legacy-hash", 1234, 256, "byte limit")
	if _, err := st.db.ExecContext(ctx, `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json)
VALUES(?,?,?,?,?,?,?,?,?,?)`, batchID, generation, now, "devices", "changed", "device-1", "server", `[]`, marker, `{"hostname":"server"}`); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 1})
	if err != nil || len(page.Batches) != 1 || len(page.Batches[0].Events) != 1 {
		t.Fatalf("legacy metadata history=%#v err=%v", page, err)
	}
	event := page.Batches[0].Events[0]
	if !event.BeforeTruncated || event.BeforeHash != "legacy-hash" || event.BeforeBytes != 1234 || event.AfterHash != valueHash([]byte(`{"hostname":"server"}`)) || event.AfterBytes != int64(len(`{"hostname":"server"}`)) {
		t.Fatalf("legacy metadata fallback=%#v", event)
	}
}

func TestStorageLimitValidationAndMetricEdges(t *testing.T) {
	invalid := []StorageLimits{
		{SnapshotBytes: 512},
		{EventValueBytes: 512},
		{HistoryPageBytes: 1024},
		{RejectBytes: -1},
		{DatabaseBytes: -1},
		{SnapshotBytes: 4096, RejectBytes: 1024},
	}
	for _, limits := range invalid {
		st := testStore(t)
		if err := st.SetStorageLimits(limits); err == nil {
			t.Fatalf("invalid storage limits were accepted: %#v", limits)
		}
	}
	st := testStore(t)
	if err := st.SetStorageLimits(StorageLimits{}); err != nil {
		t.Fatal(err)
	}
	if got := st.StorageLimits(); got != DefaultStorageLimits() {
		t.Fatalf("default storage limits=%#v", got)
	}
	metrics, err := st.StorageMetrics(context.Background())
	if err != nil || metrics.DatabaseBytes <= 0 || metrics.DatabaseLimitBytes <= 0 {
		t.Fatalf("storage metrics=%#v err=%v", metrics, err)
	}
	if metrics.PressureRatio() <= 0 || (StorageMetrics{DatabaseLimitBytes: 0}).PressureRatio() != 0 {
		t.Fatalf("storage pressure metrics=%#v", metrics)
	}
	var nilStore *Store
	if nilStore.StorageLimits() != DefaultStorageLimits() {
		t.Fatal("nil store did not return default limits")
	}
	if _, err := nilStore.StorageMetrics(context.Background()); err == nil {
		t.Fatal("nil store returned storage metrics")
	}
	if (&Store{}).StorageLimits() != DefaultStorageLimits() {
		t.Fatal("uninitialized store did not return default limits")
	}
}

func TestDatabaseStorageLimitIsEnforcedAndSurvivesRestart(t *testing.T) {
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
	metrics, err := initial.StorageMetrics(ctx)
	if err != nil {
		initial.Close()
		t.Fatal(err)
	}
	var pageSize int64
	if err := initial.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		initial.Close()
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	limit := metrics.DatabaseBytes + 2*pageSize
	limits := StorageLimits{DatabaseBytes: limit}
	st, err := OpenWithLimits(path, box, limits)
	if err != nil {
		t.Fatal(err)
	}
	var writeErr error
	for i := 0; i < 32; i++ {
		_, writeErr = st.db.ExecContext(ctx, "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", "storage-filler-"+strconv.Itoa(i), strings.Repeat("x", 16<<10))
		if writeErr != nil {
			break
		}
	}
	if writeErr == nil || !errors.Is(storageWriteError(writeErr), ErrStorageBudgetExceeded) {
		st.Close()
		t.Fatalf("database limit write error=%v", writeErr)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithLimits(path, box, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.StorageLimits().DatabaseBytes; got != limit {
		t.Fatalf("reopened database limit=%d, want %d", got, limit)
	}
	current, err := reopened.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.DatabaseBytes > limit {
		t.Fatalf("database exceeded configured limit: %d > %d", current.DatabaseBytes, limit)
	}
	if err := reopened.SetStorageLimits(StorageLimits{DatabaseBytes: current.DatabaseBytes - 1}); err == nil {
		t.Fatal("lowering database limit below current size succeeded")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	persisted, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer persisted.Close()
	if got := persisted.StorageLimits().DatabaseBytes; got != limit {
		t.Fatalf("persisted database limit=%d, want %d", got, limit)
	}
}

func TestEvidenceSnapshotMetadataValidation(t *testing.T) {
	marker := string(truncationJSON("hash", 99, 10, "byte limit"))
	valid := []struct {
		name      string
		hash      string
		bytes     int64
		truncated bool
		raw       string
		wantErr   bool
	}{
		{name: "legacy empty", raw: ""},
		{name: "legacy raw", raw: `{"value":true}`},
		{name: "valid raw", hash: valueHash([]byte(`{"value":true}`)), bytes: int64(len(`{"value":true}`)), raw: `{"value":true}`},
		{name: "valid marker", hash: "hash", bytes: 99, truncated: true, raw: marker},
		{name: "marker hash mismatch", hash: "other", bytes: 99, truncated: true, raw: marker, wantErr: true},
		{name: "marker flag mismatch", hash: "hash", bytes: 99, raw: marker, wantErr: true},
		{name: "raw hash mismatch", hash: "other", bytes: 15, raw: `{"value":true}`, wantErr: true},
		{name: "raw bytes mismatch", hash: valueHash([]byte(`{"value":true}`)), bytes: 1, raw: `{"value":true}`, wantErr: true},
		{name: "empty metadata", hash: "hash", raw: "", wantErr: true},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyEvidenceSnapshotMetadata(tc.hash, tc.bytes, tc.truncated, tc.raw, "before", 1, 2)
			if (err != nil) != tc.wantErr {
				t.Fatalf("metadata error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestStorageMetricClosedDatabaseAndStoredValueEdges(t *testing.T) {
	value := existingStoredValue([]byte(`{"value":true}`), "hash", 0, false)
	if value.bytes != int64(len(value.raw)) || value.truncated {
		t.Fatalf("stored value edge=%#v", value)
	}
	st := testStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.StorageMetrics(context.Background()); err == nil {
		t.Fatal("closed database returned storage metrics")
	}
	open := testStore(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := open.StorageMetrics(canceled); err == nil {
		t.Fatal("canceled metrics query unexpectedly succeeded")
	}
}

func TestStorageLimitPersistenceAndErrorEdges(t *testing.T) {
	ctx := context.Background()
	var nilDB *sql.DB
	if _, found, err := loadPersistedStorageLimits(nilDB); err == nil || found {
		t.Fatalf("nil database persistence lookup = found=%t err=%v", found, err)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if limits, found, err := loadPersistedStorageLimits(db); err != nil || found || limits != (StorageLimits{}) {
		t.Fatalf("database without meta table = %#v found=%t err=%v", limits, found, err)
	}
	if _, err := db.Exec("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if limits, found, err := loadPersistedStorageLimits(db); err != nil || found || limits != (StorageLimits{}) {
		t.Fatalf("database without persisted limits = %#v found=%t err=%v", limits, found, err)
	}
	if _, err := db.Exec("INSERT INTO meta(key,value) VALUES(?,?)", storageLimitsMeta, "not-json"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPersistedStorageLimits(db); err == nil || !strings.Contains(err.Error(), "decode persisted storage limits") {
		t.Fatalf("malformed persisted limits error=%v", err)
	}
	if _, err := db.Exec("UPDATE meta SET value=? WHERE key=?", `{"SnapshotBytes":1}`, storageLimitsMeta); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPersistedStorageLimits(db); err == nil || !strings.Contains(err.Error(), "persisted storage limits") {
		t.Fatalf("invalid persisted limits error=%v", err)
	}
	valid := DefaultStorageLimits()
	if err := persistStorageLimits(ctx, db, valid); err != nil {
		t.Fatal(err)
	}
	if got, found, err := loadPersistedStorageLimits(db); err != nil || !found || got != valid {
		t.Fatalf("persisted limits = %#v found=%t err=%v, want %#v", got, found, err, valid)
	}

	if err := configureDatabasePageLimit(nil, valid.DatabaseBytes); err == nil {
		t.Fatal("nil database limit configuration unexpectedly succeeded")
	}
	if err := configureDatabasePageLimit(db, 0); err == nil {
		t.Fatal("zero database limit configuration unexpectedly succeeded")
	}
	if err := storageWriteError(nil); err != nil {
		t.Fatalf("storageWriteError(nil) = %v", err)
	}
	if err := storageWriteError(ErrStorageBudgetExceeded); !errors.Is(err, ErrStorageBudgetExceeded) {
		t.Fatalf("existing storage budget error = %v", err)
	}
	for _, raw := range []string{"database or disk is full", "database full", "SQLITE_FULL"} {
		if err := storageWriteError(errors.New(raw)); !errors.Is(err, ErrStorageBudgetExceeded) {
			t.Fatalf("storageWriteError(%q) = %v", raw, err)
		}
	}
	ordinary := errors.New("ordinary write failure")
	if err := storageWriteError(ordinary); !errors.Is(err, ordinary) {
		t.Fatalf("ordinary storage error = %v", err)
	}

	var closed *sql.DB
	closed, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := persistStorageLimits(ctx, closed, valid); err == nil {
		t.Fatal("persisting limits to closed database unexpectedly succeeded")
	}
	if err := configureDatabasePageLimit(closed, valid.DatabaseBytes); err == nil {
		t.Fatal("configuring closed database limit unexpectedly succeeded")
	}
	if _, _, err := loadPersistedStorageLimits(closed); err == nil {
		t.Fatal("loading limits from closed database unexpectedly succeeded")
	}
	if err := configureDatabasePageLimit(db, 1); err == nil {
		t.Fatal("database limit below the existing page count unexpectedly succeeded")
	}

	var nilStore *Store
	if err := nilStore.SetStorageLimits(valid); err == nil {
		t.Fatal("nil store accepted storage limits")
	}
	st := testStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.SetStorageLimits(valid); err == nil {
		t.Fatal("closed store accepted storage limits")
	}
	st = testStore(t)
	if _, err := st.db.Exec("DROP TABLE meta"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetStorageLimits(valid); err == nil || !strings.Contains(err.Error(), "persist storage limits") {
		t.Fatalf("storage limit persistence failure=%v", err)
	}
}

func TestBoundedHistoryMigrationProgressValidation(t *testing.T) {
	db := migrationErrorDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_migration_progress (
		migration TEXT PRIMARY KEY,
		phase TEXT NOT NULL,
		cursor INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO schema_migration_progress(migration,phase,cursor) VALUES(?,?,?)", boundedHistoryMigration, "invalid", 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readBoundedHistoryMigrationProgress(db); err == nil || !strings.Contains(err.Error(), "invalid bounded history migration progress") {
		t.Fatalf("invalid migration phase error=%v", err)
	}
	if _, err := db.Exec("UPDATE schema_migration_progress SET phase='events',cursor=-1 WHERE migration=?", boundedHistoryMigration); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readBoundedHistoryMigrationProgress(db); err == nil || !strings.Contains(err.Error(), "invalid bounded history migration progress") {
		t.Fatalf("negative migration cursor error=%v", err)
	}
	if err := updateBoundedHistoryMigrationProgress(db, "events", 0); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := updateBoundedHistoryMigrationProgress(db, "events", 0); err == nil {
		t.Fatal("progress update on closed database unexpectedly succeeded")
	}
}

func TestBoundedHistoryMigrationChunkReadErrors(t *testing.T) {
	db := migrationErrorDB(t)
	if _, _, err := migrateSnapshotMetadataChunk(db, 0); err == nil || !strings.Contains(err.Error(), "read snapshot size metadata") {
		t.Fatalf("snapshot chunk read error=%v", err)
	}
	if _, _, err := migrateEventMetadataChunk(db, 0); err == nil || !strings.Contains(err.Error(), "read event snapshot metadata") {
		t.Fatalf("event chunk read error=%v", err)
	}
}

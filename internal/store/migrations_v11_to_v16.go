package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/crypt0rr/tailstate/internal/model"
)

func migrateSchemaV11ToV12(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin bounded history migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS schema_migration_progress (
		migration TEXT PRIMARY KEY,
		phase TEXT NOT NULL,
		cursor INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return fmt.Errorf("create bounded history migration progress: %w", err)
	}
	for _, column := range []struct {
		table, name, definition string
	}{
		{table: "snapshots", name: "content_bytes", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "snapshots", name: "content_truncated", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "events", name: "before_hash", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "events", name: "after_hash", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "events", name: "before_bytes", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "events", name: "after_bytes", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "events", name: "before_truncated", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "events", name: "after_truncated", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit bounded history migration setup: %w", err)
	}

	phase, cursor, err := readBoundedHistoryMigrationProgress(db)
	if err != nil {
		return err
	}
	for {
		switch phase {
		case "snapshots":
			next, done, chunkErr := migrateSnapshotMetadataChunk(db, cursor)
			if chunkErr != nil {
				return chunkErr
			}
			if !done {
				cursor = next
				continue
			}
			if err := updateBoundedHistoryMigrationProgress(db, "events", 0); err != nil {
				return err
			}
			phase, cursor = "events", 0
		case "events":
			next, done, chunkErr := migrateEventMetadataChunk(db, cursor)
			if chunkErr != nil {
				return chunkErr
			}
			if !done {
				cursor = next
				continue
			}
			finalTx, beginErr := db.Begin()
			if beginErr != nil {
				return fmt.Errorf("begin bounded history migration completion: %w", beginErr)
			}
			if _, execErr := finalTx.Exec("UPDATE schema_version SET version=12"); execErr != nil {
				finalTx.Rollback()
				return fmt.Errorf("record bounded history migration: %w", execErr)
			}
			if _, execErr := finalTx.Exec("DROP TABLE schema_migration_progress"); execErr != nil {
				finalTx.Rollback()
				return fmt.Errorf("remove bounded history migration progress: %w", execErr)
			}
			if commitErr := finalTx.Commit(); commitErr != nil {
				return fmt.Errorf("commit bounded history migration: %w", commitErr)
			}
			return nil
		default:
			return fmt.Errorf("invalid bounded history migration phase %q", phase)
		}
	}
}

// migrateSchemaV12ToV13 hardens persisted state without changing any table
// layout. It scrubs the encrypted service URL of destinations that were
// soft-deleted before deletion started clearing it, drops two indexes that
// duplicate another index (events_observed_at is a prefix of
// events_retention because id is the rowid; evidence_ledger_batch_id
// duplicates the UNIQUE constraint's index), and adds the indexes that let
// every retention statement use an index search without a temporary sort.
func migrateSchemaV12ToV13(db *sql.DB) error {
	ctx := context.Background()
	err := withSecureDelete(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc='' WHERE deleted_at IS NOT NULL AND service_url_enc<>''"); err != nil {
			return fmt.Errorf("scrub deleted notification destinations: %w", err)
		}
		for _, statement := range []string{
			"DROP INDEX IF EXISTS events_observed_at",
			"DROP INDEX IF EXISTS evidence_ledger_batch_id",
			"CREATE INDEX IF NOT EXISTS outbox_dead_retention ON outbox(status, created_at)",
			"CREATE INDEX IF NOT EXISTS auth_tokens_kind ON auth_tokens(kind)",
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("update retention indexes: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version=13"); err != nil {
			return fmt.Errorf("record persistence hardening migration: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("persistence hardening migration: %w", err)
	}
	return nil
}

// migrateSchemaV13ToV14 adds notification routing, classification, noise
// control, and per-service rendering state. Every new column defaults to the
// pre-upgrade behaviour: destinations route all changes, choose their format
// from the URL scheme, no event is muted, and queued outbox rows keep their
// pre-rendered Markdown. Existing events are
// classified in bounded, resumable chunks; severity is derived data and is
// not part of the signed evidence ledger payload, and the ledger records the
// muted flag only when it is set, so neither can change an existing digest.
func migrateSchemaV13ToV14(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin notification routing migration: %w", err)
	}
	defer tx.Rollback()
	for _, column := range []struct {
		table, name, definition string
	}{
		{table: "notification_destinations", name: "route_min_severity", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "notification_destinations", name: "route_include_collectors", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "notification_destinations", name: "route_exclude_collectors", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "notification_destinations", name: "route_change_kinds", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "events", name: "severity", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "events", name: "muted", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "notification_destinations", name: "message_format", definition: "TEXT NOT NULL DEFAULT ''"},
		// Existing rows hold pre-rendered Markdown and keep being delivered
		// unchanged; new rows store a format-neutral message.
		{table: "outbox", name: "payload_format", definition: "TEXT NOT NULL DEFAULT 'markdown'"},
	} {
		if err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit notification routing columns: %w", err)
	}
	var cursor int64
	for {
		next, done, err := migrateEventSeverityChunk(db, cursor)
		if err != nil {
			return err
		}
		if done {
			break
		}
		cursor = next
	}
	finalTx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin notification routing migration completion: %w", err)
	}
	defer finalTx.Rollback()
	if _, err := finalTx.Exec(`CREATE TABLE IF NOT EXISTS mute_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL CHECK(kind IN ('collector','field','tag','resource')),
		value TEXT NOT NULL,
		created_at TEXT NOT NULL,
		UNIQUE(kind, value)
	)`); err != nil {
		return fmt.Errorf("create mute rules: %w", err)
	}
	if _, err := finalTx.Exec("UPDATE schema_version SET version=14"); err != nil {
		return fmt.Errorf("record notification routing migration: %w", err)
	}
	if err := finalTx.Commit(); err != nil {
		return fmt.Errorf("commit notification routing migration: %w", err)
	}
	return nil
}

// migrateSchemaV14ToV15 adds administrative security state: a last-seen
// time on sessions for the idle timeout, the administrative audit table, and
// hashed read-only API tokens.
// Existing sessions are backfilled with their creation time, so a session
// idle for longer than the timeout before the upgrade must sign in again;
// nothing else changes behaviour.
func migrateSchemaV14ToV15(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin administrative security migration: %w", err)
	}
	defer tx.Rollback()
	if err := addColumnIfMissing(tx, "sessions", "last_seen_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE sessions SET last_seen_at=created_at WHERE last_seen_at=''"); err != nil {
		return fmt.Errorf("backfill session activity: %w", err)
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS admin_audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			event TEXT NOT NULL,
			outcome TEXT NOT NULL DEFAULT 'success',
			client_ip TEXT NOT NULL DEFAULT '',
			session_ref TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			fields TEXT NOT NULL DEFAULT ''
		)`,
		"CREATE INDEX IF NOT EXISTS admin_audit_created_at ON admin_audit(created_at, id)",
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("create administrative audit table: %w", err)
		}
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			scopes TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			revoked_at TEXT,
			last_used_at TEXT
		)`,
		"CREATE INDEX IF NOT EXISTS api_tokens_expires_at ON api_tokens(expires_at, id)",
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("create API token table: %w", err)
		}
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=15"); err != nil {
		return fmt.Errorf("record administrative security migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit administrative security migration: %w", err)
	}
	return nil
}

// migrateSchemaV15ToV16 adds change attribution: a bounded "changed by"
// record on each event and the attribution lookup status of each batch. Both
// default to empty, so existing events show no attribution, their signed
// ledger payloads are unchanged, and the migration rewrites no row.
func migrateSchemaV15ToV16(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin change attribution migration: %w", err)
	}
	defer tx.Rollback()
	if err := addColumnIfMissing(tx, "events", "attribution", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("add events.attribution: %w", err)
	}
	if err := addColumnIfMissing(tx, "event_batches", "attribution_status", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("add event_batches.attribution_status: %w", err)
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=16"); err != nil {
		return fmt.Errorf("record change attribution migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit change attribution migration: %w", err)
	}
	return nil
}

// migrateEventSeverityChunk classifies up to migrationChunkSize unclassified
// events after cursor in one transaction. Rerunning it after an interruption
// only revisits events that are still unclassified.
func migrateEventSeverityChunk(db *sql.DB, cursor int64) (int64, bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return cursor, false, fmt.Errorf("begin event severity backfill: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT id,collector,event_type,changes_json FROM events WHERE id>? AND severity='' ORDER BY id LIMIT ?", cursor, migrationChunkSize)
	if err != nil {
		return cursor, false, fmt.Errorf("read events for severity backfill: %w", err)
	}
	type pending struct {
		id       int64
		severity model.Severity
	}
	var items []pending
	for rows.Next() {
		var id int64
		var collector, kind string
		var changes []byte
		if err := rows.Scan(&id, &collector, &kind, &changes); err != nil {
			rows.Close()
			return cursor, false, fmt.Errorf("read events for severity backfill: %w", err)
		}
		items = append(items, pending{id: id, severity: classifyStoredEvent(collector, kind, changes)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return cursor, false, fmt.Errorf("read events for severity backfill: %w", err)
	}
	if err := rows.Close(); err != nil {
		return cursor, false, err
	}
	if len(items) == 0 {
		return cursor, true, nil
	}
	for _, item := range items {
		if _, err := tx.Exec("UPDATE events SET severity=? WHERE id=?", string(item.severity), item.id); err != nil {
			return cursor, false, fmt.Errorf("record event severity: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return cursor, false, fmt.Errorf("commit event severity backfill: %w", err)
	}
	return items[len(items)-1].id, false, nil
}

type snapshotMetadataMigrationRow struct {
	rowID       int64
	contentHash string
	canonical   []byte
	bytes       int64
	truncated   int
}

func readBoundedHistoryMigrationProgress(db *sql.DB) (string, int64, error) {
	var phase string
	var cursor int64
	err := db.QueryRow("SELECT phase,cursor FROM schema_migration_progress WHERE migration=?", boundedHistoryMigration).Scan(&phase, &cursor)
	if errors.Is(err, sql.ErrNoRows) {
		if _, insertErr := db.Exec("INSERT INTO schema_migration_progress(migration,phase,cursor) VALUES(?,?,0)", boundedHistoryMigration, "snapshots"); insertErr != nil {
			return "", 0, fmt.Errorf("initialize bounded history migration progress: %w", insertErr)
		}
		return "snapshots", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("read bounded history migration progress: %w", err)
	}
	if phase != "snapshots" && phase != "events" || cursor < 0 {
		return "", 0, fmt.Errorf("invalid bounded history migration progress phase=%q cursor=%d", phase, cursor)
	}
	return phase, cursor, nil
}

func updateBoundedHistoryMigrationProgress(db *sql.DB, phase string, cursor int64) error {
	if _, err := db.Exec("UPDATE schema_migration_progress SET phase=?,cursor=? WHERE migration=?", phase, cursor, boundedHistoryMigration); err != nil {
		return fmt.Errorf("update bounded history migration progress: %w", err)
	}
	return nil
}

func migrateSnapshotMetadataChunk(db *sql.DB, cursor int64) (int64, bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return cursor, false, fmt.Errorf("begin snapshot metadata backfill: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT rowid,generation,collector,resource_id,canonical_json,content_hash FROM snapshots WHERE rowid>? ORDER BY rowid LIMIT ?", cursor, migrationChunkSize)
	if err != nil {
		return cursor, false, fmt.Errorf("read snapshot size metadata: %w", err)
	}
	items := make([]snapshotMetadataMigrationRow, 0, migrationChunkSize)
	var next int64
	for rows.Next() {
		var row snapshotMetadataMigrationRow
		var generation, collector, resourceID string
		if err := rows.Scan(&row.rowID, &generation, &collector, &resourceID, &row.canonical, &row.contentHash); err != nil {
			rows.Close()
			return cursor, false, fmt.Errorf("scan snapshot size metadata: %w", err)
		}
		row.bytes = int64(len(row.canonical))
		if marker, ok := parseTruncationMarker(row.canonical); ok {
			row.contentHash = marker.TailState.SHA256
			row.bytes = marker.TailState.Bytes
			row.truncated = 1
		}
		items = append(items, row)
		next = row.rowID
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return cursor, false, fmt.Errorf("read snapshot size metadata rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return cursor, false, fmt.Errorf("close snapshot size metadata: %w", err)
	}
	if len(items) == 0 {
		return cursor, true, nil
	}
	for _, item := range items {
		if _, err := tx.Exec(`UPDATE snapshots SET content_hash=?,content_bytes=?,content_truncated=? WHERE rowid=?`, item.contentHash, item.bytes, item.truncated, item.rowID); err != nil {
			return cursor, false, fmt.Errorf("backfill snapshot size metadata: %w", err)
		}
	}
	if _, err := tx.Exec("UPDATE schema_migration_progress SET cursor=? WHERE migration=? AND phase='snapshots'", next, boundedHistoryMigration); err != nil {
		return cursor, false, fmt.Errorf("update snapshot metadata progress: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return cursor, false, fmt.Errorf("commit snapshot metadata backfill: %w", err)
	}
	slog.Info("database history migration chunk completed", "migration", boundedHistoryMigration, "phase", "snapshots", "rows", len(items), "cursor", next)
	return next, false, nil
}

type eventMetadataMigrationRow struct {
	id                              int64
	before, after                   []byte
	beforeHash, afterHash           string
	beforeBytes, afterBytes         int64
	beforeTruncated, afterTruncated int
}

func migrateEventMetadataChunk(db *sql.DB, cursor int64) (int64, bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return cursor, false, fmt.Errorf("begin event metadata backfill: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT id,before_json,after_json FROM events WHERE id>? ORDER BY id LIMIT ?", cursor, migrationChunkSize)
	if err != nil {
		return cursor, false, fmt.Errorf("read event snapshot metadata: %w", err)
	}
	items := make([]eventMetadataMigrationRow, 0, migrationChunkSize)
	var next int64
	for rows.Next() {
		var item eventMetadataMigrationRow
		if err := rows.Scan(&item.id, &item.before, &item.after); err != nil {
			rows.Close()
			return cursor, false, fmt.Errorf("scan event snapshot metadata: %w", err)
		}
		if len(item.before) > 0 {
			item.beforeHash = valueHash(item.before)
			item.beforeBytes = int64(len(item.before))
			if marker, ok := parseTruncationMarker(item.before); ok {
				item.beforeHash = marker.TailState.SHA256
				item.beforeBytes = marker.TailState.Bytes
				item.beforeTruncated = 1
			}
		}
		if len(item.after) > 0 {
			item.afterHash = valueHash(item.after)
			item.afterBytes = int64(len(item.after))
			if marker, ok := parseTruncationMarker(item.after); ok {
				item.afterHash = marker.TailState.SHA256
				item.afterBytes = marker.TailState.Bytes
				item.afterTruncated = 1
			}
		}
		items = append(items, item)
		next = item.id
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return cursor, false, fmt.Errorf("read event snapshot metadata rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return cursor, false, fmt.Errorf("close event snapshot metadata: %w", err)
	}
	if len(items) == 0 {
		return cursor, true, nil
	}
	for _, item := range items {
		if _, err := tx.Exec(`UPDATE events SET before_hash=?,after_hash=?,before_bytes=?,after_bytes=?,before_truncated=?,after_truncated=? WHERE id=?`, item.beforeHash, item.afterHash, item.beforeBytes, item.afterBytes, item.beforeTruncated, item.afterTruncated, item.id); err != nil {
			return cursor, false, fmt.Errorf("backfill event snapshot metadata: %w", err)
		}
	}
	if _, err := tx.Exec("UPDATE schema_migration_progress SET cursor=? WHERE migration=? AND phase='events'", next, boundedHistoryMigration); err != nil {
		return cursor, false, fmt.Errorf("update event metadata progress: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return cursor, false, fmt.Errorf("commit event metadata backfill: %w", err)
	}
	slog.Info("database history migration chunk completed", "migration", boundedHistoryMigration, "phase", "events", "rows", len(items), "cursor", next)
	return next, false, nil
}

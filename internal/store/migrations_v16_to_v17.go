package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// timestampMigration names the schema 17 rewrite in progress logs.
const timestampMigration = "v16_to_v17"

// timestampColumns are the operational timestamp columns that schema 17
// rewrites into timestampLayout. They are the columns compared or ordered as
// strings in SQL (leases, expiries, retry and retention times) plus the
// collector schedule. Observation times (events, event_batches, and
// evidence_ledger) are deliberately absent: they are part of signed evidence
// payloads and keep their exact bytes; see observationBound.
var timestampColumns = []struct {
	table   string
	columns []string
}{
	{table: "sessions", columns: []string{"expires_at", "created_at", "last_seen_at"}},
	{table: "auth_tokens", columns: []string{"created_at", "expires_at"}},
	{table: "api_tokens", columns: []string{"created_at", "expires_at", "revoked_at", "last_used_at"}},
	{table: "admin_audit", columns: []string{"created_at"}},
	{table: "outbox", columns: []string{"next_attempt", "first_attempt", "created_at", "delivered_at", "lease_until"}},
	{table: "webhook_triggers", columns: []string{"received_at", "next_attempt_at", "lease_until", "processed_at"}},
	{table: "collector_state", columns: []string{"last_success", "next_poll"}},
}

// migrateSchemaV16ToV17 rewrites stored operational timestamps from the
// variable-width RFC 3339 form into timestampLayout, so SQL string
// comparisons order times within the same second correctly. Each table is
// rewritten in bounded transactions of migrationChunkSize rows. The rewrite
// is idempotent (a value already in timestampLayout, empty, NULL, or
// unparseable is left as it is), so an interrupted upgrade simply runs again
// on the next start; the schema version changes only after every table is
// done.
func migrateSchemaV16ToV17(db *sql.DB) error {
	for _, target := range timestampColumns {
		var cursor int64
		for {
			next, done, err := migrateTimestampChunk(db, target.table, target.columns, cursor)
			if err != nil {
				return err
			}
			if done {
				break
			}
			cursor = next
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin timestamp format migration completion: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE schema_version SET version=17"); err != nil {
		return fmt.Errorf("record timestamp format migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit timestamp format migration: %w", err)
	}
	return nil
}

// migrateTimestampChunk rewrites the listed columns of up to
// migrationChunkSize rows of table after rowid cursor in one transaction. It
// returns the last rowid read, or done when no row follows cursor.
func migrateTimestampChunk(db *sql.DB, table string, columns []string, cursor int64) (int64, bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return cursor, false, fmt.Errorf("begin %s timestamp rewrite: %w", table, err)
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT rowid,"+strings.Join(columns, ",")+" FROM "+table+" WHERE rowid>? ORDER BY rowid LIMIT ?", cursor, migrationChunkSize)
	if err != nil {
		return cursor, false, fmt.Errorf("read %s timestamps: %w", table, err)
	}
	type rewrite struct {
		rowID  int64
		values []any
	}
	var pending []rewrite
	var next int64
	read := 0
	for rows.Next() {
		var rowID int64
		values := make([]sql.NullString, len(columns))
		targets := []any{&rowID}
		for index := range values {
			targets = append(targets, &values[index])
		}
		if err := rows.Scan(targets...); err != nil {
			rows.Close()
			return cursor, false, fmt.Errorf("scan %s timestamps: %w", table, err)
		}
		read++
		next = rowID
		changed := false
		update := make([]any, len(columns))
		for index, value := range values {
			update[index] = value
			if !value.Valid {
				continue
			}
			if normalized, ok := normalizeStoredTimestamp(value.String); ok {
				update[index] = normalized
				changed = true
			}
		}
		if changed {
			pending = append(pending, rewrite{rowID: rowID, values: update})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return cursor, false, fmt.Errorf("read %s timestamp rows: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return cursor, false, fmt.Errorf("close %s timestamps: %w", table, err)
	}
	if read == 0 {
		return cursor, true, nil
	}
	assignments := make([]string, len(columns))
	for index, column := range columns {
		assignments[index] = column + "=?"
	}
	statement := "UPDATE " + table + " SET " + strings.Join(assignments, ",") + " WHERE rowid=?"
	for _, item := range pending {
		if _, err := tx.Exec(statement, append(item.values, item.rowID)...); err != nil {
			return cursor, false, fmt.Errorf("rewrite %s timestamps: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return cursor, false, fmt.Errorf("commit %s timestamp rewrite: %w", table, err)
	}
	if len(pending) > 0 {
		slog.Info("database timestamp migration chunk completed", "migration", timestampMigration, "table", table, "rows", len(pending), "cursor", next)
	}
	return next, false, nil
}

// normalizeStoredTimestamp returns value in timestampLayout and whether that
// differs from value. Values that are not RFC 3339 times are kept.
func normalizeStoredTimestamp(value string) (string, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value, false
	}
	normalized := formatTimestamp(parsed)
	return normalized, normalized != value
}

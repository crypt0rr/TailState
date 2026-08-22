package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
)

// verifyLegacyMasterKey checks the encrypted columns present in schema v1
// without issuing any write. Those databases do not have meta.master_key_check
// yet, so this read-only preflight is the only way to reject a wrong key before
// Open executes the bootstrap DDL and begins migration.
func verifyLegacyMasterKey(db *sql.DB, box *secret.Box) error {
	if db == nil || box == nil {
		return errors.New("master key preflight is unavailable")
	}
	// Databases created before meta.master_key_check, and databases where that
	// marker was removed or damaged, still need a read-only key check before
	// bootstrap DDL. Inspect the columns that exist rather than assuming the v1
	// layout: this also covers encrypted destinations and signing metadata that
	// were introduced by later migrations.
	for _, table := range []struct {
		name    string
		columns []string
	}{
		{name: "settings", columns: []string{"oauth_secret_enc", "mattermost_url_enc", "webhook_secret_enc"}},
		{name: "notification_destinations", columns: []string{"service_url_enc"}},
	} {
		present, available, err := tableColumns(db, table.name)
		if err != nil {
			return fmt.Errorf("inspect %s schema: %w", table.name, err)
		}
		if !present {
			continue
		}
		for _, column := range table.columns {
			if !available[column] {
				continue
			}
			rows, queryErr := db.Query("SELECT " + column + " FROM " + table.name)
			if queryErr != nil {
				return fmt.Errorf("read encrypted %s.%s: %w", table.name, column, queryErr)
			}
			if err := verifyEncryptedRows(rows, box); err != nil {
				return fmt.Errorf("verify encrypted %s.%s: %w", table.name, column, err)
			}
		}
	}

	present, available, err := tableColumns(db, "meta")
	if err != nil {
		return fmt.Errorf("inspect meta schema: %w", err)
	}
	if present && available["key"] && available["value"] {
		rows, queryErr := db.Query("SELECT value FROM meta WHERE key IN ('master_key_check','evidence_signing_private_key_enc')")
		if queryErr != nil {
			return fmt.Errorf("read encrypted meta values: %w", queryErr)
		}
		if err := verifyEncryptedRows(rows, box); err != nil {
			return fmt.Errorf("verify encrypted meta values: %w", err)
		}
	}
	return nil
}

// verifyDatabaseVersionPreflight refuses to treat a non-empty SQLite file as
// a fresh TailState database when its schema marker is missing or malformed.
// Bootstrap DDL inserts the current schema version when schema_version does
// not exist (or is empty); doing that against an older or hand-edited file
// would skip every migration and can leave existing data incompatible with the
// runtime. The check is read-only so a failed startup cannot mutate the file
// it is trying to protect.
func verifyDatabaseVersionPreflight(db *sql.DB) error {
	var versionTable int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'").Scan(&versionTable); err != nil {
		return fmt.Errorf("inspect database schema marker: %w", err)
	}
	if versionTable == 0 {
		var objects int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
			WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','view','trigger')`).Scan(&objects); err != nil {
			return fmt.Errorf("inspect unversioned database objects: %w", err)
		}
		if objects > 0 {
			return errors.New("refusing to bootstrap an unversioned existing database; restore a verified backup or add a supported schema migration")
		}
		return nil
	}

	// The bootstrap DDL inserts the current version only when the marker table
	// has no rows. A damaged or hand-edited database could therefore appear
	// current while still containing an older layout if the marker is empty or
	// duplicated. Validate the marker before any CREATE/INSERT statements so
	// those files fail closed without changing their contents.
	var markerRows int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&markerRows); err != nil {
		return fmt.Errorf("inspect database schema marker rows: %w", err)
	}
	if markerRows != 1 {
		return fmt.Errorf("refusing to use database with %d schema version markers; restore a verified backup or add a supported schema migration", markerRows)
	}
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		return fmt.Errorf("inspect database schema version: %w", err)
	}
	if version < 1 || version > currentSchemaVersion {
		return fmt.Errorf("refusing to use unsupported database schema version %d before bootstrap DDL (supported versions: 1-%d)", version, currentSchemaVersion)
	}
	return nil
}

func tableColumns(db *sql.DB, table string) (bool, map[string]bool, error) {
	var present int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name=? AND type IN ('table','view')", table).Scan(&present); err != nil {
		return false, nil, err
	}
	if present == 0 {
		return false, nil, nil
	}
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, nil, err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return false, nil, err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, nil, err
	}
	if err := rows.Close(); err != nil {
		return false, nil, err
	}
	return true, columns, nil
}

func verifyEncryptedRows(rows *sql.Rows, box *secret.Box) error {
	defer rows.Close()
	for rows.Next() {
		var encrypted sql.NullString
		if err := rows.Scan(&encrypted); err != nil {
			return err
		}
		if strings.TrimSpace(encrypted.String) == "" {
			continue
		}
		if _, err := box.Decrypt(encrypted.String); err != nil {
			return errors.New("master key does not match this database")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

// migrateSchema owns the versioned on-disk upgrade path. Keeping migrations
// separate from runtime settings, reconciliation, and history queries makes
// schema changes easier to review without changing their transactional
// behavior.
func migrateSchema(db *sql.DB, box *secret.Box) error {
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&version); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than this TailState release supports (max %d)", version, currentSchemaVersion)
	}
	if version == currentSchemaVersion {
		return nil
	}
	if version == 2 {
		if err := migrateSchemaV2ToV3(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 3 {
		if err := migrateSchemaV3ToV4(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 4 {
		if err := migrateSchemaV4ToV5(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 5 {
		if err := migrateSchemaV5ToV6(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 6 {
		if err := migrateSchemaV6ToV7(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 7 {
		if err := migrateSchemaV7ToV8(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 8 {
		if err := migrateSchemaV8ToV9(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 9 {
		if err := migrateSchemaV9ToV10(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version == 10 {
		if err := migrateSchemaV10ToV11(db); err != nil {
			return err
		}
		return migrateSchema(db, box)
	}
	if version != 1 {
		return fmt.Errorf("database schema version %d requires a newer migration path", version)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS notification_destinations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		service_url_enc TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT
	)`); err != nil {
		return fmt.Errorf("create notification destinations: %w", err)
	}
	var hasDestination bool
	rows, err := tx.Query("PRAGMA table_info(outbox)")
	if err != nil {
		return fmt.Errorf("inspect outbox schema: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "destination_id" {
			hasDestination = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("inspect outbox schema rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close outbox schema inspection: %w", err)
	}
	if !hasDestination {
		if _, err := tx.Exec("ALTER TABLE outbox ADD COLUMN destination_id INTEGER"); err != nil {
			return fmt.Errorf("upgrade outbox destinations: %w", err)
		}
	}
	var legacyEnc string
	err = tx.QueryRow("SELECT mattermost_url_enc FROM settings WHERE id=1").Scan(&legacyEnc)
	if errors.Is(err, sql.ErrNoRows) {
		legacyEnc = ""
	} else if err != nil {
		return fmt.Errorf("read legacy Mattermost setting: %w", err)
	}
	var destinationID int64
	if legacyEnc != "" {
		legacyURL, err := box.Decrypt(legacyEnc)
		if err != nil {
			return fmt.Errorf("decrypt legacy Mattermost setting: %w", err)
		}
		converted, err := notify.ConvertLegacyMattermostURL(legacyURL)
		if err != nil {
			return fmt.Errorf("migrate legacy Mattermost setting: %w", err)
		}
		convertedEnc, err := box.Encrypt(converted)
		if err != nil {
			return fmt.Errorf("encrypt migrated notification destination: %w", err)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		result, err := tx.Exec("INSERT INTO notification_destinations(name,service_url_enc,enabled,created_at,updated_at) VALUES(?,?,1,?,?)", "Mattermost", convertedEnc, now, now)
		if err != nil {
			return fmt.Errorf("store migrated notification destination: %w", err)
		}
		destinationID, err = result.LastInsertId()
		if err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE outbox SET destination_id=? WHERE destination_id IS NULL", destinationID); err != nil {
			return fmt.Errorf("assign migrated outbox rows: %w", err)
		}
	}
	// A v1 database can contain pending or in-flight notifications without a
	// configured Mattermost URL. Once the destination-specific outbox is in place
	// those rows can never be selected for delivery, so leave an explicit audit
	// trail instead of reporting them forever as pending or processing.
	if _, err := tx.Exec("UPDATE outbox SET status='dead',last_error='no notification destination configured' WHERE destination_id IS NULL AND status IN ('pending','processing')"); err != nil {
		return fmt.Errorf("dead-letter orphaned outbox rows: %w", err)
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=2"); err != nil {
		return fmt.Errorf("record schema migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return migrateSchema(db, box)
}

func migrateSchemaV2ToV3(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin event history migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS event_batches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		generation INTEGER NOT NULL,
		observed_at TEXT NOT NULL,
		change_count INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		trigger_id INTEGER
	)`); err != nil {
		return fmt.Errorf("create event batches: %w", err)
	}
	for _, column := range []struct {
		table, name, definition string
	}{
		{table: "events", name: "batch_id", definition: "INTEGER"},
		{table: "events", name: "before_json", definition: "BLOB"},
		{table: "events", name: "after_json", definition: "BLOB"},
		{table: "outbox", name: "batch_id", definition: "INTEGER"},
	} {
		if err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO event_batches(generation,observed_at,change_count,created_at)
		SELECT generation,observed_at,COUNT(*),observed_at
		FROM events WHERE batch_id IS NULL GROUP BY generation,observed_at`); err != nil {
		return fmt.Errorf("backfill event batches: %w", err)
	}
	if _, err := tx.Exec(`UPDATE events SET batch_id=(
		SELECT id FROM event_batches b
		WHERE b.generation=events.generation AND b.observed_at=events.observed_at
		ORDER BY b.id LIMIT 1
	) WHERE batch_id IS NULL`); err != nil {
		return fmt.Errorf("assign event batches: %w", err)
	}
	if _, err := tx.Exec(`UPDATE outbox SET batch_id=(
		SELECT id FROM event_batches b
		WHERE b.observed_at=outbox.created_at
		ORDER BY b.id DESC LIMIT 1
	) WHERE batch_id IS NULL`); err != nil {
		return fmt.Errorf("assign outbox event batches: %w", err)
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=3"); err != nil {
		return fmt.Errorf("record event history migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event history migration: %w", err)
	}
	return nil
}

func migrateSchemaV3ToV4(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin webhook migration: %w", err)
	}
	defer tx.Rollback()
	if err := addColumnIfMissing(tx, "settings", "webhook_secret_enc", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := addColumnIfMissing(tx, "event_batches", "trigger_id", "INTEGER"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS webhook_triggers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		body_hash TEXT NOT NULL UNIQUE,
		received_at TEXT NOT NULL,
		event_types_json BLOB NOT NULL,
		collectors_json BLOB NOT NULL,
		status TEXT NOT NULL DEFAULT 'accepted',
		processed_at TEXT
	)`); err != nil {
		return fmt.Errorf("create webhook triggers: %w", err)
	}
	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS webhook_triggers_received_at ON webhook_triggers(received_at DESC, id DESC)"); err != nil {
		return fmt.Errorf("create webhook trigger index: %w", err)
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=4"); err != nil {
		return fmt.Errorf("record webhook migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webhook migration: %w", err)
	}
	return nil
}

func migrateSchemaV4ToV5(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin durable webhook migration: %w", err)
	}
	defer tx.Rollback()
	for _, column := range []struct {
		table, name, definition string
	}{
		{table: "webhook_triggers", name: "attempts", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "webhook_triggers", name: "next_attempt_at", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "webhook_triggers", name: "lease_until", definition: "TEXT"},
		{table: "webhook_triggers", name: "last_error", definition: "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS event_batch_triggers (
		batch_id INTEGER NOT NULL,
		trigger_id INTEGER NOT NULL,
		PRIMARY KEY(batch_id, trigger_id)
	)`); err != nil {
		return fmt.Errorf("create event batch trigger links: %w", err)
	}
	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS event_batch_triggers_trigger_id ON event_batch_triggers(trigger_id, batch_id)"); err != nil {
		return fmt.Errorf("create event batch trigger link index: %w", err)
	}
	if _, err := tx.Exec(`UPDATE webhook_triggers
		SET status=CASE WHEN status='accepted' THEN 'pending' ELSE status END,
			next_attempt_at=CASE WHEN next_attempt_at='' THEN received_at ELSE next_attempt_at END`); err != nil {
		return fmt.Errorf("backfill durable webhook state: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO event_batch_triggers(batch_id,trigger_id)
		SELECT id,trigger_id FROM event_batches WHERE trigger_id IS NOT NULL AND trigger_id>0`); err != nil {
		return fmt.Errorf("backfill event batch trigger links: %w", err)
	}
	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS webhook_triggers_due ON webhook_triggers(status, next_attempt_at, id)"); err != nil {
		return fmt.Errorf("create durable webhook index: %w", err)
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=5"); err != nil {
		return fmt.Errorf("record durable webhook migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit durable webhook migration: %w", err)
	}
	return nil
}

func migrateSchemaV5ToV6(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin evidence ledger migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS evidence_ledger (
		sequence INTEGER PRIMARY KEY AUTOINCREMENT,
		batch_id INTEGER NOT NULL UNIQUE,
		generation INTEGER NOT NULL,
		observed_at TEXT NOT NULL,
		prev_hash TEXT NOT NULL,
		entry_hash TEXT NOT NULL UNIQUE,
		signature TEXT NOT NULL,
		key_id TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create evidence ledger: %w", err)
	}
	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS evidence_ledger_batch_id ON evidence_ledger(batch_id)"); err != nil {
		return fmt.Errorf("create evidence ledger index: %w", err)
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=6"); err != nil {
		return fmt.Errorf("record evidence ledger migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evidence ledger migration: %w", err)
	}
	return nil
}

func migrateSchemaV6ToV7(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin authentication token migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS auth_tokens (
		token_hash TEXT PRIMARY KEY,
		kind TEXT NOT NULL CHECK(kind IN ('setup','reset')),
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create authentication tokens: %w", err)
	}
	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS auth_tokens_expires_at ON auth_tokens(expires_at)"); err != nil {
		return fmt.Errorf("create authentication token index: %w", err)
	}
	now := time.Now().UTC()
	for _, token := range []struct {
		key       string
		kind      string
		expiresAt time.Time
	}{
		{key: "setup_token_hash", kind: "setup", expiresAt: now.Add(setupTokenLifetime)},
		{key: "reset_token_hash", kind: "reset", expiresAt: now.Add(resetTokenLifetime)},
	} {
		var hash string
		err := tx.QueryRow("SELECT value FROM meta WHERE key=?", token.key).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read legacy %s token: %w", token.kind, err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO auth_tokens(token_hash,kind,created_at,expires_at) VALUES(?,?,?,?)`, hash, token.kind, now.Format(time.RFC3339Nano), token.expiresAt.Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("migrate %s token: %w", token.kind, err)
		}
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=7"); err != nil {
		return fmt.Errorf("record authentication token migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit authentication token migration: %w", err)
	}
	return nil
}

func migrateSchemaV7ToV8(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin collector telemetry migration: %w", err)
	}
	defer tx.Rollback()
	for _, column := range []struct {
		table, name, definition string
	}{
		{table: "collector_state", name: "poll_duration_ms", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "collector_state", name: "partial", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	// Capture the pre-upgrade history boundary before startup creates any
	// ledger entries. Retries after a failed backfill must use the same cutoff
	// so rows inserted after the migration cannot be signed as historical.
	var hasMeta int
	if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'").Scan(&hasMeta); err != nil {
		return fmt.Errorf("inspect metadata table for evidence ledger cutoff: %w", err)
	}
	if hasMeta > 0 {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO meta(key,value)
			SELECT ?, CAST(COALESCE(MAX(id),0) AS TEXT)
			FROM event_batches`, evidenceLedgerBackfillCutoff); err != nil {
			return fmt.Errorf("record evidence ledger backfill cutoff: %w", err)
		}
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=8"); err != nil {
		return fmt.Errorf("record collector telemetry migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collector telemetry migration: %w", err)
	}
	return nil
}

func migrateSchemaV8ToV9(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin partial error count migration: %w", err)
	}
	defer tx.Rollback()
	if err := addColumnIfMissing(tx, "collector_state", "partial_error_count", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=9"); err != nil {
		return fmt.Errorf("record partial error count migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit partial error count migration: %w", err)
	}
	return nil
}

func migrateSchemaV9ToV10(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin webhook lease fencing migration: %w", err)
	}
	defer tx.Rollback()
	if err := addColumnIfMissing(tx, "webhook_triggers", "lease_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=10"); err != nil {
		return fmt.Errorf("record webhook lease fencing migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webhook lease fencing migration: %w", err)
	}
	return nil
}

func migrateSchemaV10ToV11(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin outbox lease fencing migration: %w", err)
	}
	defer tx.Rollback()
	for _, column := range []struct {
		table, name, definition string
	}{
		{table: "outbox", name: "lease_until", definition: "TEXT"},
		{table: "outbox", name: "lease_token", definition: "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("UPDATE schema_version SET version=11"); err != nil {
		return fmt.Errorf("record outbox lease fencing migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit outbox lease fencing migration: %w", err)
	}
	return nil
}

func addColumnIfMissing(tx *sql.Tx, table, column, definition string) error {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			if err := rows.Close(); err != nil {
				return err
			}
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

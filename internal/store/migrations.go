package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/crypt0rr/tailstate/internal/secret"
)

const (
	boundedHistoryMigration = "v11_to_v12"
	migrationChunkSize      = 64
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
			// rowid equals the INTEGER PRIMARY KEY id of both tables, which is
			// the row key in their encryption bindings.
			rows, queryErr := db.Query("SELECT rowid," + column + " FROM " + table.name)
			if queryErr != nil {
				return fmt.Errorf("read encrypted %s.%s: %w", table.name, column, queryErr)
			}
			if err := verifyEncryptedRows(rows, box, table.name+"."+column); err != nil {
				return fmt.Errorf("verify encrypted %s.%s: %w", table.name, column, err)
			}
		}
	}

	present, available, err := tableColumns(db, "meta")
	if err != nil {
		return fmt.Errorf("inspect meta schema: %w", err)
	}
	if present && available["key"] && available["value"] {
		rows, queryErr := db.Query("SELECT key,value FROM meta WHERE key IN ('master_key_check','evidence_signing_private_key_enc')")
		if queryErr != nil {
			return fmt.Errorf("read encrypted meta values: %w", queryErr)
		}
		if err := verifyEncryptedRows(rows, box, "meta.value"); err != nil {
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

// verifyEncryptedRows authenticates (row key, envelope) rows against the
// binding "<location>:<row key>". Legacy v1 envelopes carry no binding and are
// checked against the key alone.
func verifyEncryptedRows(rows *sql.Rows, box *secret.Box, location string) error {
	defer rows.Close()
	for rows.Next() {
		var rowKey string
		var encrypted sql.NullString
		if err := rows.Scan(&rowKey, &encrypted); err != nil {
			return err
		}
		if strings.TrimSpace(encrypted.String) == "" {
			continue
		}
		if _, err := box.Open(location+":"+rowKey, encrypted.String); err != nil {
			return errors.New("master key does not match this database")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

// migration upgrades a database from one schema version to the next. Each
// step records its target version itself, in the same transaction as its
// final change, so an interrupted upgrade resumes at the first step that did
// not commit.
type migration struct {
	from, to int
	apply    func(db *sql.DB, box *secret.Box) error
}

// migrations is the versioned on-disk upgrade path, in order.
var migrations = []migration{
	{from: 1, to: 2, apply: migrateSchemaV1ToV2},
	{from: 2, to: 3, apply: withoutKey(migrateSchemaV2ToV3)},
	{from: 3, to: 4, apply: withoutKey(migrateSchemaV3ToV4)},
	{from: 4, to: 5, apply: withoutKey(migrateSchemaV4ToV5)},
	{from: 5, to: 6, apply: withoutKey(migrateSchemaV5ToV6)},
	{from: 6, to: 7, apply: withoutKey(migrateSchemaV6ToV7)},
	{from: 7, to: 8, apply: withoutKey(migrateSchemaV7ToV8)},
	{from: 8, to: 9, apply: withoutKey(migrateSchemaV8ToV9)},
	{from: 9, to: 10, apply: withoutKey(migrateSchemaV9ToV10)},
	{from: 10, to: 11, apply: withoutKey(migrateSchemaV10ToV11)},
	{from: 11, to: 12, apply: withoutKey(migrateSchemaV11ToV12)},
	{from: 12, to: 13, apply: withoutKey(migrateSchemaV12ToV13)},
	{from: 13, to: 14, apply: withoutKey(migrateSchemaV13ToV14)},
	{from: 14, to: 15, apply: withoutKey(migrateSchemaV14ToV15)},
	{from: 15, to: 16, apply: withoutKey(migrateSchemaV15ToV16)},
}

// withoutKey adapts a migration step that needs no master key.
func withoutKey(apply func(*sql.DB) error) func(*sql.DB, *secret.Box) error {
	return func(db *sql.DB, _ *secret.Box) error { return apply(db) }
}

// migrateSchema owns the versioned on-disk upgrade path. Keeping migrations
// separate from runtime settings, reconciliation, and history queries makes
// schema changes easier to review without changing their transactional
// behavior. It applies the step for the stored version until the database
// reaches currentSchemaVersion, re-reading the version after every step.
func migrateSchema(db *sql.DB, box *secret.Box) error {
	for {
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
		step, ok := migrationFrom(version)
		if !ok {
			return fmt.Errorf("database schema version %d requires a newer migration path", version)
		}
		if err := step.apply(db, box); err != nil {
			return err
		}
	}
}

// migrationFrom returns the step that upgrades version.
func migrationFrom(version int) (migration, bool) {
	for _, step := range migrations {
		if step.from == version {
			return step, true
		}
	}
	return migration{}, false
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

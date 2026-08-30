package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// ErrDatabaseNotFound indicates that a read-only inspection target does not
// exist. Callers can report this as an uninitialized installation without
// creating a database as a side effect of diagnosis.
var ErrDatabaseNotFound = errors.New("database not found")

// ReadOnlyInspection contains schema and storage metadata collected without
// changing the database. It intentionally contains no settings, payloads, or
// credentials.
type ReadOnlyInspection struct {
	SchemaVersion           int
	SchemaVersionPresent    bool
	SchemaMigrationPending  bool
	ConfiguredStorageLimits StorageLimits
	PersistedStorageLimits  StorageLimits
	PersistedStorageFound   bool
	EffectiveStorageLimits  StorageLimits
}

// ReadOnlyStore exposes only the queries used by deployment diagnostics. A
// wrapper is used instead of returning Store directly so future diagnostic
// callers cannot accidentally invoke a mutating Store method.
type ReadOnlyStore struct {
	store *Store
}

// OpenReadOnly opens an existing SQLite database without creating directories,
// applying PRAGMAs that write state, running DDL, or running migrations. The
// optional storage profile follows the same zero-means-default convention as
// OpenWithLimits and represents the profile that serve would apply.
func OpenReadOnly(path string, box *secret.Box, configured ...StorageLimits) (*ReadOnlyStore, ReadOnlyInspection, error) {
	var inspection ReadOnlyInspection
	if strings.TrimSpace(path) == "" {
		return nil, inspection, errors.New("database path is required")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, inspection, fmt.Errorf("%w: %s", ErrDatabaseNotFound, path)
		}
		return nil, inspection, fmt.Errorf("inspect database path: %w", err)
	}
	if box == nil {
		return nil, inspection, errors.New("master key is required")
	}
	if len(configured) > 1 {
		return nil, inspection, errors.New("only one configured storage profile is allowed")
	}
	configuredLimits := StorageLimits{}
	if len(configured) == 1 {
		configuredLimits = configured[0]
	}
	normalizedConfigured, err := normalizeStorageLimits(configuredLimits)
	if err != nil {
		return nil, inspection, fmt.Errorf("storage limits: %w", err)
	}
	inspection.ConfiguredStorageLimits = normalizedConfigured

	// mode=ro prevents SQLite from creating a new file. query_only provides an
	// additional connection-level guard if a diagnostic query is accidentally
	// changed to an Exec in the future. journal_mode is deliberately absent:
	// unlike the serving path, inspection must not configure or checkpoint WAL.
	dsn := "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=query_only(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, inspection, fmt.Errorf("open read-only database: %w", err)
	}
	db.SetMaxOpenConns(1)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = db.Close()
		}
	}()
	if err := db.PingContext(context.Background()); err != nil {
		return nil, inspection, fmt.Errorf("ping read-only database: %w", err)
	}
	present, err := verifyExistingMasterKey(db, box)
	if err != nil {
		return nil, inspection, err
	}
	if !present {
		if err := verifyLegacyMasterKey(db, box); err != nil {
			return nil, inspection, err
		}
	}
	if err := verifyDatabaseVersionPreflight(db); err != nil {
		return nil, inspection, err
	}
	version, present, err := readDatabaseSchemaVersion(db)
	if err != nil {
		return nil, inspection, err
	}
	inspection.SchemaVersion = version
	inspection.SchemaVersionPresent = present
	inspection.SchemaMigrationPending = present && version < currentSchemaVersion
	persisted, found, err := loadPersistedStorageLimits(db)
	if err != nil {
		return nil, inspection, err
	}
	inspection.PersistedStorageLimits = persisted
	inspection.PersistedStorageFound = found
	inspection.EffectiveStorageLimits = normalizedConfigured
	if configuredLimits == (StorageLimits{}) && found {
		inspection.EffectiveStorageLimits = persisted
	}
	st := &Store{db: db, box: box}
	st.limits.Store(inspection.EffectiveStorageLimits)
	closeOnError = false
	return &ReadOnlyStore{store: st}, inspection, nil
}

// NormalizeStorageLimits applies the same defaults and cross-field checks used
// by the serving path without opening a database.
func NormalizeStorageLimits(limits StorageLimits) (StorageLimits, error) {
	return normalizeStorageLimits(limits)
}

// Status returns the current status using read-only queries.
func (s *ReadOnlyStore) Status(ctx context.Context) (Status, error) {
	if s == nil || s.store == nil {
		return Status{}, errors.New("read-only store is unavailable")
	}
	return s.store.Status(ctx)
}

// StorageMetrics returns the current storage metrics using read-only queries.
func (s *ReadOnlyStore) StorageMetrics(ctx context.Context) (StorageMetrics, error) {
	if s == nil || s.store == nil {
		return StorageMetrics{}, errors.New("read-only store is unavailable")
	}
	return s.store.StorageMetrics(ctx)
}

// Close releases the read-only database connection.
func (s *ReadOnlyStore) Close() error {
	if s == nil || s.store == nil || s.store.db == nil {
		return nil
	}
	return s.store.db.Close()
}

func readDatabaseSchemaVersion(db *sql.DB) (version int, present bool, err error) {
	var tableCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'").Scan(&tableCount); err != nil {
		return 0, false, fmt.Errorf("inspect database schema marker: %w", err)
	}
	if tableCount == 0 {
		return 0, false, nil
	}
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		return 0, true, fmt.Errorf("read database schema version: %w", err)
	}
	return version, true, nil
}

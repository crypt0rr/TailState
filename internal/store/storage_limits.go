package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// StorageLimits bounds the amount of normalized provider data retained and
// read for one history page. The limits apply after model normalization and
// therefore do not change the semantic drift comparison or notification text.
// RejectBytes is an optional hard ceiling for a raw value: when it is crossed
// TailState rejects the unbounded write but still stores a small truncation
// marker so the content hash and observed size remain auditable.
type StorageLimits struct {
	SnapshotBytes    int64
	EventValueBytes  int64
	HistoryPageBytes int64
	RejectBytes      int64
	DatabaseBytes    int64
}

const storageLimitsMeta = "storage_limits"

const (
	defaultSnapshotBytes    int64 = 1 << 20
	defaultEventValueBytes  int64 = 512 << 10
	defaultHistoryPageBytes int64 = 2 << 20
	defaultRejectBytes      int64 = 4 << 20
	defaultDatabaseBytes    int64 = 512 << 20
)

// DefaultStorageLimits returns the production storage guardrails.
func DefaultStorageLimits() StorageLimits {
	return StorageLimits{
		SnapshotBytes:    defaultSnapshotBytes,
		EventValueBytes:  defaultEventValueBytes,
		HistoryPageBytes: defaultHistoryPageBytes,
		RejectBytes:      defaultRejectBytes,
		DatabaseBytes:    defaultDatabaseBytes,
	}
}

func loadPersistedStorageLimits(db *sql.DB) (StorageLimits, bool, error) {
	if db == nil {
		return StorageLimits{}, false, errors.New("database is unavailable")
	}
	var present int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'").Scan(&present); err != nil {
		return StorageLimits{}, false, fmt.Errorf("inspect persisted storage limits: %w", err)
	}
	if present == 0 {
		return StorageLimits{}, false, nil
	}
	var encoded string
	err := db.QueryRow("SELECT value FROM meta WHERE key=?", storageLimitsMeta).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return StorageLimits{}, false, nil
	}
	if err != nil {
		return StorageLimits{}, false, fmt.Errorf("read persisted storage limits: %w", err)
	}
	var limits StorageLimits
	if err := json.Unmarshal([]byte(encoded), &limits); err != nil {
		return StorageLimits{}, false, fmt.Errorf("decode persisted storage limits: %w", err)
	}
	normalized, err := normalizeStorageLimits(limits)
	if err != nil {
		return StorageLimits{}, false, fmt.Errorf("persisted storage limits: %w", err)
	}
	return normalized, true, nil
}

func persistStorageLimits(ctx context.Context, db *sql.DB, limits StorageLimits) error {
	encoded, err := json.Marshal(limits)
	if err != nil {
		return fmt.Errorf("encode storage limits: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, storageLimitsMeta, string(encoded)); err != nil {
		return fmt.Errorf("persist storage limits: %w", err)
	}
	return nil
}

func normalizeStorageLimits(limits StorageLimits) (StorageLimits, error) {
	defaults := DefaultStorageLimits()
	if limits.SnapshotBytes == 0 {
		limits.SnapshotBytes = defaults.SnapshotBytes
	}
	if limits.EventValueBytes == 0 {
		limits.EventValueBytes = defaults.EventValueBytes
	}
	if limits.HistoryPageBytes == 0 {
		limits.HistoryPageBytes = defaults.HistoryPageBytes
	}
	if limits.RejectBytes == 0 {
		limits.RejectBytes = defaults.RejectBytes
	}
	if limits.DatabaseBytes == 0 {
		limits.DatabaseBytes = defaults.DatabaseBytes
	}
	if limits.SnapshotBytes < 1024 || limits.EventValueBytes < 1024 || limits.HistoryPageBytes < 4096 || limits.RejectBytes < 0 || limits.DatabaseBytes < 1 {
		return StorageLimits{}, errors.New("storage limits are too small or invalid")
	}
	if limits.RejectBytes > 0 && limits.RejectBytes < limits.SnapshotBytes {
		return StorageLimits{}, errors.New("storage reject limit must be at least the snapshot limit")
	}
	return limits, nil
}

// truncationMarker is deliberately provider-independent. It contains no
// preview of the provider body, only material needed to explain what was
// retained and to verify the full normalized hash from an external source.
type truncationMarker struct {
	TailState struct {
		Truncated bool   `json:"truncated"`
		SHA256    string `json:"sha256"`
		Bytes     int64  `json:"bytes"`
		Limit     int64  `json:"limit"`
		Reason    string `json:"reason"`
	} `json:"_tailstate"`
}

type storedValue struct {
	raw       []byte
	hash      string
	bytes     int64
	truncated bool
	rejected  bool
	reason    string
}

func boundedValue(raw []byte, hash string, limit, reject int64) storedValue {
	value := storedValue{raw: append([]byte(nil), raw...), hash: hash, bytes: int64(len(raw))}
	if len(raw) == 0 || int64(len(raw)) <= limit {
		return value
	}
	value.truncated = true
	value.reason = "byte limit"
	if reject > 0 && int64(len(raw)) > reject {
		value.rejected = true
		value.reason = "hard write limit"
	}
	value.raw = truncationJSON(hash, int64(len(raw)), limit, value.reason)
	return value
}

func existingStoredValue(raw []byte, hash string, bytes int64, truncated bool) storedValue {
	if bytes <= 0 && len(raw) > 0 {
		bytes = int64(len(raw))
	}
	return storedValue{raw: append([]byte(nil), raw...), hash: hash, bytes: bytes, truncated: truncated}
}

func truncationJSON(hash string, bytes, limit int64, reason string) []byte {
	marker := truncationMarker{}
	marker.TailState.Truncated = true
	marker.TailState.SHA256 = hash
	marker.TailState.Bytes = bytes
	marker.TailState.Limit = limit
	marker.TailState.Reason = reason
	encoded, _ := json.Marshal(marker)
	return encoded
}

func parseTruncationMarker(raw []byte) (truncationMarker, bool) {
	var marker truncationMarker
	if len(raw) == 0 || json.Unmarshal(raw, &marker) != nil || !marker.TailState.Truncated {
		return truncationMarker{}, false
	}
	return marker, true
}

func valueHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type storageCounters struct {
	snapshotTruncations   atomic.Uint64
	eventTruncations      atomic.Uint64
	historyTruncations    atomic.Uint64
	oversizedWriteRejects atomic.Uint64
}

// StorageMetrics is the bounded, low-cardinality storage signal exposed to
// diagnostics and Prometheus. DatabaseBytes is the logical SQLite allocation
// (page_count × page_size), including free pages left by deletes.
// DatabaseUsedBytes excludes those free pages ((page_count − freelist_count)
// × page_size); it is the figure compared with the budget, because SQLite
// reuses free pages before it grows the file. The DatabaseFileBytes, DatabaseWALBytes,
// DatabaseSHMBytes, and DatabasePhysicalBytes fields are physical filesystem
// observations and are not enforcement values. It intentionally omits
// provider payloads and destination URLs.
type StorageMetrics struct {
	SnapshotTruncations     uint64
	EventValueTruncations   uint64
	HistoryPageTruncations  uint64
	OversizedWritesRejected uint64
	DatabaseBytes           int64
	DatabaseUsedBytes       int64
	DatabaseFreelistPages   int64
	DatabaseFreeBytes       int64
	DatabaseLimitBytes      int64
	// DatabaseEnforcedLimitBytes is the page ceiling SQLite is enforcing on the
	// connection that served this snapshot (max_page_count * page_size).
	DatabaseEnforcedLimitBytes int64
	DatabasePageSizeBytes      int64
	DatabaseFileBytes          int64
	DatabaseWALBytes           int64
	DatabaseSHMBytes           int64
	DatabasePhysicalBytes      int64
}

// ErrStorageBudgetExceeded indicates that SQLite rejected a write because the
// configured logical database page budget has been reached.
var ErrStorageBudgetExceeded = errors.New("database storage budget exceeded")

func (s *Store) StorageLimits() StorageLimits {
	if s == nil {
		return DefaultStorageLimits()
	}
	if value := s.limits.Load(); value != nil {
		return value.(StorageLimits)
	}
	return DefaultStorageLimits()
}

// SetStorageLimits is primarily useful for operators choosing a deployment
// profile and for low-budget integration tests. Existing rows are not
// rewritten; new writes and reads use the new limits.
func (s *Store) SetStorageLimits(limits StorageLimits) error {
	previous := s.StorageLimits()
	normalized, err := normalizeStorageLimits(limits)
	if err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return errors.New("storage limits unavailable")
	}
	if err := configureDatabasePageLimit(s.db, s.connector, normalized.DatabaseBytes); err != nil {
		_ = configureDatabasePageLimit(s.db, s.connector, previous.DatabaseBytes)
		return err
	}
	if err := persistStorageLimits(context.Background(), s.db, normalized); err != nil {
		_ = configureDatabasePageLimit(s.db, s.connector, previous.DatabaseBytes)
		return err
	}
	s.limits.Store(normalized)
	return nil
}

// configureDatabasePageLimit applies the byte budget as a SQLite page ceiling
// on the current pooled connection and records it on the connector, so every
// later connection receives the same ceiling. A nil connector is accepted for
// read-only callers that never reconnect for writes.
//
// The startup check compares the budget with used pages (page_count minus
// freelist_count): free pages left by retention are reused before the file
// grows, so a database whose live data fits is accepted even when its file
// is still larger. SQLite cannot lower max_page_count below page_count, so
// until the free pages are released with `tailstate admin compact` the
// effective ceiling is the current file size, which StorageMetrics and the
// storage_limit_enforced metric report.
func configureDatabasePageLimit(db *sql.DB, connector *pageLimitedConnector, limit int64) error {
	if db == nil || limit < 1 {
		return errors.New("database storage limit is invalid")
	}
	var pageSize int64
	if err := db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return fmt.Errorf("read database page size: %w", err)
	}
	if pageSize < 1 {
		return errors.New("database page size is invalid")
	}
	// SQLite limits whole pages. Use the largest page count that cannot exceed
	// the configured byte ceiling; a sub-page budget necessarily rounds up to
	// one page because SQLite cannot allocate a fraction of a page.
	maxPages := limit / pageSize
	if maxPages < 1 {
		maxPages = 1
	}
	var pageCount, freePages int64
	if err := db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
		return fmt.Errorf("read database page count: %w", err)
	}
	if err := db.QueryRow("PRAGMA freelist_count").Scan(&freePages); err != nil {
		return fmt.Errorf("read database free page count: %w", err)
	}
	if used := pageCount - freePages; used > maxPages {
		return fmt.Errorf("database uses %d bytes, above configured limit %d", used*pageSize, limit)
	}
	if connector != nil {
		// Record the ceiling before applying it so a connection opened
		// concurrently with this call cannot miss it.
		connector.maxPages.Store(maxPages)
	}
	var appliedPages int64
	if err := db.QueryRow("PRAGMA max_page_count = " + strconv.FormatInt(maxPages, 10)).Scan(&appliedPages); err != nil {
		return fmt.Errorf("set database page limit: %w", err)
	}
	if connector != nil {
		connector.enforcedPages.Store(appliedPages)
	}
	if appliedPages > maxPages {
		slog.Warn("database file holds free pages beyond the configured limit; the limit is enforced at the current file size until the database is compacted with `tailstate admin compact` while TailState is stopped",
			"configured_limit_bytes", limit, "file_pages", pageCount, "free_pages", freePages, "page_size", pageSize)
	}
	return nil
}

func storageWriteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrStorageBudgetExceeded) {
		return err
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "database or disk is full") || strings.Contains(lower, "database full") || strings.Contains(lower, "sqlite_full") {
		return fmt.Errorf("%w: %v", ErrStorageBudgetExceeded, err)
	}
	return err
}

// StorageMetrics returns a safe snapshot of storage pressure and guardrail
// counters for diagnostics, metrics, and tests. It reads through the
// read-only pool, so a scrape never waits behind a write transaction.
func (s *Store) StorageMetrics(ctx context.Context) (StorageMetrics, error) {
	if s == nil || s.db == nil {
		return StorageMetrics{}, errors.New("storage metrics unavailable")
	}
	limits := s.StorageLimits()
	db := s.readDB()
	var pageCount, pageSize, freePages int64
	if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return StorageMetrics{}, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return StorageMetrics{}, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		return StorageMetrics{}, err
	}
	var maxPages int64
	if s.connector != nil && s.connector.enforcedPages.Load() > 0 {
		maxPages = s.connector.enforcedPages.Load()
	} else if err := s.db.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&maxPages); err != nil {
		return StorageMetrics{}, err
	}
	physical, err := s.physicalStorageMetrics(ctx)
	if err != nil {
		return StorageMetrics{}, err
	}
	return StorageMetrics{
		SnapshotTruncations:        s.counters.snapshotTruncations.Load(),
		EventValueTruncations:      s.counters.eventTruncations.Load(),
		HistoryPageTruncations:     s.counters.historyTruncations.Load(),
		OversizedWritesRejected:    s.counters.oversizedWriteRejects.Load(),
		DatabaseBytes:              pageCount * pageSize,
		DatabaseUsedBytes:          (pageCount - freePages) * pageSize,
		DatabaseFreelistPages:      freePages,
		DatabaseFreeBytes:          freePages * pageSize,
		DatabaseLimitBytes:         limits.DatabaseBytes,
		DatabaseEnforcedLimitBytes: maxPages * pageSize,
		DatabasePageSizeBytes:      pageSize,
		DatabaseFileBytes:          physical.main,
		DatabaseWALBytes:           physical.wal,
		DatabaseSHMBytes:           physical.shm,
		DatabasePhysicalBytes:      physical.total,
	}, nil
}

type physicalStorageMetrics struct {
	main, wal, shm, total int64
}

func (s *Store) physicalStorageMetrics(ctx context.Context) (physicalStorageMetrics, error) {
	if err := ctx.Err(); err != nil {
		return physicalStorageMetrics{}, err
	}
	path := s.databasePath
	if path == "" {
		var sequence int64
		var name, databaseFile string
		if err := s.db.QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &name, &databaseFile); err != nil {
			return physicalStorageMetrics{}, fmt.Errorf("read database path: %w", err)
		}
		path = databaseFile
	}
	if path == "" || path == ":memory:" {
		return physicalStorageMetrics{}, nil
	}
	main, err := physicalFileBytes(path)
	if err != nil {
		return physicalStorageMetrics{}, fmt.Errorf("read database file size: %w", err)
	}
	wal, err := physicalFileBytes(path + "-wal")
	if err != nil {
		return physicalStorageMetrics{}, fmt.Errorf("read database WAL file size: %w", err)
	}
	shm, err := physicalFileBytes(path + "-shm")
	if err != nil {
		return physicalStorageMetrics{}, fmt.Errorf("read database SHM file size: %w", err)
	}
	return physicalStorageMetrics{main: main, wal: wal, shm: shm, total: main + wal + shm}, nil
}

func physicalFileBytes(path string) (int64, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", path)
	}
	return info.Size(), nil
}

// LimitEnforced reports whether SQLite is enforcing a page ceiling no larger
// than the configured byte budget. A budget smaller than one page necessarily
// rounds up to a single page. A false result means writes could grow past the
// configured limit.
func (m StorageMetrics) LimitEnforced() bool {
	if m.DatabaseLimitBytes <= 0 || m.DatabaseEnforcedLimitBytes <= 0 {
		return false
	}
	return m.DatabaseEnforcedLimitBytes <= max(m.DatabaseLimitBytes, m.DatabasePageSizeBytes)
}

// PressureRatio is used bytes (excluding free pages) divided by the budget,
// so it falls as soon as retention frees rows. A value built without
// free-page information (DatabaseUsedBytes and DatabaseFreelistPages both
// zero) falls back to the allocated DatabaseBytes.
func (m StorageMetrics) PressureRatio() float64 {
	if m.DatabaseLimitBytes <= 0 {
		return 0
	}
	used := m.DatabaseUsedBytes
	if used == 0 && m.DatabaseFreelistPages == 0 {
		used = m.DatabaseBytes
	}
	return float64(used) / float64(m.DatabaseLimitBytes)
}

func logStorageTruncation(collector, resourceID, hash string, observed, limit int64, reason string) {
	slog.Warn("normalized snapshot value truncated", "collector", collector, "resource_id", resourceID, "content_hash", hash, "observed_bytes", observed, "configured_limit_bytes", limit, "reason", reason)
}

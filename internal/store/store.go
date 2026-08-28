package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

type Store struct {
	db          *sql.DB
	box         *secret.Box
	evidenceKey evidenceSigningKey
	limits      atomic.Value // stores StorageLimits
	counters    storageCounters
}

type Settings struct {
	Tailnet            string
	OAuthClientID      string
	OAuthClientSecret  string
	WebhookSecret      string
	ClearWebhookSecret bool
	// MattermostURL is retained for source compatibility with older callers.
	// New configuration is stored through NotificationDestination APIs.
	MattermostURL     string
	DeviceInterval    time.Duration
	InventoryInterval time.Duration
	Generation        int64
	// Revision is a non-secret settings change marker. It changes whenever
	// SaveSettings writes the row, including credential and polling updates
	// that intentionally preserve Generation and its snapshots.
	Revision     string
	ConfiguredAt time.Time
	BaselineAt   *time.Time
}

type CollectorState struct {
	Name              string     `json:"name"`
	Supported         bool       `json:"supported"`
	Baseline          bool       `json:"baseline"`
	Partial           bool       `json:"partial"`
	PartialErrorCount int        `json:"partial_error_count"`
	PollDurationMS    int64      `json:"poll_duration_ms"`
	LastSuccess       *time.Time `json:"last_success,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	FailureCount      int        `json:"failure_count"`
	NextPoll          *time.Time `json:"next_poll,omitempty"`
}

type Status struct {
	Configured          bool
	BaselineAt          *time.Time
	BaselineReady       bool
	BaselineDegraded    bool
	BaselineReason      string
	BaselineGraceUntil  *time.Time
	ResourceCounts      map[string]int
	Collectors          []CollectorState
	Pending             int
	Processing          int
	Dead                int
	Destinations        int
	EnabledDestinations int
	WebhookPending      int
	WebhookProcessing   int
	WebhookDead         int
}

type OutboxItem struct {
	ID            int64
	BatchID       int64
	DestinationID int64
	Destination   NotificationDestination
	Payload       string
	Attempts      int
	FirstAttempt  time.Time
	LeaseUntil    *time.Time
	LeaseToken    string
}

type ChangeBatch struct {
	ID          int64
	Generation  int64
	ObservedAt  time.Time
	ChangeCount int
	TriggerID   int64
	TriggerIDs  []int64
}

// WebhookTrigger records verified provider metadata without retaining the
// signed request body or its potentially sensitive data payload.
type WebhookTrigger struct {
	ID          int64
	BodyHash    string
	ReceivedAt  time.Time
	EventTypes  []string
	Collectors  []string
	Status      string
	Attempts    int
	NextAttempt time.Time
	LeaseUntil  *time.Time
	LeaseToken  string
	LastError   string
	ProcessedAt *time.Time
}

type ChangeBatchResult struct {
	ChangeBatch
	Changes []model.Change
}

type HistoryFieldChange struct {
	Field  string
	Old    string
	New    string
	HasOld bool
	HasNew bool
}

type HistoryEvent struct {
	ID              int64
	BatchID         int64
	Generation      int64
	ObservedAt      time.Time
	Collector       string
	EventType       string
	ResourceID      string
	Name            string
	Fields          []HistoryFieldChange
	FieldsTruncated bool
	TotalFields     int
	BeforeJSON      string
	AfterJSON       string
	BeforeHash      string
	AfterHash       string
	BeforeBytes     int64
	AfterBytes      int64
	BeforeTruncated bool
	AfterTruncated  bool
}

type HistoryDelivery struct {
	ID            int64
	DestinationID int64
	Destination   string
	Status        string
	Attempts      int
	LastError     string
	NextAttempt   *time.Time
	DeliveredAt   *time.Time
}

type HistoryBatch struct {
	ChangeBatch
	Events          []HistoryEvent
	Deliveries      []HistoryDelivery
	LedgerSequence  int64
	LedgerPrevHash  string
	LedgerHash      string
	LedgerSignature string
	LedgerKeyID     string
	ledgerPayload   []byte
}

type HistoryFilter struct {
	Collector  string
	EventType  string
	ResourceID string
	Cursor     int64
	Limit      int
}

type HistoryPage struct {
	Batches          []HistoryBatch
	NextCursor       int64
	HasNext          bool
	Truncated        bool
	BytesRead        int64
	ByteLimit        int64
	TruncationReason string
}

const currentSchemaVersion = 12

const (
	webhookTriggerRetryWindow = 24 * time.Hour
	webhookTriggerLease       = 2 * time.Minute
	webhookTriggerBatchSize   = 8
	setupTokenLifetime        = 30 * time.Minute
	resetTokenLifetime        = 30 * time.Minute
	outboxRetryWindow         = 24 * time.Hour
	outboxLease               = 2 * time.Minute
	baselineGracePeriod       = 15 * time.Minute
)

func Open(path string, box *secret.Box) (*Store, error) {
	return OpenWithLimits(path, box, StorageLimits{})
}

// OpenWithLimits opens a store and applies the operator-selected storage
// profile before bootstrap DDL or migrations can grow the database. The
// logical SQLite page ceiling is persisted by SQLite and is also reapplied on
// every restart, so a configured budget cannot silently become advisory.
func OpenWithLimits(path string, box *secret.Box, configuredLimits StorageLimits) (*Store, error) {
	if box == nil {
		return nil, errors.New("master key is required")
	}
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	limits := configuredLimits
	if limits == (StorageLimits{}) {
		if persisted, found, loadErr := loadPersistedStorageLimits(db); loadErr != nil {
			db.Close()
			return nil, loadErr
		} else if found {
			limits = persisted
		}
	}
	limits, err = normalizeStorageLimits(limits)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage limits: %w", err)
	}
	if err := configureDatabasePageLimit(db, limits.DatabaseBytes); err != nil {
		db.Close()
		return nil, fmt.Errorf("database storage limit setup failed: %w", err)
	}
	present, err := verifyExistingMasterKey(db, box)
	if err != nil {
		db.Close()
		return nil, err
	}
	// Version-one databases predate meta.master_key_check. Validate one of
	// their authenticated encrypted settings before executing the bootstrap
	// DDL, otherwise a wrong key could still create current-schema tables
	// before the legacy migration reports its decrypt failure.
	if !present {
		if err := verifyLegacyMasterKey(db, box); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := verifyDatabaseVersionPreflight(db); err != nil {
		db.Close()
		return nil, err
	}
	// Migrations are transactional per version, but a later step can still
	// leave an older step committed before startup stops. Warn before any DDL
	// so operators have an actionable recovery point in the normal startup
	// logs, and keep the database/key pair available for a verified restore.
	var existingVersion int
	if err := db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&existingVersion); err == nil && existingVersion < currentSchemaVersion {
		slog.Warn("database schema migration pending; stop TailState and create a verified backup before retrying", "from_version", existingVersion, "to_version", currentSchemaVersion, "database", path)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("database schema setup failed; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if err := migrateSchema(db, box); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	// The due index depends on columns introduced by the v4-to-v5 migration.
	// Keep it out of the bootstrap DDL so historical v4 databases can reach
	// that migration before the index is created.
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS webhook_triggers_due ON webhook_triggers(status, next_attempt_at, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating webhook trigger index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS events_batch_id ON events(batch_id, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating event history index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS outbox_batch_id ON outbox(batch_id, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating outbox history index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	st := &Store{db: db, box: box}
	st.limits.Store(limits)
	present, err = verifyExistingMasterKey(db, box)
	if err != nil {
		db.Close()
		return nil, err
	}
	if !present {
		encrypted, encryptErr := box.Encrypt("tailstate-master-key-check")
		if encryptErr != nil {
			db.Close()
			return nil, encryptErr
		}
		if _, err = db.Exec("INSERT INTO meta(key,value) VALUES('master_key_check',?)", encrypted); err != nil {
			db.Close()
			return nil, err
		}
	}
	st.evidenceKey, err = loadOrCreateEvidenceSigningKey(context.Background(), db, box)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("load evidence signing key: %w", err)
	}
	if err := st.backfillEvidenceLedgerOnStartup(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("backfill evidence ledger: %w", err)
	}
	if err := persistStorageLimits(context.Background(), db, limits); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

func verifyExistingMasterKey(db *sql.DB, box *secret.Box) (bool, error) {
	var keyCheck string
	err := db.QueryRow("SELECT value FROM meta WHERE key='master_key_check'").Scan(&keyCheck)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	plain, decryptErr := box.Decrypt(keyCheck)
	if decryptErr != nil || plain != "tailstate-master-key-check" {
		return true, errors.New("master key does not match this TailState database")
	}
	return true, nil
}

func filepathDir(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "."
	}
	return path[:i]
}
func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

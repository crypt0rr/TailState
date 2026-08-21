package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

type Store struct {
	db          *sql.DB
	box         *secret.Box
	evidenceKey evidenceSigningKey
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
	Batches    []HistoryBatch
	NextCursor int64
	HasNext    bool
}

const currentSchemaVersion = 9

const (
	webhookTriggerRetryWindow = 24 * time.Hour
	webhookTriggerLease       = 2 * time.Minute
	webhookTriggerBatchSize   = 8
	setupTokenLifetime        = 30 * time.Minute
	resetTokenLifetime        = 30 * time.Minute
	outboxRetryWindow         = 24 * time.Hour
	baselineGracePeriod       = 15 * time.Minute
)

func Open(path string, box *secret.Box) (*Store, error) {
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
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
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	if err := migrateSchema(db, box); err != nil {
		db.Close()
		return nil, err
	}
	// The due index depends on columns introduced by the v4-to-v5 migration.
	// Keep it out of the bootstrap DDL so historical v4 databases can reach
	// that migration before the index is created.
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS webhook_triggers_due ON webhook_triggers(status, next_attempt_at, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("create webhook trigger due index: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS events_batch_id ON events(batch_id, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("create event history index: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS outbox_batch_id ON outbox(batch_id, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("create outbox batch index: %w", err)
	}
	st := &Store{db: db, box: box}
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

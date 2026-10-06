package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

type Store struct {
	db *sql.DB
	// reader is a small query_only pool for health, readiness, metrics, and
	// History reads. SQLite WAL readers never wait for the writer, so these
	// paths stay responsive while db (one connection) holds a long write
	// transaction. nil for stores opened by the administrative helpers.
	reader       *sql.DB
	connector    *pageLimitedConnector
	databasePath string
	box          *secret.Box
	evidenceKey  evidenceSigningKey
	limits       atomic.Value // stores StorageLimits
	counters     storageCounters
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
	// ExpiryWarningDays lists the windows, in days before expiry, at which a
	// node key or auth key expiry warning is sent. nil selects the defaults
	// (14 and 3 days); an empty non-nil slice disables expiry warnings.
	ExpiryWarningDays []int
	// ExpiryTagFilter limits expiry warnings to resources carrying at least
	// one of these tags. An empty filter includes every resource.
	ExpiryTagFilter []string
	// OAuthScopes lists the read scopes requested for the Tailscale access
	// token. nil or empty selects all:read.
	OAuthScopes []string
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
	// Attribution is the configuration audit log state for the current
	// generation; its zero value means it has not been checked yet.
	Attribution AttributionSource
}

type OutboxItem struct {
	ID            int64
	BatchID       int64
	DestinationID int64
	Destination   NotificationDestination
	Payload       string
	// PayloadFormat is notify.PayloadMarkdown for pre-rendered Markdown
	// (every row written before schema v14) or notify.PayloadMessage for a
	// format-neutral message rendered at send time.
	PayloadFormat string
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
	// AttributionStatus is the configuration audit lookup outcome for the
	// batch (empty when no lookup ran) and Attributed the number of changes
	// it explained.
	AttributionStatus string
	Attributed        int
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
	Severity        string
	Muted           bool
	// Attribution is the configuration audit record that explains the
	// change, if any; ChangedBy is its display text, "actor unknown" when
	// the batch lookup ran without a match, or "" when nothing is shown.
	Attribution *model.Attribution
	ChangedBy   string
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
	// AttributionStatus is the batch's configuration audit lookup outcome
	// (AttributionComplete, AttributionUnavailable, AttributionUnsupported,
	// or empty for batches recorded without a lookup).
	AttributionStatus string
	Events            []HistoryEvent
	Deliveries        []HistoryDelivery
	LedgerSequence    int64
	LedgerPrevHash    string
	LedgerHash        string
	LedgerSignature   string
	LedgerKeyID       string
	ledgerPayload     []byte
}

type HistoryFilter struct {
	Collector  string
	EventType  string
	ResourceID string
	// From and Until bound a batch's observation time: From is inclusive and
	// Until exclusive. Both are compared at whole-second UTC precision; a
	// zero value leaves that side open.
	From  time.Time
	Until time.Time
	// Cursor pages towards older batches (ID below Cursor). After pages
	// towards newer batches (ID above After) and is ignored when Cursor is
	// set. Results are always returned newest first.
	Cursor int64
	After  int64
	Limit  int
	// BatchID selects exactly one batch, for notification deep links.
	BatchID int64
	// Severity selects events with exactly this built-in severity.
	Severity string
}

type HistoryPage struct {
	Batches    []HistoryBatch
	NextCursor int64
	HasNext    bool
	// PrevCursor and HasPrev describe the adjacent page of newer batches:
	// request it with HistoryFilter.After set to PrevCursor.
	PrevCursor       int64
	HasPrev          bool
	Truncated        bool
	BytesRead        int64
	ByteLimit        int64
	TruncationReason string
}

const currentSchemaVersion = 16

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
// logical SQLite page ceiling is a per-connection setting, so the connector
// reapplies it to every connection the pool opens (including replacements for
// connections discarded after an interrupted statement) and on every restart;
// a configured budget cannot silently become advisory.
func OpenWithLimits(path string, box *secret.Box, configuredLimits StorageLimits) (*Store, error) {
	if box == nil {
		return nil, errors.New("master key is required")
	}
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return nil, err
	}
	if err := ensurePrivateDatabaseFile(path); err != nil {
		return nil, err
	}
	// _txlock=immediate makes every transaction take the write lock when it
	// begins. A deferred transaction that reads and then writes after another
	// process (an admin command, for example) committed fails immediately
	// with SQLITE_BUSY_SNAPSHOT; an immediate one waits for busy_timeout.
	//
	// journal_size_limit caps the WAL file left behind after a checkpoint
	// resets it; without it a burst leaves a WAL as large as the burst on
	// disk indefinitely.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=journal_size_limit(" + strconv.FormatInt(journalSizeLimitBytes, 10) + ")&_txlock=immediate"
	connector := newPageLimitedConnector(dsn)
	db := sql.OpenDB(connector)
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
	limits, err := normalizeStorageLimits(limits)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage limits: %w", err)
	}
	if err := configureDatabasePageLimit(db, connector, limits.DatabaseBytes); err != nil {
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
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS events_retention ON events(observed_at, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating event retention index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS outbox_retry_retention ON outbox(status, first_attempt, lease_until, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating outbox retry index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS outbox_delivered_retention ON outbox(status, delivered_at, created_at, id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating outbox retention index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS outbox_dead_retention ON outbox(status, created_at)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating outbox dead-letter retention index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS auth_tokens_kind ON auth_tokens(kind)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed while creating authentication token kind index; stop TailState and restore the verified pre-upgrade backup before retrying: %w", err)
	}
	st := &Store{db: db, connector: connector, databasePath: path, box: box}
	st.limits.Store(limits)
	present, err = verifyExistingMasterKey(db, box)
	if err != nil {
		db.Close()
		return nil, err
	}
	if !present {
		encrypted, encryptErr := box.Seal(metaBinding(masterKeyCheckMeta), "tailstate-master-key-check")
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
	if err := restrictDatabaseSidecars(path); err != nil {
		db.Close()
		return nil, err
	}
	reader, err := openReaderPool(path)
	if err != nil {
		db.Close()
		return nil, err
	}
	st.reader = reader
	return st, nil
}

// journalSizeLimitBytes is the WAL size SQLite truncates to after a
// checkpoint resets the log (64 MiB). A variable so tests can use a small cap.
var journalSizeLimitBytes int64 = 64 << 20

const readerPoolSize = 4

// openReaderPool opens the read-only pool used by health, readiness, metrics,
// and History reads. It is opened only after OpenWithLimits has created,
// migrated, and switched the database to WAL, so readers always see the
// current schema. mode=ro and query_only make every connection unable to
// write, which is why these connections need neither the page-limited
// connector (a read cannot allocate pages) nor journal_mode (WAL is a
// persistent property of the file). Each statement outside a transaction
// reads the latest committed WAL snapshot, so readers observe every commit
// made through the writer before the statement began.
func openReaderPool(path string) (*sql.DB, error) {
	reader, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return nil, fmt.Errorf("open read-only pool: %w", err)
	}
	reader.SetMaxOpenConns(readerPoolSize)
	reader.SetMaxIdleConns(readerPoolSize)
	if err := reader.Ping(); err != nil {
		reader.Close()
		return nil, fmt.Errorf("open read-only pool: %w", err)
	}
	return reader, nil
}

// readDB returns the read-only pool when the store has one, else the writer.
func (s *Store) readDB() *sql.DB {
	if s.reader != nil {
		return s.reader
	}
	return s.db
}

// OpenExisting opens an existing, current-schema database for a narrow
// administrative write (such as issuing a password reset token) while the
// service may be running. Unlike OpenWithLimits it never creates the file or
// its directory, runs no bootstrap DDL, migrations, or backfills, does not
// generate signing keys, and does not persist storage limits; a missing or
// older-schema database is left untouched and reported as an error.
func OpenExisting(path string, box *secret.Box) (*Store, error) {
	if box == nil {
		return nil, errors.New("master key is required")
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrDatabaseNotFound, path)
		}
		return nil, fmt.Errorf("inspect database path: %w", err)
	}
	// mode=rw refuses to create a missing file. journal_mode is omitted: the
	// serving process already configured WAL, which is persistent.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rw&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	closeWith := func(openErr error) (*Store, error) {
		_ = db.Close()
		return nil, openErr
	}
	if err := db.Ping(); err != nil {
		return closeWith(fmt.Errorf("open database: %w", err))
	}
	present, err := verifyExistingMasterKey(db, box)
	if err != nil {
		return closeWith(err)
	}
	if !present {
		if err := verifyLegacyMasterKey(db, box); err != nil {
			return closeWith(err)
		}
	}
	if err := verifyDatabaseVersionPreflight(db); err != nil {
		return closeWith(err)
	}
	version, versioned, err := readDatabaseSchemaVersion(db)
	if err != nil {
		return closeWith(err)
	}
	if !versioned {
		return closeWith(errors.New("database is not initialized; start TailState once before running this command"))
	}
	if version != currentSchemaVersion {
		return closeWith(fmt.Errorf("database schema version %d is not the current version %d; stop TailState, create a verified backup, and start the current release to migrate before running this command", version, currentSchemaVersion))
	}
	if !present {
		return closeWith(errors.New("database has no master key check; start TailState once before running this command"))
	}
	st := &Store{db: db, databasePath: path, box: box}
	st.limits.Store(DefaultStorageLimits())
	return st, nil
}

// ensurePrivateDatabaseFile creates the database file with owner-only
// permissions before SQLite opens it, and tightens an existing file. SQLite
// creates the -wal and -shm sidecars with the main file's permission bits, so
// this keeps recent history, session hashes and encrypted settings in the WAL
// from being created world-readable on a fresh database.
func ensurePrivateDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// restrictDatabaseSidecars tightens the database and any sidecar left by an
// earlier release or an unclean shutdown, which SQLite reuses as-is.
func restrictDatabaseSidecars(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
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
	plain, decryptErr := box.Open(metaBinding(masterKeyCheckMeta), keyCheck)
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

// Close closes the read-only pool and the writer.
func (s *Store) Close() error {
	var readerErr error
	if s.reader != nil {
		readerErr = s.reader.Close()
	}
	return errors.Join(readerErr, s.db.Close())
}

// Ping checks the database through the read-only pool so /healthz answers
// while a write transaction holds the writer connection. A trivial query is
// used rather than a driver ping so the check reads the database file.
func (s *Store) Ping(ctx context.Context) error {
	var version int64
	return s.readDB().QueryRowContext(ctx, "PRAGMA schema_version").Scan(&version)
}

package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
)

type Store struct {
	db          *sql.DB
	box         *secret.Box
	evidenceKey evidenceSigningKey
}

type Settings struct {
	Tailnet           string
	OAuthClientID     string
	OAuthClientSecret string
	WebhookSecret     string
	// MattermostURL is retained for source compatibility with older callers.
	// New configuration is stored through NotificationDestination APIs.
	MattermostURL     string
	DeviceInterval    time.Duration
	InventoryInterval time.Duration
	Generation        int64
	ConfiguredAt      time.Time
	BaselineAt        *time.Time
}

type NotificationDestination struct {
	ID         int64
	Name       string
	ServiceURL string
	Enabled    bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
}

type CollectorState struct {
	Name         string     `json:"name"`
	Supported    bool       `json:"supported"`
	Baseline     bool       `json:"baseline"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	FailureCount int        `json:"failure_count"`
	NextPoll     *time.Time `json:"next_poll,omitempty"`
}

type Status struct {
	Configured          bool
	BaselineAt          *time.Time
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
	ID         int64
	BatchID    int64
	Generation int64
	ObservedAt time.Time
	Collector  string
	EventType  string
	ResourceID string
	Name       string
	Fields     []HistoryFieldChange
	BeforeJSON string
	AfterJSON  string
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

const currentSchemaVersion = 6

const (
	webhookTriggerRetryWindow = 24 * time.Hour
	webhookTriggerLease       = 2 * time.Minute
	webhookTriggerBatchSize   = 8
)

func Open(path string, box *secret.Box) (*Store, error) {
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
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
	st := &Store{db: db, box: box}
	var keyCheck string
	err = db.QueryRow("SELECT value FROM meta WHERE key='master_key_check'").Scan(&keyCheck)
	if errors.Is(err, sql.ErrNoRows) {
		encrypted, encryptErr := box.Encrypt("tailstate-master-key-check")
		if encryptErr != nil {
			db.Close()
			return nil, encryptErr
		}
		if _, err = db.Exec("INSERT INTO meta(key,value) VALUES('master_key_check',?)", encrypted); err != nil {
			db.Close()
			return nil, err
		}
	} else if err != nil {
		db.Close()
		return nil, err
	} else {
		plain, decryptErr := box.Decrypt(keyCheck)
		if decryptErr != nil || plain != "tailstate-master-key-check" {
			db.Close()
			return nil, errors.New("master key does not match this TailState database")
		}
	}
	st.evidenceKey, err = loadOrCreateEvidenceSigningKey(context.Background(), db, box)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("load evidence signing key: %w", err)
	}
	if err := st.backfillEvidenceLedger(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("backfill evidence ledger: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

// migrateSchema keeps startup safe as the on-disk schema evolves. The schema
// bootstrap is intentionally idempotent; versioned migrations belong here so
// a future release cannot silently run against an incompatible database.
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
	rows.Close()
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

func addColumnIfMissing(tx *sql.Tx, table, column, definition string) error {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
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

func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin").Scan(&n)
	return n > 0, err
}

func (s *Store) NewSetupToken(ctx context.Context) (string, error) {
	exists, err := s.AdminExists(ctx)
	if err != nil || exists {
		return "", err
	}
	token, err := secret.Token(24)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES('setup_token_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, secret.HashToken(token))
	return token, err
}

func (s *Store) Claim(ctx context.Context, token, password string) error {
	if err := s.validateSetupToken(ctx, token); err != nil {
		return err
	}
	hash, err := secret.PasswordHash(password)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var want string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='setup_token_hash'").Scan(&want); err != nil {
		return errors.New("setup token is unavailable")
	}
	got := secret.HashToken(token)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errors.New("invalid setup token")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "INSERT INTO admin(id,password_hash,created_at,updated_at) VALUES(1,?,?,?)", hash, now, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM meta WHERE key='setup_token_hash'"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) validateSetupToken(ctx context.Context, token string) error {
	var want string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='setup_token_hash'").Scan(&want); err != nil {
		return errors.New("setup token is unavailable")
	}
	if subtle.ConstantTimeCompare([]byte(secret.HashToken(token)), []byte(want)) != 1 {
		return errors.New("invalid setup token")
	}
	return nil
}

func (s *Store) Authenticate(ctx context.Context, password string) bool {
	var hash string
	if s.db.QueryRowContext(ctx, "SELECT password_hash FROM admin WHERE id=1").Scan(&hash) != nil {
		return false
	}
	return secret.PasswordMatches(hash, password)
}

func (s *Store) ResetPassword(ctx context.Context, password string) error {
	hash, err := secret.PasswordHash(password)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE admin SET password_hash=?,updated_at=? WHERE id=1", hash, now)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("administrator is not configured")
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) NewResetToken(ctx context.Context) (string, error) {
	token, err := secret.Token(24)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES('reset_token_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, secret.HashToken(token))
	return token, err
}
func (s *Store) ResetWithToken(ctx context.Context, token, password string) error {
	if err := s.validateResetToken(ctx, token); err != nil {
		return err
	}
	hash, err := secret.PasswordHash(password)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var want string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='reset_token_hash'").Scan(&want); err != nil {
		return errors.New("reset token is unavailable")
	}
	if subtle.ConstantTimeCompare([]byte(secret.HashToken(token)), []byte(want)) != 1 {
		return errors.New("invalid reset token")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "UPDATE admin SET password_hash=?,updated_at=? WHERE id=1", hash, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("administrator is not configured")
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM meta WHERE key='reset_token_hash'"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) validateResetToken(ctx context.Context, token string) error {
	var want string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='reset_token_hash'").Scan(&want); err != nil {
		return errors.New("reset token is unavailable")
	}
	if subtle.ConstantTimeCompare([]byte(secret.HashToken(token)), []byte(want)) != 1 {
		return errors.New("invalid reset token")
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context) (token, csrf string, err error) {
	token, err = secret.Token(32)
	if err != nil {
		return
	}
	csrf, err = secret.Token(24)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?)", secret.HashToken(token), secret.HashToken(csrf), now.Add(12*time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return
}

func (s *Store) ValidateSession(ctx context.Context, token, csrf string, requireCSRF bool) bool {
	var csrfHash, expires string
	if s.db.QueryRowContext(ctx, "SELECT csrf_hash,expires_at FROM sessions WHERE token_hash=?", secret.HashToken(token)).Scan(&csrfHash, &expires) != nil {
		return false
	}
	expiry, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !expiry.After(time.Now()) {
		return false
	}
	if requireCSRF && subtle.ConstantTimeCompare([]byte(secret.HashToken(csrf)), []byte(csrfHash)) != 1 {
		return false
	}
	return true
}

func (s *Store) DeleteSession(ctx context.Context, token string) {
	_, _ = s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", secret.HashToken(token))
}

func (s *Store) SaveSettings(ctx context.Context, in Settings) (int64, error) {
	if strings.TrimSpace(in.Tailnet) == "" {
		in.Tailnet = "-"
	}
	in.WebhookSecret = strings.TrimSpace(in.WebhookSecret)
	if len(in.WebhookSecret) > 1024 {
		return 0, errors.New("webhook secret is too long")
	}
	if in.OAuthClientID == "" || in.OAuthClientSecret == "" {
		return 0, errors.New("OAuth credentials are required")
	}
	if in.DeviceInterval < 15*time.Second || in.InventoryInterval < 30*time.Second {
		return 0, errors.New("poll intervals are too short")
	}
	secretEnc, err := s.box.Encrypt(in.OAuthClientSecret)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var oldTailnet, oldClient, oldSecretEnc, oldWebhookSecretEnc string
	var generation int64
	generationChanged := false
	settingsExists := true
	err = tx.QueryRowContext(ctx, "SELECT tailnet,oauth_client_id,oauth_secret_enc,COALESCE(webhook_secret_enc,''),generation FROM settings WHERE id=1").Scan(&oldTailnet, &oldClient, &oldSecretEnc, &oldWebhookSecretEnc, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		settingsExists = false
		generation = 1
	} else if err != nil {
		return 0, err
	} else {
		oldSecret, decryptErr := s.box.Decrypt(oldSecretEnc)
		if decryptErr != nil {
			return 0, decryptErr
		}
		if oldTailnet != in.Tailnet || oldClient != in.OAuthClientID || oldSecret != in.OAuthClientSecret {
			generation++
			generationChanged = true
		}
	}
	webhookSecretEnc := oldWebhookSecretEnc
	if in.WebhookSecret != "" {
		webhookSecretEnc, err = s.box.Encrypt(in.WebhookSecret)
		if err != nil {
			return 0, err
		}
	}
	legacyURLEnc := ""
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(mattermost_url_enc,'') FROM settings WHERE id=1").Scan(&legacyURLEnc); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if in.MattermostURL != "" {
		converted, convertErr := notify.ConvertLegacyMattermostURL(in.MattermostURL)
		if convertErr != nil {
			return 0, convertErr
		}
		legacyURLEnc, err = s.box.Encrypt(in.MattermostURL)
		if err != nil {
			return 0, err
		}
		if _, err := upsertDestinationTx(ctx, tx, s.box, 0, "Mattermost", converted, true); err != nil {
			return 0, err
		}
	}
	if in.MattermostURL == "" && !settingsExists {
		var enabled int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL").Scan(&enabled); err != nil {
			return 0, err
		}
		if enabled == 0 {
			return 0, errors.New("at least one enabled notification destination is required")
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO settings(id,tailnet,oauth_client_id,oauth_secret_enc,mattermost_url_enc,webhook_secret_enc,device_interval_seconds,inventory_interval_seconds,generation,configured_at,baseline_at)
	VALUES(1,?,?,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET tailnet=excluded.tailnet,oauth_client_id=excluded.oauth_client_id,oauth_secret_enc=excluded.oauth_secret_enc,mattermost_url_enc=CASE WHEN excluded.mattermost_url_enc='' THEN settings.mattermost_url_enc ELSE excluded.mattermost_url_enc END,webhook_secret_enc=CASE WHEN excluded.webhook_secret_enc='' THEN settings.webhook_secret_enc ELSE excluded.webhook_secret_enc END,device_interval_seconds=excluded.device_interval_seconds,inventory_interval_seconds=excluded.inventory_interval_seconds,generation=excluded.generation,configured_at=excluded.configured_at,baseline_at=CASE WHEN settings.generation=excluded.generation THEN settings.baseline_at ELSE NULL END`, in.Tailnet, in.OAuthClientID, secretEnc, legacyURLEnc, webhookSecretEnc, int64(in.DeviceInterval.Seconds()), int64(in.InventoryInterval.Seconds()), generation, now)
	if err != nil {
		return 0, err
	}
	if generationChanged {
		if _, err := tx.ExecContext(ctx, "DELETE FROM snapshots WHERE generation<>?", generation); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM collector_state WHERE generation<>?", generation); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return generation, nil
}

func (s *Store) Settings(ctx context.Context) (Settings, error) {
	var out Settings
	var secretEnc, urlEnc, webhookSecretEnc, configured, baseline string
	var device, inventory int64
	err := s.db.QueryRowContext(ctx, "SELECT tailnet,oauth_client_id,oauth_secret_enc,mattermost_url_enc,COALESCE(webhook_secret_enc,''),device_interval_seconds,inventory_interval_seconds,generation,configured_at,COALESCE(baseline_at,'') FROM settings WHERE id=1").Scan(&out.Tailnet, &out.OAuthClientID, &secretEnc, &urlEnc, &webhookSecretEnc, &device, &inventory, &out.Generation, &configured, &baseline)
	if err != nil {
		return Settings{}, err
	}
	out.OAuthClientSecret, err = s.box.Decrypt(secretEnc)
	if err != nil {
		return Settings{}, err
	}
	if urlEnc != "" {
		out.MattermostURL, err = s.box.Decrypt(urlEnc)
		if err != nil {
			return Settings{}, err
		}
	}
	if webhookSecretEnc != "" {
		out.WebhookSecret, err = s.box.Decrypt(webhookSecretEnc)
		if err != nil {
			return Settings{}, err
		}
	}
	out.DeviceInterval = time.Duration(device) * time.Second
	out.InventoryInterval = time.Duration(inventory) * time.Second
	out.ConfiguredAt, _ = time.Parse(time.RFC3339Nano, configured)
	if baseline != "" {
		t, _ := time.Parse(time.RFC3339Nano, baseline)
		out.BaselineAt = &t
	}
	return out, nil
}

// WebhookSecret returns the decrypted Tailscale webhook secret only to the
// request verifier. It is never included in rendered settings data.
func (s *Store) WebhookSecret(ctx context.Context) (string, error) {
	var encrypted string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(webhook_secret_enc,'') FROM settings WHERE id=1").Scan(&encrypted); err != nil {
		return "", err
	}
	if encrypted == "" {
		return "", nil
	}
	return s.box.Decrypt(encrypted)
}

// RecordWebhookTrigger persists verified event metadata and returns whether
// this body hash was newly queued. A unique hash makes provider retries and
// accidental replay harmless while keeping the original body out of SQLite.
func (s *Store) RecordWebhookTrigger(ctx context.Context, bodyHash string, eventTypes, collectors []string) (WebhookTrigger, bool, error) {
	bodyHash = strings.TrimSpace(bodyHash)
	if len(bodyHash) != sha256HexLength {
		return WebhookTrigger{}, false, errors.New("invalid webhook body hash")
	}
	if _, err := hex.DecodeString(bodyHash); err != nil {
		return WebhookTrigger{}, false, errors.New("invalid webhook body hash")
	}
	eventTypes = sortedUnique(eventTypes)
	collectors = sortedUnique(collectors)
	if len(eventTypes) > 100 || len(collectors) > 32 {
		return WebhookTrigger{}, false, errors.New("webhook metadata is too large")
	}
	eventJSON, err := json.Marshal(eventTypes)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	collectorJSON, err := json.Marshal(collectors)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO webhook_triggers(body_hash,received_at,event_types_json,collectors_json,status,next_attempt_at) VALUES(?,?,?,?, 'pending',?) ON CONFLICT(body_hash) DO NOTHING`, bodyHash, nowValue, eventJSON, collectorJSON, nowValue)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	created := false
	if affected, affectedErr := result.RowsAffected(); affectedErr == nil {
		created = affected == 1
	}
	trigger, err := readWebhookTrigger(tx.QueryRowContext(ctx, webhookTriggerSelect+" WHERE body_hash=?", bodyHash))
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return WebhookTrigger{}, false, err
	}
	return trigger, created, nil
}

const (
	sha256HexLength      = sha256.Size * 2
	webhookTriggerSelect = `SELECT id,body_hash,received_at,event_types_json,collectors_json,status,attempts,next_attempt_at,COALESCE(lease_until,''),last_error,COALESCE(processed_at,'') FROM webhook_triggers`
)

type webhookTriggerScanner interface {
	Scan(dest ...any) error
}

func readWebhookTrigger(scanner webhookTriggerScanner) (WebhookTrigger, error) {
	var trigger WebhookTrigger
	var received, eventRaw, collectorRaw, nextAttempt, leaseUntil, processed string
	if err := scanner.Scan(&trigger.ID, &trigger.BodyHash, &received, &eventRaw, &collectorRaw, &trigger.Status, &trigger.Attempts, &nextAttempt, &leaseUntil, &trigger.LastError, &processed); err != nil {
		return WebhookTrigger{}, err
	}
	trigger.ReceivedAt = parseTime(received)
	trigger.NextAttempt = parseTime(nextAttempt)
	if leaseUntil != "" {
		value := parseTime(leaseUntil)
		trigger.LeaseUntil = &value
	}
	if processed != "" {
		value := parseTime(processed)
		trigger.ProcessedAt = &value
	}
	if err := json.Unmarshal([]byte(eventRaw), &trigger.EventTypes); err != nil {
		return WebhookTrigger{}, fmt.Errorf("decode webhook event metadata: %w", err)
	}
	if err := json.Unmarshal([]byte(collectorRaw), &trigger.Collectors); err != nil {
		return WebhookTrigger{}, fmt.Errorf("decode webhook collector metadata: %w", err)
	}
	return trigger, nil
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

// ClaimWebhookTriggers leases queued triggers for one reconciliation worker.
// Expired leases are returned to the queue, while triggers older than the
// retry horizon become dead letters instead of being retried forever.
func (s *Store) ClaimWebhookTriggers(ctx context.Context, limit int, lease time.Duration) ([]WebhookTrigger, error) {
	if limit <= 0 {
		limit = webhookTriggerBatchSize
	}
	if limit > 64 {
		limit = 64
	}
	if lease < time.Second {
		lease = webhookTriggerLease
	}
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	deadline := now.Add(-webhookTriggerRetryWindow).Format(time.RFC3339Nano)
	leaseValue := now.Add(lease).Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_triggers SET status='pending',lease_until=NULL WHERE status='processing' AND (lease_until IS NULL OR lease_until<=?)`, nowValue); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_triggers SET status='dead',lease_until=NULL,last_error='reconciliation retry window expired' WHERE status IN ('pending','processing') AND received_at<=? AND (status='pending' OR lease_until IS NULL OR lease_until<=?)`, deadline, nowValue); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, webhookTriggerSelect+` WHERE status='pending' AND next_attempt_at<=? ORDER BY id LIMIT ?`, nowValue, limit)
	if err != nil {
		return nil, err
	}
	triggers := make([]WebhookTrigger, 0, limit)
	for rows.Next() {
		trigger, scanErr := readWebhookTrigger(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		triggers = append(triggers, trigger)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range triggers {
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status='processing',attempts=attempts+1,lease_until=? WHERE id=? AND status='pending'", leaseValue, triggers[i].ID); err != nil {
			return nil, err
		}
		triggers[i].Status = "processing"
		triggers[i].Attempts++
		value := now.Add(lease)
		triggers[i].LeaseUntil = &value
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return triggers, nil
}

// CompleteWebhookTriggers marks successfully reconciled triggers only after
// the associated inventory transaction has committed.
func (s *Store) CompleteWebhookTriggers(ctx context.Context, ids []int64) error {
	ids = uniquePositiveIDs(ids)
	if len(ids) == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status='processed',processed_at=?,lease_until=NULL,last_error='' WHERE id=? AND status IN ('pending','processing')", now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RetryWebhookTriggers returns failed triggers to the durable queue, or
// dead-letters them once their 24-hour retry horizon has elapsed.
func (s *Store) RetryWebhookTriggers(ctx context.Context, ids []int64, next time.Time, message string) error {
	ids = uniquePositiveIDs(ids)
	if len(ids) == 0 {
		return nil
	}
	message = truncate(strings.TrimSpace(message), 500)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		var received string
		if err := tx.QueryRowContext(ctx, "SELECT received_at FROM webhook_triggers WHERE id=?", id).Scan(&received); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
		dead := now.Sub(parseTime(received)) >= webhookTriggerRetryWindow
		status := "pending"
		attempt := next.UTC()
		if dead {
			status = "dead"
			attempt = now
			if message == "" {
				message = "reconciliation retry window expired"
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status=?,next_attempt_at=?,lease_until=NULL,last_error=? WHERE id=? AND status IN ('pending','processing')", status, attempt.Format(time.RFC3339Nano), message, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkWebhookTriggerProcessed remains for compatibility with older callers.
func (s *Store) MarkWebhookTriggerProcessed(ctx context.Context, id int64) error {
	return s.CompleteWebhookTriggers(ctx, []int64{id})
}

func uniquePositiveIDs(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	for _, value := range values {
		if value > 0 {
			seen[value] = struct{}{}
		}
	}
	out := make([]int64, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// ListDestinations returns active notification destinations. Pass true to
// include soft-deleted destinations (their encrypted URLs are still decrypted
// only inside the process and are never rendered by the web layer).
func (s *Store) ListDestinations(ctx context.Context, includeDeleted ...bool) ([]NotificationDestination, error) {
	query := "SELECT id,name,service_url_enc,enabled,created_at,updated_at,COALESCE(deleted_at,'') FROM notification_destinations"
	if len(includeDeleted) == 0 || !includeDeleted[0] {
		query += " WHERE deleted_at IS NULL"
	}
	query += " ORDER BY id"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationDestination
	for rows.Next() {
		var d NotificationDestination
		var encrypted, created, updated, deleted string
		var enabled int
		if err := rows.Scan(&d.ID, &d.Name, &encrypted, &enabled, &created, &updated, &deleted); err != nil {
			return nil, err
		}
		d.ServiceURL, err = s.box.Decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		d.Enabled = enabled == 1
		d.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		d.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if deleted != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, deleted)
			if parseErr == nil {
				d.DeletedAt = &value
			}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveDestination creates or updates a destination. The URL is validated
// before it is encrypted and stored.
func (s *Store) SaveDestination(ctx context.Context, destination NotificationDestination) (int64, error) {
	destination.Name = strings.TrimSpace(destination.Name)
	destination.ServiceURL = strings.TrimSpace(destination.ServiceURL)
	if destination.Name == "" {
		return 0, errors.New("destination name is required")
	}
	if err := notify.Validate(destination.ServiceURL); err != nil {
		return 0, err
	}
	encrypted, err := s.box.Encrypt(destination.ServiceURL)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := upsertDestinationTx(ctx, tx, s.box, destination.ID, destination.Name, destination.ServiceURL, destination.Enabled)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc=? WHERE id=?", encrypted, id); err != nil {
		return 0, err
	}
	if !destination.Enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination disabled' WHERE destination_id=? AND status='pending'", id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// SetDestinationEnabled changes delivery state. Pending rows are dead-lettered
// when a destination is disabled so they cannot resume unexpectedly.
func (s *Store) SetDestinationEnabled(ctx context.Context, id int64, enabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET enabled=?,updated_at=? WHERE id=? AND deleted_at IS NULL", boolInt(enabled), now, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return errors.New("notification destination not found")
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination disabled' WHERE destination_id=? AND status='pending'", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteDestination soft-deletes a destination and dead-letters its pending
// notifications. Historical rows remain available for audit and retention.
func (s *Store) DeleteDestination(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET enabled=0,deleted_at=?,updated_at=? WHERE id=? AND deleted_at IS NULL", now, now, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return errors.New("notification destination not found")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination removed' WHERE destination_id=? AND status='pending'", id); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertDestinationTx(ctx context.Context, tx *sql.Tx, box *secret.Box, id int64, name, serviceURL string, enabled bool) (int64, error) {
	encoded, err := box.Encrypt(serviceURL)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if id == 0 {
		if name == "Mattermost" {
			_ = tx.QueryRowContext(ctx, "SELECT id FROM notification_destinations WHERE name=? AND deleted_at IS NULL ORDER BY id LIMIT 1", name).Scan(&id)
		}
	}
	if id > 0 {
		result, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET name=?,service_url_enc=?,enabled=?,updated_at=?,deleted_at=NULL WHERE id=?", name, encoded, boolInt(enabled), now, id)
		if err != nil {
			return 0, err
		}
		if n, _ := result.RowsAffected(); n == 0 {
			return 0, errors.New("notification destination not found")
		}
		return id, nil
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO notification_destinations(name,service_url_enc,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", name, encoded, boolInt(enabled), now, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Store) TrackAppVersion(ctx context.Context, current string, notification func(previous, current string) string) (bool, error) {
	current = strings.TrimSpace(current)
	if current == "" || current == "dev" {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='app_version'").Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES('app_version',?)", current); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if previous == current {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, "UPDATE meta SET value=? WHERE key='app_version'", current); err != nil {
		return false, err
	}
	var configured int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM settings").Scan(&configured); err != nil {
		return false, err
	}
	var enabledDestinations int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL").Scan(&enabledDestinations); err != nil {
		return false, err
	}
	notified := configured > 0 && enabledDestinations > 0
	if notified {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		payload := notification(previous, current)
		if err = enqueueOutboxTx(ctx, tx, payload, now, 0); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return notified, nil
}

type recordedChange struct {
	Change model.Change
	Before []byte
	After  []byte
}

func (s *Store) ApplyBatch(ctx context.Context, generation int64, results []model.Collected, digest func([]model.Change) string) ([]model.Change, error) {
	batch, err := s.ApplyBatchWithBatch(ctx, generation, results, digest)
	return batch.Changes, err
}

func (s *Store) ApplyBatchWithBatch(ctx context.Context, generation int64, results []model.Collected, digest func([]model.Change) string, triggerIDs ...int64) (ChangeBatchResult, error) {
	triggerIDs = uniquePositiveIDs(triggerIDs)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	defer tx.Rollback()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&activeGeneration); err != nil {
		return ChangeBatchResult{}, err
	}
	if activeGeneration != generation {
		return ChangeBatchResult{}, nil
	}
	now := time.Now().UTC()
	observedAt := now.Format(time.RFC3339Nano)
	var changes []model.Change
	var recorded []recordedChange
	record := func(change model.Change, before, after []byte) {
		changes = append(changes, change)
		recorded = append(recorded, recordedChange{Change: change, Before: append([]byte(nil), before...), After: append([]byte(nil), after...)})
	}
	for _, result := range results {
		if result.Error != nil {
			continue
		}
		if result.Unsupported {
			next := now.Add(6 * time.Hour).Format(time.RFC3339Nano)
			_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,next_poll) VALUES(?,?,0,0,'unsupported',?) ON CONFLICT(generation,collector) DO UPDATE SET supported=0,baseline=0,last_error='unsupported',next_poll=excluded.next_poll`, generation, result.Collector, next)
			if err != nil {
				return ChangeBatchResult{}, err
			}
			continue
		}
		var baseline int
		_ = tx.QueryRowContext(ctx, "SELECT baseline FROM collector_state WHERE generation=? AND collector=?", generation, result.Collector).Scan(&baseline)
		seen := make(map[string]struct{}, len(result.Resources))
		for _, resource := range result.Resources {
			seen[resource.ID] = struct{}{}
			raw, hash, err := model.CanonicalFor(result.Collector, resource.Data)
			if err != nil {
				return ChangeBatchResult{}, err
			}
			var oldRaw []byte
			var oldHash, oldType, oldName string
			var missing int
			err = tx.QueryRowContext(ctx, "SELECT canonical_json,content_hash,resource_type,name,missing_count FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, resource.ID).Scan(&oldRaw, &oldHash, &oldType, &oldName, &missing)
			if err == nil && oldHash != hash {
				var oldValue any
				if json.Unmarshal(oldRaw, &oldValue) == nil {
					normalizedOldRaw, normalizedOldHash, normalizeErr := model.CanonicalFor(result.Collector, oldValue)
					if normalizeErr != nil {
						return ChangeBatchResult{}, normalizeErr
					}
					oldRaw = normalizedOldRaw
					oldHash = normalizedOldHash
				}
			}
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if baseline == 1 {
					record(model.Change{Kind: "created", Collector: result.Collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name}, nil, raw)
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,missing_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, generation, result.Collector, resource.ID, resource.Type, resource.Name, raw, hash, 0, now.Format(time.RFC3339Nano))
			case err != nil:
				return ChangeBatchResult{}, err
			case oldHash != hash:
				if baseline == 1 {
					record(model.Change{Kind: "changed", Collector: result.Collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name, Fields: model.Diff(oldRaw, raw)}, oldRaw, raw)
				}
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, raw, hash, now.Format(time.RFC3339Nano), generation, result.Collector, resource.ID)
			default:
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, raw, hash, now.Format(time.RFC3339Nano), generation, result.Collector, resource.ID)
			}
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
		rows, err := tx.QueryContext(ctx, "SELECT resource_id,resource_type,name,canonical_json,missing_count FROM snapshots WHERE generation=? AND collector=?", generation, result.Collector)
		if err != nil {
			return ChangeBatchResult{}, err
		}
		type absent struct {
			id, typ, name string
			raw           []byte
			missing       int
		}
		var missingRows []absent
		for rows.Next() {
			var a absent
			if err := rows.Scan(&a.id, &a.typ, &a.name, &a.raw, &a.missing); err != nil {
				rows.Close()
				return ChangeBatchResult{}, err
			}
			if _, ok := seen[a.id]; !ok {
				missingRows = append(missingRows, a)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return ChangeBatchResult{}, err
		}
		rows.Close()
		for _, a := range missingRows {
			if a.missing+1 >= 2 {
				if baseline == 1 {
					record(model.Change{Kind: "removed", Collector: result.Collector, ResourceID: a.id, Type: a.typ, Name: a.name}, a.raw, nil)
				}
				_, err = tx.ExecContext(ctx, "DELETE FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, a.id)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET missing_count=missing_count+1 WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, a.id)
			}
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified) VALUES(?,?,1,1,?,'',0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,baseline=1,last_success=excluded.last_success,last_error='',failure_count=0,unhealthy_notified=0`, generation, result.Collector, observedAt)
		if err != nil {
			return ChangeBatchResult{}, err
		}
	}
	var triggerID int64
	if len(triggerIDs) > 0 && triggerIDs[0] > 0 {
		triggerID = triggerIDs[0]
	}
	result := ChangeBatchResult{ChangeBatch: ChangeBatch{Generation: generation, ObservedAt: now, TriggerID: triggerID, TriggerIDs: append([]int64(nil), triggerIDs...)}, Changes: changes}
	if len(recorded) > 0 {
		var triggerValue any
		if triggerID > 0 {
			triggerValue = triggerID
		}
		batchResult, err := tx.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at,trigger_id) VALUES(?,?,?,?,?)", generation, observedAt, len(recorded), observedAt, triggerValue)
		if err != nil {
			return ChangeBatchResult{}, err
		}
		batchID, err := batchResult.LastInsertId()
		if err != nil {
			return ChangeBatchResult{}, err
		}
		result.ID, result.ChangeCount = batchID, len(recorded)
		for _, triggerID := range triggerIDs {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO event_batch_triggers(batch_id,trigger_id) VALUES(?,?)", batchID, triggerID); err != nil {
				return ChangeBatchResult{}, err
			}
		}
		for _, entry := range recorded {
			fields, marshalErr := json.Marshal(entry.Change.Fields)
			if marshalErr != nil {
				return ChangeBatchResult{}, marshalErr
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?,?)", batchID, generation, observedAt, entry.Change.Collector, entry.Change.Kind, entry.Change.ResourceID, entry.Change.Name, fields, nullableJSON(entry.Before), nullableJSON(entry.After))
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
		payload := digest(changes)
		if err = enqueueOutboxTx(ctx, tx, payload, observedAt, batchID); err != nil {
			return ChangeBatchResult{}, err
		}
		if err = s.appendEvidenceLedgerTx(ctx, tx, batchID); err != nil {
			return ChangeBatchResult{}, err
		}
	}
	var remaining int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1 AND baseline=0", generation).Scan(&remaining)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	var supported int
	_ = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1", generation).Scan(&supported)
	if supported > 0 && remaining == 0 {
		_, err = tx.ExecContext(ctx, "UPDATE settings SET baseline_at=COALESCE(baseline_at,?) WHERE id=1 AND generation=?", observedAt, generation)
		if err != nil {
			return ChangeBatchResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ChangeBatchResult{}, err
	}
	return result, nil
}

func nullableJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func (s *Store) RecordCollectorFailure(ctx context.Context, generation int64, collector, message string) (notify bool, recovered bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&activeGeneration); err != nil {
		return false, false, err
	}
	if activeGeneration != generation {
		return false, false, nil
	}
	var failures, notified int
	_ = tx.QueryRowContext(ctx, "SELECT failure_count,unhealthy_notified FROM collector_state WHERE generation=? AND collector=?", generation, collector).Scan(&failures, &notified)
	failures++
	notify = failures >= 3 && notified == 0
	if notify {
		notified = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,failure_count,unhealthy_notified) VALUES(?,?,1,0,?,?,?) ON CONFLICT(generation,collector) DO UPDATE SET last_error=excluded.last_error,failure_count=excluded.failure_count,unhealthy_notified=excluded.unhealthy_notified`, generation, collector, message, failures, notified)
	if err != nil {
		return false, false, err
	}
	err = tx.Commit()
	return
}

func (s *Store) CollectorWasUnhealthy(ctx context.Context, generation int64, collector string) bool {
	var notified int
	_ = s.db.QueryRowContext(ctx, "SELECT unhealthy_notified FROM collector_state WHERE generation=? AND collector=?", generation, collector).Scan(&notified)
	return notified == 1
}

func (s *Store) EnqueueSystem(ctx context.Context, payload string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := enqueueOutboxTx(ctx, tx, payload, now, 0); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DueOutbox(ctx context.Context, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.id,COALESCE(o.batch_id,0),o.destination_id,o.payload,o.attempts,o.first_attempt,d.name,d.service_url_enc,d.enabled,d.created_at,d.updated_at,COALESCE(d.deleted_at,'')
		FROM outbox o JOIN notification_destinations d ON d.id=o.destination_id
		WHERE o.status='pending' AND o.next_attempt<=? AND d.enabled=1 AND d.deleted_at IS NULL ORDER BY o.id LIMIT ?`, time.Now().UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var item OutboxItem
		var batchID sql.NullInt64
		var first, encrypted, created, updated, deleted, name string
		var enabled int
		if err := rows.Scan(&item.ID, &batchID, &item.DestinationID, &item.Payload, &item.Attempts, &first, &name, &encrypted, &enabled, &created, &updated, &deleted); err != nil {
			return nil, err
		}
		if batchID.Valid {
			item.BatchID = batchID.Int64
		}
		item.FirstAttempt, _ = time.Parse(time.RFC3339Nano, first)
		item.Destination = NotificationDestination{ID: item.DestinationID, Name: name, Enabled: enabled == 1}
		item.Destination.ServiceURL, err = s.box.Decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		item.Destination.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		item.Destination.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if deleted != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, deleted)
			if parseErr == nil {
				item.Destination.DeletedAt = &value
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func enqueueOutboxTx(ctx context.Context, tx *sql.Tx, payload, now string, batchID int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var destinationID int64
		if err := rows.Scan(&destinationID); err != nil {
			return err
		}
		var batchValue any
		if batchID > 0 {
			batchValue = batchID
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(?,?,?,'pending',?,?,?)", batchValue, destinationID, payload, now, now, now); err != nil {
			return err
		}
	}
	return rows.Err()
}
func (s *Store) Delivered(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status='delivered',delivered_at=?,last_error='' WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}
func (s *Store) Retry(ctx context.Context, id int64, next time.Time, message string, dead bool) error {
	var encrypted string
	if err := s.db.QueryRowContext(ctx, "SELECT d.service_url_enc FROM outbox o JOIN notification_destinations d ON d.id=o.destination_id WHERE o.id=?", id).Scan(&encrypted); err == nil {
		if destinationURL, decryptErr := s.box.Decrypt(encrypted); decryptErr == nil {
			message = strings.ReplaceAll(message, destinationURL, notify.RedactURL(destinationURL))
		}
	}
	status := "pending"
	if dead {
		status = "dead"
	}
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status=?,attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?", status, next.UTC().Format(time.RFC3339Nano), truncate(message, 500), id)
	return err
}

func (s *Store) Status(ctx context.Context) (Status, error) {
	out := Status{ResourceCounts: map[string]int{}}
	var baseline string
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(baseline_at,'') FROM settings WHERE id=1").Scan(&baseline)
	if err == nil {
		out.Configured = true
		if baseline != "" {
			t, _ := time.Parse(time.RFC3339Nano, baseline)
			out.BaselineAt = &t
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if out.Configured {
		settings, err := s.Settings(ctx)
		if err != nil {
			return out, fmt.Errorf("load settings for status: %w", err)
		}
		rows, err := s.db.QueryContext(ctx, "SELECT collector,COUNT(*) FROM snapshots WHERE generation=? GROUP BY collector", settings.Generation)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return out, err
			}
			out.ResourceCounts[k] = n
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return out, err
		}
		rows.Close()
		rows, err = s.db.QueryContext(ctx, "SELECT collector,supported,baseline,COALESCE(last_success,''),last_error,failure_count,COALESCE(next_poll,'') FROM collector_state WHERE generation=? ORDER BY collector", settings.Generation)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var c CollectorState
			var last, next string
			if err := rows.Scan(&c.Name, &c.Supported, &c.Baseline, &last, &c.LastError, &c.FailureCount, &next); err != nil {
				return out, err
			}
			if last != "" {
				t, _ := time.Parse(time.RFC3339Nano, last)
				c.LastSuccess = &t
			}
			if next != "" {
				t, _ := time.Parse(time.RFC3339Nano, next)
				c.NextPoll = &t
			}
			out.Collectors = append(out.Collectors, c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return out, err
		}
		rows.Close()
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='pending'").Scan(&out.Pending); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='dead'").Scan(&out.Dead); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE deleted_at IS NULL").Scan(&out.Destinations); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE deleted_at IS NULL AND enabled=1").Scan(&out.EnabledDestinations); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_triggers WHERE status='pending'").Scan(&out.WebhookPending); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_triggers WHERE status='processing'").Scan(&out.WebhookProcessing); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_triggers WHERE status='dead'").Scan(&out.WebhookDead); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Store) SetNextPoll(ctx context.Context, generation int64, collectors []string, next time.Time) {
	sort.Strings(collectors)
	for _, collector := range collectors {
		_, _ = s.db.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,next_poll)
		SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM settings WHERE id=1 AND generation=?)
		ON CONFLICT(generation,collector) DO UPDATE SET next_poll=excluded.next_poll`, generation, collector, next.UTC().Format(time.RFC3339Nano), generation)
	}
}

func (s *Store) CollectorDue(ctx context.Context, generation int64, collector string) bool {
	var next string
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(next_poll,'') FROM collector_state WHERE generation=? AND collector=?", generation, collector).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) || next == "" {
		return true
	}
	if err != nil {
		return true
	}
	when, err := time.Parse(time.RFC3339Nano, next)
	return err != nil || !when.After(time.Now())
}
func (s *Store) Cleanup(ctx context.Context, retention time.Duration) error {
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	cutoff := now.Add(-retention).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE observed_at<?", cutoff)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM event_batches WHERE NOT EXISTS (SELECT 1 FROM events WHERE events.batch_id=event_batches.id)"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM event_batch_triggers WHERE NOT EXISTS (SELECT 1 FROM event_batches WHERE event_batches.id=event_batch_triggers.batch_id)"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM evidence_ledger WHERE NOT EXISTS (SELECT 1 FROM event_batches WHERE event_batches.id=evidence_ledger.batch_id)"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM webhook_triggers WHERE received_at<?", cutoff); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM outbox WHERE status='delivered' AND delivered_at<?", cutoff)
	return err
}

func (s *Store) ListHistory(ctx context.Context, filter HistoryFilter) (HistoryPage, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	where := []string{"1=1"}
	args := make([]any, 0, 5)
	if filter.Cursor > 0 {
		where = append(where, "b.id < ?")
		args = append(args, filter.Cursor)
	}
	if filter.Collector != "" {
		where = append(where, "EXISTS (SELECT 1 FROM events e WHERE e.batch_id=b.id AND e.collector=?)")
		args = append(args, filter.Collector)
	}
	if filter.EventType != "" {
		where = append(where, "EXISTS (SELECT 1 FROM events e WHERE e.batch_id=b.id AND e.event_type=?)")
		args = append(args, filter.EventType)
	}
	if filter.ResourceID != "" {
		where = append(where, "EXISTS (SELECT 1 FROM events e WHERE e.batch_id=b.id AND (e.resource_id LIKE ? OR e.name LIKE ?))")
		term := "%" + filter.ResourceID + "%"
		args = append(args, term, term)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT b.id,b.generation,b.observed_at,b.change_count,COALESCE(b.trigger_id,0)
		FROM event_batches b WHERE `+strings.Join(where, " AND ")+` ORDER BY b.id DESC LIMIT ?`, args...)
	if err != nil {
		return HistoryPage{}, err
	}
	defer rows.Close()
	page := HistoryPage{Batches: make([]HistoryBatch, 0, limit)}
	for rows.Next() {
		var batch HistoryBatch
		var observed string
		if err := rows.Scan(&batch.ID, &batch.Generation, &observed, &batch.ChangeCount, &batch.TriggerID); err != nil {
			return HistoryPage{}, err
		}
		batch.ObservedAt, _ = time.Parse(time.RFC3339Nano, observed)
		page.Batches = append(page.Batches, batch)
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, err
	}
	if len(page.Batches) > limit {
		page.HasNext = true
		page.NextCursor = page.Batches[limit-1].ID
		page.Batches = page.Batches[:limit]
	}
	loadedBatches := make([]HistoryBatch, 0, len(page.Batches))
	for _, batch := range page.Batches {
		loaded, err := s.loadHistoryBatch(ctx, batch, filter)
		if err != nil {
			return HistoryPage{}, err
		}
		if len(loaded.Events) > 0 {
			if filter.Collector != "" || filter.EventType != "" || filter.ResourceID != "" {
				loaded.ChangeCount = len(loaded.Events)
			}
			loadedBatches = append(loadedBatches, loaded)
		}
	}
	page.Batches = loadedBatches
	return page, nil
}

func (s *Store) loadHistoryBatch(ctx context.Context, batch HistoryBatch, filter HistoryFilter) (HistoryBatch, error) {
	triggerRows, err := s.db.QueryContext(ctx, "SELECT trigger_id FROM event_batch_triggers WHERE batch_id=? ORDER BY trigger_id", batch.ID)
	if err != nil {
		return HistoryBatch{}, err
	}
	for triggerRows.Next() {
		var triggerID int64
		if err := triggerRows.Scan(&triggerID); err != nil {
			triggerRows.Close()
			return HistoryBatch{}, err
		}
		if triggerID > 0 {
			batch.TriggerIDs = append(batch.TriggerIDs, triggerID)
		}
	}
	if err := triggerRows.Err(); err != nil {
		triggerRows.Close()
		return HistoryBatch{}, err
	}
	if err := triggerRows.Close(); err != nil {
		return HistoryBatch{}, err
	}
	if len(batch.TriggerIDs) == 0 && batch.TriggerID > 0 {
		batch.TriggerIDs = []int64{batch.TriggerID}
	}
	if err := s.db.QueryRowContext(ctx, "SELECT sequence,prev_hash,entry_hash,signature,key_id FROM evidence_ledger WHERE batch_id=?", batch.ID).Scan(&batch.LedgerSequence, &batch.LedgerPrevHash, &batch.LedgerHash, &batch.LedgerSignature, &batch.LedgerKeyID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return HistoryBatch{}, err
	}
	eventWhere := []string{"batch_id=?"}
	eventArgs := []any{batch.ID}
	if filter.Collector != "" {
		eventWhere = append(eventWhere, "collector=?")
		eventArgs = append(eventArgs, filter.Collector)
	}
	if filter.EventType != "" {
		eventWhere = append(eventWhere, "event_type=?")
		eventArgs = append(eventArgs, filter.EventType)
	}
	if filter.ResourceID != "" {
		eventWhere = append(eventWhere, "(resource_id LIKE ? OR name LIKE ?)")
		term := "%" + filter.ResourceID + "%"
		eventArgs = append(eventArgs, term, term)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json
		FROM events WHERE `+strings.Join(eventWhere, " AND ")+` ORDER BY id`, eventArgs...)
	if err != nil {
		return HistoryBatch{}, err
	}
	defer rows.Close()
	batch.Events = make([]HistoryEvent, 0, batch.ChangeCount)
	for rows.Next() {
		var event HistoryEvent
		var observed string
		var fieldsRaw, beforeRaw, afterRaw []byte
		if err := rows.Scan(&event.ID, &event.BatchID, &event.Generation, &observed, &event.Collector, &event.EventType, &event.ResourceID, &event.Name, &fieldsRaw, &beforeRaw, &afterRaw); err != nil {
			return HistoryBatch{}, err
		}
		event.ObservedAt, _ = time.Parse(time.RFC3339Nano, observed)
		var fields []model.FieldChange
		if err := json.Unmarshal(fieldsRaw, &fields); err != nil && len(fieldsRaw) > 0 {
			return HistoryBatch{}, fmt.Errorf("decode history fields: %w", err)
		}
		event.Fields = formatHistoryFields(fields)
		event.BeforeJSON = prettyJSON(beforeRaw)
		event.AfterJSON = prettyJSON(afterRaw)
		batch.Events = append(batch.Events, event)
	}
	if err := rows.Err(); err != nil {
		return HistoryBatch{}, err
	}
	if err := rows.Close(); err != nil {
		return HistoryBatch{}, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT o.id,o.destination_id,COALESCE(d.name,'Removed destination'),o.status,o.attempts,o.last_error,o.next_attempt,COALESCE(o.delivered_at,''),COALESCE(d.service_url_enc,'')
		FROM outbox o LEFT JOIN notification_destinations d ON d.id=o.destination_id
		WHERE o.batch_id=? ORDER BY o.id`, batch.ID)
	if err != nil {
		return HistoryBatch{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var delivery HistoryDelivery
		var nextAttempt, deliveredAt string
		var encryptedURL string
		if err := rows.Scan(&delivery.ID, &delivery.DestinationID, &delivery.Destination, &delivery.Status, &delivery.Attempts, &delivery.LastError, &nextAttempt, &deliveredAt, &encryptedURL); err != nil {
			return HistoryBatch{}, err
		}
		if encryptedURL != "" {
			if destinationURL, decryptErr := s.box.Decrypt(encryptedURL); decryptErr == nil {
				delivery.LastError = strings.ReplaceAll(delivery.LastError, destinationURL, notify.RedactURL(destinationURL))
			}
		}
		delivery.NextAttempt = parseOptionalTime(nextAttempt)
		delivery.DeliveredAt = parseOptionalTime(deliveredAt)
		batch.Deliveries = append(batch.Deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return HistoryBatch{}, err
	}
	return batch, nil
}

func formatHistoryFields(fields []model.FieldChange) []HistoryFieldChange {
	out := make([]HistoryFieldChange, 0, len(fields))
	for _, field := range fields {
		formatted := HistoryFieldChange{Field: field.Field, HasOld: field.Old != nil, HasNew: field.New != nil}
		if formatted.HasOld {
			formatted.Old = prettyValue(field.Old)
		}
		if formatted.HasNew {
			formatted.New = prettyValue(field.New)
		}
		out = append(out, formatted)
	}
	return out
}

func prettyJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return string(raw)
	}
	return prettyValue(value)
}

func prettyValue(value any) string {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}

func parseOptionalTime(value string) *time.Time {
	if value == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	return &t
}

func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "…"
}

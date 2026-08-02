package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
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
	db  *sql.DB
	box *secret.Box
}

type Settings struct {
	Tailnet           string
	OAuthClientID     string
	OAuthClientSecret string
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
}

type OutboxItem struct {
	ID            int64
	DestinationID int64
	Destination   NotificationDestination
	Payload       string
	Attempts      int
	FirstAttempt  time.Time
}

const currentSchemaVersion = 2

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
	var oldTailnet, oldClient, oldSecretEnc string
	var generation int64
	generationChanged := false
	settingsExists := true
	err = tx.QueryRowContext(ctx, "SELECT tailnet,oauth_client_id,oauth_secret_enc,generation FROM settings WHERE id=1").Scan(&oldTailnet, &oldClient, &oldSecretEnc, &generation)
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
	_, err = tx.ExecContext(ctx, `INSERT INTO settings(id,tailnet,oauth_client_id,oauth_secret_enc,mattermost_url_enc,device_interval_seconds,inventory_interval_seconds,generation,configured_at,baseline_at)
	VALUES(1,?,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET tailnet=excluded.tailnet,oauth_client_id=excluded.oauth_client_id,oauth_secret_enc=excluded.oauth_secret_enc,mattermost_url_enc=CASE WHEN excluded.mattermost_url_enc='' THEN settings.mattermost_url_enc ELSE excluded.mattermost_url_enc END,device_interval_seconds=excluded.device_interval_seconds,inventory_interval_seconds=excluded.inventory_interval_seconds,generation=excluded.generation,configured_at=excluded.configured_at,baseline_at=CASE WHEN settings.generation=excluded.generation THEN settings.baseline_at ELSE NULL END`, in.Tailnet, in.OAuthClientID, secretEnc, legacyURLEnc, int64(in.DeviceInterval.Seconds()), int64(in.InventoryInterval.Seconds()), generation, now)
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
	var secretEnc, urlEnc, configured, baseline string
	var device, inventory int64
	err := s.db.QueryRowContext(ctx, "SELECT tailnet,oauth_client_id,oauth_secret_enc,mattermost_url_enc,device_interval_seconds,inventory_interval_seconds,generation,configured_at,COALESCE(baseline_at,'') FROM settings WHERE id=1").Scan(&out.Tailnet, &out.OAuthClientID, &secretEnc, &urlEnc, &device, &inventory, &out.Generation, &configured, &baseline)
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
	out.DeviceInterval = time.Duration(device) * time.Second
	out.InventoryInterval = time.Duration(inventory) * time.Second
	out.ConfiguredAt, _ = time.Parse(time.RFC3339Nano, configured)
	if baseline != "" {
		t, _ := time.Parse(time.RFC3339Nano, baseline)
		out.BaselineAt = &t
	}
	return out, nil
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
		if err = enqueueOutboxTx(ctx, tx, payload, now); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return notified, nil
}

func (s *Store) ApplyBatch(ctx context.Context, generation int64, results []model.Collected, digest func([]model.Change) string) ([]model.Change, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&activeGeneration); err != nil {
		return nil, err
	}
	if activeGeneration != generation {
		return nil, nil
	}
	now := time.Now().UTC()
	var changes []model.Change
	for _, result := range results {
		if result.Error != nil {
			continue
		}
		if result.Unsupported {
			next := now.Add(6 * time.Hour).Format(time.RFC3339Nano)
			_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,next_poll) VALUES(?,?,0,0,'unsupported',?) ON CONFLICT(generation,collector) DO UPDATE SET supported=0,baseline=0,last_error='unsupported',next_poll=excluded.next_poll`, generation, result.Collector, next)
			if err != nil {
				return nil, err
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
				return nil, err
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
						return nil, normalizeErr
					}
					oldRaw = normalizedOldRaw
					oldHash = normalizedOldHash
				}
			}
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if baseline == 1 {
					changes = append(changes, model.Change{Kind: "created", Collector: result.Collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name})
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,missing_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, generation, result.Collector, resource.ID, resource.Type, resource.Name, raw, hash, 0, now.Format(time.RFC3339Nano))
			case err != nil:
				return nil, err
			case oldHash != hash:
				if baseline == 1 {
					changes = append(changes, model.Change{Kind: "changed", Collector: result.Collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name, Fields: model.Diff(oldRaw, raw)})
				}
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, raw, hash, now.Format(time.RFC3339Nano), generation, result.Collector, resource.ID)
			default:
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, raw, hash, now.Format(time.RFC3339Nano), generation, result.Collector, resource.ID)
			}
			if err != nil {
				return nil, err
			}
		}
		rows, err := tx.QueryContext(ctx, "SELECT resource_id,resource_type,name,missing_count FROM snapshots WHERE generation=? AND collector=?", generation, result.Collector)
		if err != nil {
			return nil, err
		}
		type absent struct {
			id, typ, name string
			missing       int
		}
		var missingRows []absent
		for rows.Next() {
			var a absent
			if err := rows.Scan(&a.id, &a.typ, &a.name, &a.missing); err != nil {
				rows.Close()
				return nil, err
			}
			if _, ok := seen[a.id]; !ok {
				missingRows = append(missingRows, a)
			}
		}
		rows.Close()
		for _, a := range missingRows {
			if a.missing+1 >= 2 {
				if baseline == 1 {
					changes = append(changes, model.Change{Kind: "removed", Collector: result.Collector, ResourceID: a.id, Type: a.typ, Name: a.name})
				}
				_, err = tx.ExecContext(ctx, "DELETE FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, a.id)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET missing_count=missing_count+1 WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, a.id)
			}
			if err != nil {
				return nil, err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified) VALUES(?,?,1,1,?,'',0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,baseline=1,last_success=excluded.last_success,last_error='',failure_count=0,unhealthy_notified=0`, generation, result.Collector, now.Format(time.RFC3339Nano))
		if err != nil {
			return nil, err
		}
	}
	for _, change := range changes {
		raw, _ := json.Marshal(change.Fields)
		_, err = tx.ExecContext(ctx, "INSERT INTO events(generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,?,?,?,?,?,?)", generation, now.Format(time.RFC3339Nano), change.Collector, change.Kind, change.ResourceID, change.Name, raw)
		if err != nil {
			return nil, err
		}
	}
	if len(changes) > 0 {
		payload := digest(changes)
		if err = enqueueOutboxTx(ctx, tx, payload, now.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	var remaining int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1 AND baseline=0", generation).Scan(&remaining)
	if err != nil {
		return nil, err
	}
	var supported int
	_ = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1", generation).Scan(&supported)
	if supported > 0 && remaining == 0 {
		_, err = tx.ExecContext(ctx, "UPDATE settings SET baseline_at=COALESCE(baseline_at,?) WHERE id=1 AND generation=?", now.Format(time.RFC3339Nano), generation)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return changes, nil
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
	if err := enqueueOutboxTx(ctx, tx, payload, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DueOutbox(ctx context.Context, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.id,o.destination_id,o.payload,o.attempts,o.first_attempt,d.name,d.service_url_enc,d.enabled,d.created_at,d.updated_at,COALESCE(d.deleted_at,'')
		FROM outbox o JOIN notification_destinations d ON d.id=o.destination_id
		WHERE o.status='pending' AND o.next_attempt<=? AND d.enabled=1 AND d.deleted_at IS NULL ORDER BY o.id LIMIT ?`, time.Now().UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var item OutboxItem
		var first, encrypted, created, updated, deleted, name string
		var enabled int
		if err := rows.Scan(&item.ID, &item.DestinationID, &item.Payload, &item.Attempts, &first, &name, &encrypted, &enabled, &created, &updated, &deleted); err != nil {
			return nil, err
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

func enqueueOutboxTx(ctx context.Context, tx *sql.Tx, payload, now string) error {
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
		if _, err := tx.ExecContext(ctx, "INSERT INTO outbox(destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(? ,?,'pending',?,?,?)", destinationID, payload, now, now, now); err != nil {
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
	_, err = s.db.ExecContext(ctx, "DELETE FROM outbox WHERE status='delivered' AND delivered_at<?", cutoff)
	return err
}
func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "…"
}

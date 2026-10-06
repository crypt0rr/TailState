package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

// expiryWarningStateMeta stores which expiry warning windows have already
// been sent for each resource, together with the expiry each warning was sent
// for. It lives in the meta table so no schema migration is needed.
const expiryWarningStateMeta = "expiry_warning_state"

// SnapshotRecord is a stored normalized snapshot of one resource.
type SnapshotRecord struct {
	ResourceID string
	Name       string
	Raw        []byte
}

// CollectorSnapshots returns the current normalized snapshots for one
// collector in the given generation. Truncated snapshots are skipped because
// they hold only a size marker instead of the resource fields. The read-only
// pool serves it, so the status page's expiry card and the daily expiry check
// never queue behind a write transaction.
func (s *Store) CollectorSnapshots(ctx context.Context, generation int64, collector string) ([]SnapshotRecord, error) {
	rows, err := s.readDB().QueryContext(ctx, "SELECT resource_id,name,canonical_json FROM snapshots WHERE generation=? AND collector=? AND content_truncated=0 ORDER BY resource_id", generation, collector)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotRecord
	for rows.Next() {
		var record SnapshotRecord
		if err := rows.Scan(&record.ResourceID, &record.Name, &record.Raw); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

// ExpiryOptions is the active monitoring generation with the expiry warning
// windows and tag filter, read without decrypting any credential.
type ExpiryOptions struct {
	Generation  int64
	WarningDays []int
	TagFilter   []string
}

// ExpiryOptions reads the expiry warning options through the read-only pool,
// so the status page's "Expiring soon" card never queues behind a write
// transaction. It returns sql.ErrNoRows on an unconfigured installation.
func (s *Store) ExpiryOptions(ctx context.Context) (ExpiryOptions, error) {
	var out ExpiryOptions
	if err := s.readDB().QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&out.Generation); err != nil {
		return ExpiryOptions{}, err
	}
	var options Settings
	if err := loadMonitoringOptions(ctx, s.readDB(), &options); err != nil {
		return ExpiryOptions{}, err
	}
	out.WarningDays, out.TagFilter = options.ExpiryWarningDays, options.ExpiryTagFilter
	return out, nil
}

// ExpiryWarningState returns the persisted expiry warning state, or an empty
// string when no warning has been recorded yet.
func (s *Store) ExpiryWarningState(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", expiryWarningStateMeta).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

// CommitExpiryWarnings enqueues the expiry warning notifications and stores
// the new warning state in one transaction, so a crash can neither lose a
// warning that was marked as sent nor send a recorded warning twice. Nothing
// is written, and false is returned, when the monitoring generation changed
// while the check was running.
func (s *Store) CommitExpiryWarnings(ctx context.Context, generation int64, messages []notify.Message, state string) (bool, error) {
	type encoded struct{ format, payload string }
	payloads := make([]encoded, 0, len(messages))
	for _, message := range messages {
		payloadFormat, payload, err := notify.EncodePayload(message)
		if err != nil {
			return false, err
		}
		payloads = append(payloads, encoded{payloadFormat, payload})
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var active int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&active); err != nil {
		return false, err
	}
	if active != generation {
		return false, nil
	}
	now := formatTimestamp(time.Now())
	for _, payload := range payloads {
		if err := enqueueOutboxTx(ctx, tx, payload.format, payload.payload, now, 0); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", expiryWarningStateMeta, state); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, storageWriteError(err)
	}
	return true, nil
}

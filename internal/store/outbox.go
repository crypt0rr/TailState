package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

const outboxSelect = `SELECT o.id,COALESCE(o.batch_id,0),o.destination_id,o.payload,o.payload_format,o.attempts,o.first_attempt,
		COALESCE(o.lease_until,''),COALESCE(o.lease_token,''),d.name,d.service_url_enc,d.enabled,d.created_at,d.updated_at,COALESCE(d.deleted_at,''),d.message_format
		FROM outbox o JOIN notification_destinations d ON d.id=o.destination_id`

type outboxScanner interface {
	Scan(dest ...any) error
}

// EnqueueMessage queues a system notification (health, update) for every
// enabled destination. The message is stored format-neutral and rendered for
// each destination's service when it is sent.
func (s *Store) EnqueueMessage(ctx context.Context, message notify.Message) error {
	payloadFormat, payload, err := notify.EncodePayload(message)
	if err != nil {
		return err
	}
	return s.enqueueSystem(ctx, payloadFormat, payload)
}

// EnqueueSystem queues pre-rendered Markdown for every enabled destination;
// it is delivered unchanged.
func (s *Store) EnqueueSystem(ctx context.Context, payload string) error {
	return s.enqueueSystem(ctx, notify.PayloadMarkdown, payload)
}

func (s *Store) enqueueSystem(ctx context.Context, payloadFormat, payload string) error {
	now := formatTimestamp(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := enqueueOutboxTx(ctx, tx, payloadFormat, payload, now, 0); err != nil {
		return err
	}
	return tx.Commit()
}

// ClaimDueOutbox leases due notifications for one delivery worker. Claiming
// changes the row to processing in the same transaction that reads it, so a
// second worker or a restarted process cannot send the same pending row just
// because the first worker is still in flight. Expired leases are returned to
// pending before the next claim; completion and retry methods fence the old
// worker with the lease token. A due row whose destination URL cannot be
// decrypted is dead-lettered instead of claimed, so it cannot block delivery
// to the other destinations.
func (s *Store) ClaimDueOutbox(ctx context.Context, limit int, leases ...time.Duration) ([]OutboxItem, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 64 {
		limit = 64
	}
	lease := outboxLease
	if len(leases) > 0 && leases[0] >= time.Second {
		lease = leases[0]
	}
	now := time.Now().UTC()
	nowValue := formatTimestamp(now)
	leaseValue := formatTimestamp(now.Add(lease))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE outbox
		SET status='pending',lease_until=NULL,lease_token=''
		WHERE status='processing' AND (lease_until IS NULL OR lease_until<=?)`, nowValue); err != nil {
		return nil, err
	}
	// Cleanup normally enforces the retry horizon, but delivery claims can run
	// between cleanup passes (including immediately after a restart). Expired
	// rows must never be sent again just because their next_attempt is due.
	retryCutoff := formatTimestamp(now.Add(-outboxRetryWindow))
	if _, err := tx.ExecContext(ctx, `UPDATE outbox
		SET status='dead',next_attempt=?,lease_until=NULL,lease_token='',
			last_error=CASE WHEN TRIM(last_error)='' THEN 'delivery retry window expired' ELSE last_error END
		WHERE status='pending' AND first_attempt<=?`, nowValue, retryCutoff); err != nil {
		return nil, err
	}
	// Each destination receives its notifications oldest first. A row is
	// claimable only when every older live row for the same destination is
	// also claimable: an older row that is backing off after a failure, or
	// still in flight, holds the destination's younger rows back. Without
	// this, rows that back off independently would be delivered out of
	// order after an outage (a young row's short retry delay expires before
	// an old row's long one). Older claimable rows sort first, so a batch cut
	// by the limit never skips one.
	rows, err := tx.QueryContext(ctx, outboxSelect+`
		WHERE o.status='pending' AND o.next_attempt<=? AND d.enabled=1 AND d.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM outbox p
			WHERE p.destination_id=o.destination_id AND p.id<o.id
			  AND (p.status='processing' OR (p.status='pending' AND p.next_attempt>?)))
		ORDER BY o.id LIMIT ?`, nowValue, nowValue, limit)
	if err != nil {
		return nil, err
	}
	items := make([]OutboxItem, 0, limit)
	var unreadable []*unreadableDestinationError
	for rows.Next() {
		item, scanErr := s.readOutboxItem(rows)
		var urlErr *unreadableDestinationError
		if errors.As(scanErr, &urlErr) {
			unreadable = append(unreadable, urlErr)
			continue
		}
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// A row whose destination URL cannot be decrypted (for example one
	// sealed under a previous master key) can never be sent. It is
	// dead-lettered with a reason naming the destination instead of failing
	// the claim, which would stop delivery to every other destination.
	for _, urlErr := range unreadable {
		if _, err := tx.ExecContext(ctx, `UPDATE outbox
			SET status='dead',next_attempt=?,last_error=?,lease_until=NULL,lease_token=''
			WHERE id=? AND status='pending'`, nowValue, truncate(urlErr.reason(), 500), urlErr.outboxID); err != nil {
			return nil, err
		}
	}
	claimed := make([]OutboxItem, 0, len(items))
	for i := range items {
		token, tokenErr := newOutboxLeaseToken()
		if tokenErr != nil {
			return nil, tokenErr
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE outbox
			SET status='processing',attempts=attempts+1,lease_until=?,lease_token=?
			WHERE id=? AND status='pending'`, leaseValue, token, items[i].ID)
		if updateErr != nil {
			return nil, updateErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return nil, rowsErr
		}
		if changed != 1 {
			continue
		}
		items[i].Attempts++
		items[i].LeaseToken = token
		leaseUntil := now.Add(lease)
		items[i].LeaseUntil = &leaseUntil
		claimed = append(claimed, items[i])
	}
	items = claimed
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	for _, urlErr := range unreadable {
		slog.Warn("notification dead-lettered: destination service URL cannot be decrypted", "outbox_id", urlErr.outboxID, "destination_id", urlErr.destinationID, "error", urlErr.err)
	}
	return items, nil
}

// unreadableDestinationError reports an outbox row whose destination service
// URL cannot be decrypted with the current master key.
type unreadableDestinationError struct {
	outboxID      int64
	destinationID int64
	name          string
	err           error
}

func (e *unreadableDestinationError) Error() string {
	return fmt.Sprintf("decrypt service URL of destination %d: %v", e.destinationID, e.err)
}

func (e *unreadableDestinationError) Unwrap() error { return e.err }

// reason is the dead-letter reason recorded on the outbox row.
func (e *unreadableDestinationError) reason() string {
	return fmt.Sprintf("service URL of destination %d (%s) cannot be decrypted with the current master key; save the destination with its URL again, or disable or remove it", e.destinationID, e.name)
}

func (s *Store) readOutboxItem(scanner outboxScanner) (OutboxItem, error) {
	var item OutboxItem
	var batchID sql.NullInt64
	var first, leaseUntil, encrypted, created, updated, deleted, name, format string
	var enabled int
	if err := scanner.Scan(&item.ID, &batchID, &item.DestinationID, &item.Payload, &item.PayloadFormat, &item.Attempts, &first, &leaseUntil, &item.LeaseToken, &name, &encrypted, &enabled, &created, &updated, &deleted, &format); err != nil {
		return OutboxItem{}, err
	}
	if batchID.Valid {
		item.BatchID = batchID.Int64
	}
	var err error
	item.FirstAttempt, err = time.Parse(time.RFC3339Nano, first)
	if err != nil {
		return OutboxItem{}, fmt.Errorf("parse outbox first attempt timestamp: %w", err)
	}
	if strings.TrimSpace(leaseUntil) != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, leaseUntil)
		if parseErr != nil {
			return OutboxItem{}, fmt.Errorf("parse outbox lease timestamp: %w", parseErr)
		}
		item.LeaseUntil = &value
	}
	item.Destination = NotificationDestination{ID: item.DestinationID, Name: name, Enabled: enabled == 1, Format: format}
	// Deleted destinations have their URL scrubbed; claims never select them,
	// but an empty value must not be treated as a decryption failure.
	if encrypted != "" {
		item.Destination.ServiceURL, err = s.box.Open(destinationBinding(item.DestinationID), encrypted)
		if err != nil {
			return OutboxItem{}, &unreadableDestinationError{outboxID: item.ID, destinationID: item.DestinationID, name: name, err: err}
		}
	}
	item.Destination.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return OutboxItem{}, fmt.Errorf("parse outbox destination created timestamp: %w", err)
	}
	item.Destination.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return OutboxItem{}, fmt.Errorf("parse outbox destination updated timestamp: %w", err)
	}
	if deleted != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, deleted)
		if parseErr != nil {
			return OutboxItem{}, fmt.Errorf("parse outbox destination deleted timestamp: %w", parseErr)
		}
		item.Destination.DeletedAt = &value
	}
	return item, nil
}

func enqueueOutboxTx(ctx context.Context, tx *sql.Tx, payloadFormat, payload, now string, batchID int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL ORDER BY id")
	if err != nil {
		return err
	}
	for rows.Next() {
		var destinationID int64
		if err := rows.Scan(&destinationID); err != nil {
			rows.Close()
			return err
		}
		var batchValue any
		if batchID > 0 {
			batchValue = batchID
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,payload_format,status,next_attempt,first_attempt,created_at) VALUES(?,?,?,?,'pending',?,?,?)", batchValue, destinationID, payload, payloadFormat, now, now, now); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

// DeliveredClaimed completes only the exact delivery attempt returned by
// ClaimDueOutbox. A worker whose lease expired cannot complete a newer attempt
// for the same row.
func (s *Store) DeliveredClaimed(ctx context.Context, item OutboxItem) error {
	_, err := s.DeliveredClaimedResult(ctx, item)
	return err
}

// DeliveredClaimedResult completes only the exact delivery attempt returned
// by ClaimDueOutbox and reports whether the lease token still owned the row.
// A false result means another worker reclaimed or finalized the row while the
// sender was in flight.
func (s *Store) DeliveredClaimedResult(ctx context.Context, item OutboxItem) (bool, error) {
	if item.ID <= 0 || strings.TrimSpace(item.LeaseToken) == "" {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, "UPDATE outbox SET status='delivered',delivered_at=?,last_error='',lease_until=NULL,lease_token='' WHERE id=? AND status='processing' AND lease_token=?", formatTimestamp(time.Now()), item.ID, item.LeaseToken)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

// RetryClaimed requeues or dead-letters only the exact delivery attempt that
// failed. The attempt counter was incremented when the row was claimed.
func (s *Store) RetryClaimed(ctx context.Context, item OutboxItem, next time.Time, message string, dead bool) error {
	_, err := s.RetryClaimedResult(ctx, item, next, message, dead)
	return err
}

// RetryClaimedResult requeues or dead-letters only the exact delivery attempt
// that failed and reports whether the lease token still owned the row.
func (s *Store) RetryClaimedResult(ctx context.Context, item OutboxItem, next time.Time, message string, dead bool) (bool, error) {
	if item.ID <= 0 || strings.TrimSpace(item.LeaseToken) == "" {
		return false, nil
	}
	message = notify.SafeDeliveryMessage(message)
	status := "pending"
	if dead {
		status = "dead"
	}
	result, err := s.db.ExecContext(ctx, "UPDATE outbox SET status=?,next_attempt=?,last_error=?,lease_until=NULL,lease_token='' WHERE id=? AND status='processing' AND lease_token=?", status, formatTimestamp(next), truncate(message, 500), item.ID, item.LeaseToken)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

// ReleaseClaimed returns a claimed row to pending without counting an
// attempt. The delivery worker uses it for a destination's younger rows in a
// batch after an older row for that destination failed: they were never sent,
// and the failed row's backoff now holds them back so they stay in order.
// It reports whether the lease token still owned the row.
func (s *Store) ReleaseClaimed(ctx context.Context, item OutboxItem) (bool, error) {
	if item.ID <= 0 || strings.TrimSpace(item.LeaseToken) == "" {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, "UPDATE outbox SET status='pending',attempts=MAX(attempts-1,0),lease_until=NULL,lease_token='' WHERE id=? AND status='processing' AND lease_token=?", item.ID, item.LeaseToken)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

// RenewClaimed extends the lease for an in-flight delivery when the caller
// still owns the lease token. It returns false when another worker has already
// reclaimed or finalized the row.
func (s *Store) RenewClaimed(ctx context.Context, item OutboxItem, leases ...time.Duration) (bool, error) {
	if item.ID <= 0 || strings.TrimSpace(item.LeaseToken) == "" {
		return false, nil
	}
	lease := outboxLease
	if len(leases) > 0 && leases[0] >= time.Second {
		lease = leases[0]
	}
	leaseUntil := formatTimestamp(time.Now().UTC().Add(lease))
	result, err := s.db.ExecContext(ctx, "UPDATE outbox SET lease_until=? WHERE id=? AND status='processing' AND lease_token=?", leaseUntil, item.ID, item.LeaseToken)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

func newOutboxLeaseToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate outbox lease token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

// ErrDestinationDisabled is returned when dead letters are retried for a
// destination that is disabled; re-enable it first so the retry is explicit.
var ErrDestinationDisabled = errors.New("notification destination is disabled")

// DestinationDelivery summarizes the outbox for one active destination.
// RetryableDead counts the dead letters RetryDeadOutbox would requeue.
type DestinationDelivery struct {
	ID            int64
	Name          string
	Enabled       bool
	Pending       int
	Processing    int
	Dead          int
	RetryableDead int
	// ServiceURLUnreadable reports that the destination's service URL cannot
	// be decrypted with the current master key, so its notifications are
	// dead-lettered until it is saved with its URL again.
	ServiceURLUnreadable bool
}

// retryableDeadOutbox selects dead letters that may be requeued. Rows
// dead-lettered because the monitoring identity changed, or whose batch
// belongs to a previous settings generation, describe another tailnet or
// OAuth identity and stay dead; system notifications (no batch) are eligible.
// The column prefix lets the same predicate serve a join and an UPDATE.
func retryableDeadOutbox(prefix string) string {
	return prefix + `status='dead' AND ` + prefix + `last_error<>'monitoring identity changed' AND (` + prefix + `batch_id IS NULL OR NOT EXISTS (
		SELECT 1 FROM event_batches eb WHERE eb.id=` + prefix + `batch_id AND eb.generation<>(SELECT generation FROM settings WHERE id=1)))`
}

// DestinationDeliveries returns per-destination delivery counts for every
// active destination, including destinations with an empty outbox, through
// the read-only pool so the status page never waits behind a write.
func (s *Store) DestinationDeliveries(ctx context.Context) ([]DestinationDelivery, error) {
	rows, err := s.readDB().QueryContext(ctx, `SELECT d.id,d.name,d.enabled,d.service_url_enc,
		COALESCE(SUM(o.status='pending'),0),COALESCE(SUM(o.status='processing'),0),COALESCE(SUM(o.status='dead'),0),
		COALESCE(SUM(CASE WHEN `+retryableDeadOutbox("o.")+` THEN 1 ELSE 0 END),0)
		FROM notification_destinations d LEFT JOIN outbox o ON o.destination_id=d.id
		WHERE d.deleted_at IS NULL GROUP BY d.id ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DestinationDelivery
	for rows.Next() {
		var delivery DestinationDelivery
		var enabled int
		var encrypted string
		if err := rows.Scan(&delivery.ID, &delivery.Name, &enabled, &encrypted, &delivery.Pending, &delivery.Processing, &delivery.Dead, &delivery.RetryableDead); err != nil {
			return nil, err
		}
		delivery.Enabled = enabled == 1
		if encrypted != "" {
			_, openErr := s.box.Open(destinationBinding(delivery.ID), encrypted)
			delivery.ServiceURLUnreadable = openErr != nil
		}
		out = append(out, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, rows.Close()
}

// RetryDeadOutbox requeues the retryable dead letters of one enabled,
// active destination with a fresh 24-hour delivery window: attempts restart
// at zero, the first attempt is now, and the rows are due immediately. It
// returns the number of requeued rows. Delivery stays at-least-once; a row
// whose provider accepted the message before it was dead-lettered may be
// delivered again.
func (s *Store) RetryDeadOutbox(ctx context.Context, destinationID int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM notification_destinations WHERE id=? AND deleted_at IS NULL", destinationID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("notification destination not found")
		}
		return 0, err
	}
	if enabled != 1 {
		return 0, ErrDestinationDisabled
	}
	now := formatTimestamp(time.Now())
	result, err := tx.ExecContext(ctx, `UPDATE outbox
		SET status='pending',attempts=0,first_attempt=?,next_attempt=?,last_error='',lease_until=NULL,lease_token='',delivered_at=NULL
		WHERE destination_id=? AND `+retryableDeadOutbox(""), now, now, destinationID)
	if err != nil {
		return 0, err
	}
	requeued, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return requeued, tx.Commit()
}

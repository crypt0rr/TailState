package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

const outboxSelect = `SELECT o.id,COALESCE(o.batch_id,0),o.destination_id,o.payload,o.attempts,o.first_attempt,
		COALESCE(o.lease_until,''),COALESCE(o.lease_token,''),d.name,d.service_url_enc,d.enabled,d.created_at,d.updated_at,COALESCE(d.deleted_at,'')
		FROM outbox o JOIN notification_destinations d ON d.id=o.destination_id`

type outboxScanner interface {
	Scan(dest ...any) error
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

// ClaimDueOutbox leases due notifications for one delivery worker. Claiming
// changes the row to processing in the same transaction that reads it, so a
// second worker or a restarted process cannot send the same pending row just
// because the first worker is still in flight. Expired leases are returned to
// pending before the next claim; completion and retry methods fence the old
// worker with the lease token.
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
	nowValue := now.Format(time.RFC3339Nano)
	leaseValue := now.Add(lease).Format(time.RFC3339Nano)
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
	retryCutoff := now.Add(-outboxRetryWindow).Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE outbox
		SET status='dead',next_attempt=?,lease_until=NULL,lease_token='',
			last_error=CASE WHEN TRIM(last_error)='' THEN 'delivery retry window expired' ELSE last_error END
		WHERE status='pending' AND first_attempt<=?`, nowValue, retryCutoff); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, outboxSelect+`
		WHERE o.status='pending' AND o.next_attempt<=? AND d.enabled=1 AND d.deleted_at IS NULL
		ORDER BY o.id LIMIT ?`, nowValue, limit)
	if err != nil {
		return nil, err
	}
	items := make([]OutboxItem, 0, limit)
	for rows.Next() {
		item, scanErr := s.readOutboxItem(rows)
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
	return items, nil
}

func (s *Store) readOutboxItem(scanner outboxScanner) (OutboxItem, error) {
	var item OutboxItem
	var batchID sql.NullInt64
	var first, leaseUntil, encrypted, created, updated, deleted, name string
	var enabled int
	if err := scanner.Scan(&item.ID, &batchID, &item.DestinationID, &item.Payload, &item.Attempts, &first, &leaseUntil, &item.LeaseToken, &name, &encrypted, &enabled, &created, &updated, &deleted); err != nil {
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
	item.Destination = NotificationDestination{ID: item.DestinationID, Name: name, Enabled: enabled == 1}
	item.Destination.ServiceURL, err = s.box.Decrypt(encrypted)
	if err != nil {
		return OutboxItem{}, err
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

func enqueueOutboxTx(ctx context.Context, tx *sql.Tx, payload, now string, batchID int64) error {
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
		if _, err := tx.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(?,?,?,'pending',?,?,?)", batchValue, destinationID, payload, now, now, now); err != nil {
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
	if item.ID <= 0 || strings.TrimSpace(item.LeaseToken) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status='delivered',delivered_at=?,last_error='',lease_until=NULL,lease_token='' WHERE id=? AND status='processing' AND lease_token=?", time.Now().UTC().Format(time.RFC3339Nano), item.ID, item.LeaseToken)
	return err
}

// RetryClaimed requeues or dead-letters only the exact delivery attempt that
// failed. The attempt counter was incremented when the row was claimed.
func (s *Store) RetryClaimed(ctx context.Context, item OutboxItem, next time.Time, message string, dead bool) error {
	if item.ID <= 0 || strings.TrimSpace(item.LeaseToken) == "" {
		return nil
	}
	message = notify.SafeDeliveryMessage(message)
	status := "pending"
	if dead {
		status = "dead"
	}
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status=?,next_attempt=?,last_error=?,lease_until=NULL,lease_token='' WHERE id=? AND status='processing' AND lease_token=?", status, next.UTC().Format(time.RFC3339Nano), truncate(message, 500), item.ID, item.LeaseToken)
	return err
}

func newOutboxLeaseToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate outbox lease token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

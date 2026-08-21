package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

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
		item.FirstAttempt, err = time.Parse(time.RFC3339Nano, first)
		if err != nil {
			return nil, fmt.Errorf("parse outbox first attempt timestamp: %w", err)
		}
		item.Destination = NotificationDestination{ID: item.DestinationID, Name: name, Enabled: enabled == 1}
		item.Destination.ServiceURL, err = s.box.Decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		item.Destination.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("parse outbox destination created timestamp: %w", err)
		}
		item.Destination.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			return nil, fmt.Errorf("parse outbox destination updated timestamp: %w", err)
		}
		if deleted != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, deleted)
			if parseErr != nil {
				return nil, fmt.Errorf("parse outbox destination deleted timestamp: %w", parseErr)
			}
			item.Destination.DeletedAt = &value
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
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
func (s *Store) Delivered(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status='delivered',delivered_at=?,last_error='' WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}
func (s *Store) Retry(ctx context.Context, id int64, next time.Time, message string, dead bool) error {
	// Persist only a provider-independent reason. The error string can come
	// from an arbitrary sender and may contain response bodies or credentials;
	// destination-specific redaction alone cannot make that text safe.
	message = notify.SafeDeliveryMessage(message)
	status := "pending"
	if dead {
		status = "dead"
	}
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status=?,attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?", status, next.UTC().Format(time.RFC3339Nano), truncate(message, 500), id)
	return err
}

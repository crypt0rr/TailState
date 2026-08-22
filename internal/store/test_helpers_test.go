package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

// testApplyBatch keeps slice-oriented assertions concise without keeping a
// compatibility method in the Store API. Live callers should use
// ApplyBatchWithBatch so trigger correlation and batch metadata remain visible.
func testApplyBatch(s *Store, ctx context.Context, generation int64, results []model.Collected, digest func([]model.Change) string) ([]model.Change, error) {
	batch, err := s.ApplyBatchWithBatch(ctx, generation, results, digest)
	return batch.Changes, err
}

// The helpers below intentionally exist only in the store package's test
// build. Runtime delivery and trigger processing use the leased APIs; these
// pending-only transitions are retained solely for focused persistence tests
// that need to inspect or seed a row without starting the monitor.
func testDueOutbox(s *Store, ctx context.Context, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, outboxSelect+`
		WHERE o.status='pending' AND o.next_attempt<=? AND d.enabled=1 AND d.deleted_at IS NULL ORDER BY o.id LIMIT ?`, time.Now().UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		item, err := s.readOutboxItem(rows)
		if err != nil {
			return nil, err
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

func testDelivered(s *Store, ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status='delivered',delivered_at=?,last_error='' WHERE id=? AND status='pending'", time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func testRetry(s *Store, ctx context.Context, id int64, next time.Time, message string, dead bool) error {
	message = notify.SafeDeliveryMessage(message)
	status := "pending"
	if dead {
		status = "dead"
	}
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status=?,attempts=attempts+1,next_attempt=?,last_error=? WHERE id=? AND status='pending'", status, next.UTC().Format(time.RFC3339Nano), truncate(message, 500), id)
	return err
}

func testCompleteWebhookTriggers(s *Store, ctx context.Context, ids []int64) error {
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
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status='processed',processed_at=?,lease_until=NULL,lease_token='',last_error='' WHERE id=? AND status IN ('pending','processing')", now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func testRetryWebhookTriggers(s *Store, ctx context.Context, ids []int64, next time.Time, message string) error {
	ids = uniquePositiveIDs(ids)
	if len(ids) == 0 {
		return nil
	}
	message = truncate(strings.TrimSpace(message), 500)
	if message != "" {
		message = notify.SafeDeliveryMessage(message)
	}
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
		receivedAt, parseErr := parseWebhookTimestamp(received, "received_at")
		if parseErr != nil {
			return parseErr
		}
		dead := now.Sub(receivedAt) >= webhookTriggerRetryWindow
		status := "pending"
		attempt := next.UTC()
		lastError := message
		if dead {
			status = "dead"
			attempt = now
			if lastError == "" {
				lastError = "reconciliation retry window expired"
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status=?,next_attempt_at=?,lease_until=NULL,lease_token='',last_error=? WHERE id=? AND status IN ('pending','processing')", status, attempt.Format(time.RFC3339Nano), lastError, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

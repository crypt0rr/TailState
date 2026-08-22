package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
)

// NotificationDestination is an encrypted, administrator-managed delivery
// endpoint. Deleted destinations remain in the database so historical
// deliveries can still be audited.
type NotificationDestination struct {
	ID         int64
	Name       string
	ServiceURL string
	Enabled    bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
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
		d.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("parse destination created timestamp: %w", err)
		}
		d.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			return nil, fmt.Errorf("parse destination updated timestamp: %w", err)
		}
		if deleted != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, deleted)
			if parseErr != nil {
				return nil, fmt.Errorf("parse destination deleted timestamp: %w", parseErr)
			}
			d.DeletedAt = &value
		}
		out = append(out, d)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := upsertDestinationTx(ctx, tx, s.box, destination.ID, destination.Name, destination.ServiceURL, destination.Enabled)
	if err != nil {
		return 0, err
	}
	if !destination.Enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination disabled',lease_until=NULL,lease_token='' WHERE destination_id=? AND status IN ('pending','processing')", id); err != nil {
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
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("notification destination not found")
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination disabled',lease_until=NULL,lease_token='' WHERE destination_id=? AND status IN ('pending','processing')", id); err != nil {
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
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("notification destination not found")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination removed',lease_until=NULL,lease_token='' WHERE destination_id=? AND status IN ('pending','processing')", id); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertDestinationTx(ctx context.Context, tx *sql.Tx, box *secret.Box, id int64, name, serviceURL string, enabled bool) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if id > 0 {
		var existingEncoded string
		if err := tx.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=? AND deleted_at IS NULL", id).Scan(&existingEncoded); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, errors.New("notification destination not found")
			}
			return 0, err
		}
		encoded := existingEncoded
		if existing, decryptErr := box.Decrypt(existingEncoded); decryptErr != nil || existing != serviceURL {
			var err error
			encoded, err = box.Encrypt(serviceURL)
			if err != nil {
				return 0, err
			}
		}
		result, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET name=?,service_url_enc=?,enabled=?,updated_at=? WHERE id=? AND deleted_at IS NULL", name, encoded, boolInt(enabled), now, id)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, errors.New("notification destination not found")
		}
		return id, nil
	}
	encoded, err := box.Encrypt(serviceURL)
	if err != nil {
		return 0, err
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

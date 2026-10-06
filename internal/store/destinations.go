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
	// Routing selects the changes this destination receives. It is read by
	// ListDestinations and written by SetDestinationRouting; SaveDestination
	// leaves it unchanged.
	Routing RoutingRules
	// Format overrides the message format chosen from the URL scheme
	// (notify.FormatAuto when empty). It is written by SetDestinationFormat.
	Format string
}

// ListDestinations returns active notification destinations. Pass true to
// include soft-deleted destinations; their service URL was scrubbed when they
// were deleted, so they are returned with an empty ServiceURL.
func (s *Store) ListDestinations(ctx context.Context, includeDeleted ...bool) ([]NotificationDestination, error) {
	query := "SELECT id,name,service_url_enc,enabled,created_at,updated_at,COALESCE(deleted_at,''),route_min_severity,route_include_collectors,route_exclude_collectors,route_change_kinds,message_format FROM notification_destinations"
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
		var minSeverity, include, exclude, kinds string
		var enabled int
		if err := rows.Scan(&d.ID, &d.Name, &encrypted, &enabled, &created, &updated, &deleted, &minSeverity, &include, &exclude, &kinds, &d.Format); err != nil {
			return nil, err
		}
		d.Routing = routingFromColumns(minSeverity, include, exclude, kinds)
		if encrypted != "" {
			d.ServiceURL, err = s.box.Open(destinationBinding(d.ID), encrypted)
			if err != nil {
				return nil, err
			}
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
	now := formatTimestamp(time.Now())
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

// DeleteDestination soft-deletes a destination, scrubs its encrypted service
// URL, and dead-letters its pending notifications. The name and historical
// delivery rows remain available for audit and retention, but an operator who
// deletes a destination because its URL leaked must not leave that credential
// recoverable from later backups by anyone holding the master key.
func (s *Store) DeleteDestination(ctx context.Context, id int64) error {
	return withSecureDelete(ctx, s.db, func(tx *sql.Tx) error {
		now := formatTimestamp(time.Now())
		result, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET enabled=0,service_url_enc='',deleted_at=?,updated_at=? WHERE id=? AND deleted_at IS NULL", now, now, id)
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
		_, err = tx.ExecContext(ctx, "UPDATE outbox SET status='dead',last_error='destination removed',lease_until=NULL,lease_token='' WHERE destination_id=? AND status IN ('pending','processing')", id)
		return err
	})
}

// withSecureDelete runs fn in a transaction on one pinned connection with
// SQLite's secure_delete enabled, so content removed by the transaction is
// overwritten in the freed page space instead of lingering in the database
// file. The pragma is per connection and is restored before the connection
// returns to the pool to keep ordinary retention deletes cheap.
func withSecureDelete(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA secure_delete=ON"); err != nil {
		return err
	}
	defer func() {
		if _, resetErr := conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA secure_delete=OFF"); resetErr != nil && err == nil {
			err = resetErr
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertDestinationTx(ctx context.Context, tx *sql.Tx, box *secret.Box, id int64, name, serviceURL string, enabled bool) (int64, error) {
	now := formatTimestamp(time.Now())
	if id > 0 {
		var existingEncoded string
		if err := tx.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=? AND deleted_at IS NULL", id).Scan(&existingEncoded); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, errors.New("notification destination not found")
			}
			return 0, err
		}
		encoded := existingEncoded
		// Reuse the stored ciphertext only when it is already a bound v2
		// envelope for this row; an unchanged legacy value is upgraded.
		if existing, decryptErr := box.Open(destinationBinding(id), existingEncoded); decryptErr != nil || existing != serviceURL || !secret.IsCurrentEnvelope(existingEncoded) {
			var err error
			encoded, err = box.Seal(destinationBinding(id), serviceURL)
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
	return insertDestinationTx(ctx, tx, box, name, serviceURL, enabled, now)
}

// insertDestinationTx creates a destination row and then seals its URL with
// the row's binding, which depends on the ID SQLite assigns. Both writes are
// in the caller's transaction, so no row is ever committed without its URL.
func insertDestinationTx(ctx context.Context, tx *sql.Tx, box *secret.Box, name, serviceURL string, enabled bool, now string) (int64, error) {
	result, err := tx.ExecContext(ctx, "INSERT INTO notification_destinations(name,service_url_enc,enabled,created_at,updated_at) VALUES(?,'',?,?,?)", name, boolInt(enabled), now, now)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	encoded, err := box.Seal(destinationBinding(id), serviceURL)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc=? WHERE id=?", encoded, id); err != nil {
		return 0, err
	}
	return id, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

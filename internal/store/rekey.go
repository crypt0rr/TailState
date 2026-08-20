package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// Rekey re-encrypts every value protected by the database master key in one
// transaction. The evidence signing key material is copied, not regenerated,
// so previously exported evidence remains verifiable after rotation.
//
// Callers should stop the serving process before invoking this operation. The
// store swaps to newBox only after the transaction commits successfully.
func (s *Store) Rekey(ctx context.Context, newBox *secret.Box) error {
	if newBox == nil {
		return errors.New("new master key is required")
	}
	var keyCheck string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='master_key_check'").Scan(&keyCheck); err != nil {
		return fmt.Errorf("read master key check: %w", err)
	}
	plain, err := s.box.Decrypt(keyCheck)
	if err != nil || plain != "tailstate-master-key-check" {
		return errors.New("current master key does not match this TailState database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin master-key rotation: %w", err)
	}
	defer tx.Rollback()

	reencrypt := func(value string) (string, error) {
		if value == "" {
			return "", nil
		}
		decoded, decryptErr := s.box.Decrypt(value)
		if decryptErr != nil {
			return "", decryptErr
		}
		return newBox.Encrypt(decoded)
	}

	var settings struct {
		id      int64
		oauth   string
		legacy  string
		webhook string
	}
	err = tx.QueryRowContext(ctx, "SELECT id,oauth_secret_enc,mattermost_url_enc,COALESCE(webhook_secret_enc,'') FROM settings WHERE id=1").Scan(&settings.id, &settings.oauth, &settings.legacy, &settings.webhook)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read encrypted settings: %w", err)
	}
	if err == nil {
		settings.oauth, err = reencrypt(settings.oauth)
		if err != nil {
			return fmt.Errorf("re-encrypt OAuth secret: %w", err)
		}
		settings.legacy, err = reencrypt(settings.legacy)
		if err != nil {
			return fmt.Errorf("re-encrypt legacy notification URL: %w", err)
		}
		settings.webhook, err = reencrypt(settings.webhook)
		if err != nil {
			return fmt.Errorf("re-encrypt webhook secret: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE settings SET oauth_secret_enc=?,mattermost_url_enc=?,webhook_secret_enc=? WHERE id=1", settings.oauth, settings.legacy, settings.webhook); err != nil {
			return fmt.Errorf("store re-encrypted settings: %w", err)
		}
	}

	rows, err := tx.QueryContext(ctx, "SELECT id,service_url_enc FROM notification_destinations ORDER BY id")
	if err != nil {
		return fmt.Errorf("read encrypted notification destinations: %w", err)
	}
	type destinationEnvelope struct {
		id  int64
		enc string
	}
	var destinations []destinationEnvelope
	for rows.Next() {
		var destination destinationEnvelope
		if err := rows.Scan(&destination.id, &destination.enc); err != nil {
			rows.Close()
			return fmt.Errorf("scan encrypted notification destination: %w", err)
		}
		destinations = append(destinations, destination)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read encrypted notification destinations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close encrypted notification destinations: %w", err)
	}
	for _, destination := range destinations {
		encoded, err := reencrypt(destination.enc)
		if err != nil {
			return fmt.Errorf("re-encrypt notification destination %d: %w", destination.id, err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc=? WHERE id=?", encoded, destination.id); err != nil {
			return fmt.Errorf("store notification destination %d: %w", destination.id, err)
		}
	}

	for _, key := range []string{"master_key_check", evidenceSigningPrivateKeyMeta} {
		var encoded string
		err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", key).Scan(&encoded)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read encrypted metadata %s: %w", key, err)
		}
		rotated, err := reencrypt(encoded)
		if err != nil {
			return fmt.Errorf("re-encrypt metadata %s: %w", key, err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE meta SET value=? WHERE key=?", rotated, key); err != nil {
			return fmt.Errorf("store re-encrypted metadata %s: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit master-key rotation: %w", err)
	}
	s.box = newBox
	return nil
}

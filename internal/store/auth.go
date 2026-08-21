package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin").Scan(&n)
	return n > 0, err
}

func (s *Store) NewSetupToken(ctx context.Context) (string, error) {
	return s.issueAuthToken(ctx, "setup", "setup_token_hash", setupTokenLifetime)
}

func (s *Store) Claim(ctx context.Context, token, password string) error {
	if err := s.validateAuthToken(ctx, "setup", token, "setup token"); err != nil {
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
	var want, expires string
	if err := tx.QueryRowContext(ctx, "SELECT token_hash,expires_at FROM auth_tokens WHERE kind='setup' ORDER BY created_at DESC LIMIT 1").Scan(&want, &expires); err != nil {
		return errors.New("setup token is unavailable")
	}
	got := secret.HashToken(token)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errors.New("invalid setup token")
	}
	if expiry, err := time.Parse(time.RFC3339Nano, expires); err != nil || !expiry.After(time.Now().UTC()) {
		return errors.New("setup token has expired")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "INSERT INTO admin(id,password_hash,created_at,updated_at) VALUES(1,?,?,?)", hash, now, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_tokens WHERE token_hash=? AND kind='setup'", want); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM meta WHERE key='setup_token_hash'"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) issueAuthToken(ctx context.Context, kind, legacyKey string, lifetime time.Duration) (string, error) {
	token, err := secret.Token(24)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// Check the administrator state inside the issuing transaction. Without this
	// transactional guard a concurrent setup claim could finish between a
	// caller's state check and token insertion, leaving a fresh setup token
	// after the installation was claimed.
	if kind == "setup" || kind == "reset" {
		var admins int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin").Scan(&admins); err != nil {
			return "", err
		}
		if kind == "setup" && admins > 0 {
			return "", errors.New("administrator is already configured")
		}
		if kind == "reset" && admins == 0 {
			return "", errors.New("administrator is not configured")
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_tokens WHERE kind=?", kind); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO auth_tokens(token_hash,kind,created_at,expires_at) VALUES(?,?,?,?)", secret.HashToken(token), kind, now.Format(time.RFC3339Nano), now.Add(lifetime).Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", legacyKey, secret.HashToken(token)); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) validateAuthToken(ctx context.Context, kind, token, label string) error {
	var want, expires string
	if err := s.db.QueryRowContext(ctx, "SELECT token_hash,expires_at FROM auth_tokens WHERE kind=? ORDER BY created_at DESC LIMIT 1", kind).Scan(&want, &expires); err != nil {
		return errors.New(label + " is unavailable")
	}
	if subtle.ConstantTimeCompare([]byte(secret.HashToken(token)), []byte(want)) != 1 {
		return errors.New("invalid " + label)
	}
	if expiry, err := time.Parse(time.RFC3339Nano, expires); err != nil || !expiry.After(time.Now().UTC()) {
		return errors.New(label + " has expired")
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_tokens WHERE kind='reset'"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM meta WHERE key='reset_token_hash'"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) NewResetToken(ctx context.Context) (string, error) {
	return s.issueAuthToken(ctx, "reset", "reset_token_hash", resetTokenLifetime)
}
func (s *Store) ResetWithToken(ctx context.Context, token, password string) error {
	if err := s.validateAuthToken(ctx, "reset", token, "reset token"); err != nil {
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
	var want, expires string
	if err := tx.QueryRowContext(ctx, "SELECT token_hash,expires_at FROM auth_tokens WHERE kind='reset' ORDER BY created_at DESC LIMIT 1").Scan(&want, &expires); err != nil {
		return errors.New("reset token is unavailable")
	}
	if subtle.ConstantTimeCompare([]byte(secret.HashToken(token)), []byte(want)) != 1 {
		return errors.New("invalid reset token")
	}
	if expiry, err := time.Parse(time.RFC3339Nano, expires); err != nil || !expiry.After(time.Now().UTC()) {
		return errors.New("reset token has expired")
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_tokens WHERE token_hash=? AND kind='reset'", want); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM meta WHERE key='reset_token_hash'"); err != nil {
		return err
	}
	return tx.Commit()
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

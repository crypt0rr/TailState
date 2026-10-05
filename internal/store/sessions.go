package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"sort"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// Session lifetimes. A session ends SessionLifetime after sign-in, or after
// SessionIdleTimeout without user activity, whichever comes first. Requests
// that are not user activity (the status page's automatic refresh) are
// validated without extending the idle window.
const (
	SessionLifetime    = 12 * time.Hour
	SessionIdleTimeout = 60 * time.Minute
	// sessionTouchInterval bounds last-seen writes to one per session per
	// interval, so browsing does not turn every page view into a write.
	sessionTouchInterval = time.Minute
	// sessionRefLength is the number of characters of the session token hash
	// shown in the session list and recorded in the administrative audit log.
	sessionRefLength  = 12
	maxListedSessions = 200
	// bookkeepingWriteTimeout bounds the best-effort writes made while
	// authenticating a request (the last-seen touch and the removal of an
	// idle session), so a request that only reads is never held for the
	// whole busy timeout while another writer owns the database.
	bookkeepingWriteTimeout = 250 * time.Millisecond
)

// bookkeepingWrite runs a best-effort write with bookkeepingWriteTimeout.
func (s *Store) bookkeepingWrite(ctx context.Context, query string, args ...any) error {
	ctx, cancel := context.WithTimeout(ctx, bookkeepingWriteTimeout)
	defer cancel()
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// SessionInfo describes one active session without its secret material. Ref
// is a prefix of the stored token hash: enough to tell sessions apart and to
// correlate audit records, useless for authentication.
type SessionInfo struct {
	Ref        string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IdleUntil  time.Time
	Current    bool
}

// SessionRef returns the public reference of a session token.
func SessionRef(token string) string {
	if token == "" {
		return ""
	}
	return secret.HashToken(token)[:sessionRefLength]
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
	nowValue := now.Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?)", secret.HashToken(token), secret.HashToken(csrf), now.Add(SessionLifetime).Format(time.RFC3339Nano), nowValue, nowValue)
	return
}

// ValidateSession checks a session as user activity; see
// AuthenticateSession.
func (s *Store) ValidateSession(ctx context.Context, token, csrf string, requireCSRF bool) bool {
	_, ok := s.AuthenticateSession(ctx, token, csrf, requireCSRF, true)
	return ok
}

// AuthenticateSession validates a session token (and, when requireCSRF is
// set, its CSRF token) against both the absolute lifetime and the idle
// timeout. When activity is true the session's last-seen time is advanced;
// automatic page refreshes pass false so an unattended browser tab cannot
// keep a session alive. A session found idle is deleted.
func (s *Store) AuthenticateSession(ctx context.Context, token, csrf string, requireCSRF, activity bool) (SessionInfo, bool) {
	if token == "" {
		return SessionInfo{}, false
	}
	hash := secret.HashToken(token)
	var csrfHash, expires, created, lastSeen string
	// The lookup is a pure read on the read-only pool, so an authenticated
	// page does not wait behind a write. Every statement reads the latest
	// committed snapshot, so a committed logout, password change, or reset
	// is observed immediately. Only the idle deletion and the throttled
	// last-seen touch below use the writer.
	if s.readDB().QueryRowContext(ctx, "SELECT csrf_hash,expires_at,created_at,last_seen_at FROM sessions WHERE token_hash=?", hash).Scan(&csrfHash, &expires, &created, &lastSeen) != nil {
		return SessionInfo{}, false
	}
	now := time.Now().UTC()
	info, err := sessionInfo(hash, expires, created, lastSeen)
	if err != nil || !info.ExpiresAt.After(now) {
		return SessionInfo{}, false
	}
	if !info.IdleUntil.After(now) {
		_ = s.bookkeepingWrite(ctx, "DELETE FROM sessions WHERE token_hash=?", hash)
		return SessionInfo{}, false
	}
	if requireCSRF && subtle.ConstantTimeCompare([]byte(secret.HashToken(csrf)), []byte(csrfHash)) != 1 {
		return SessionInfo{}, false
	}
	if activity && now.Sub(info.LastSeenAt) >= sessionTouchInterval {
		// A failed touch only shortens the idle window; it never grants
		// access, so the error is not surfaced to the request.
		if err := s.bookkeepingWrite(ctx, "UPDATE sessions SET last_seen_at=? WHERE token_hash=?", now.Format(time.RFC3339Nano), hash); err == nil {
			info.LastSeenAt = now
			info.IdleUntil = now.Add(SessionIdleTimeout)
		}
	}
	info.Current = true
	return info, true
}

func sessionInfo(hash, expires, created, lastSeen string) (SessionInfo, error) {
	info := SessionInfo{Ref: hash[:min(len(hash), sessionRefLength)]}
	var err error
	if info.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires); err != nil {
		return SessionInfo{}, err
	}
	if info.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return SessionInfo{}, err
	}
	// Sessions created before schema v15 have no last-seen time; the
	// migration backfills it from created_at, and this fallback covers a row
	// written without one afterwards.
	info.LastSeenAt = info.CreatedAt
	if lastSeen != "" {
		if info.LastSeenAt, err = time.Parse(time.RFC3339Nano, lastSeen); err != nil {
			return SessionInfo{}, err
		}
	}
	info.IdleUntil = info.LastSeenAt.Add(SessionIdleTimeout)
	return info, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) {
	_, _ = s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", secret.HashToken(token))
}

// ListSessions returns the sessions that are still valid, most recently
// active first, marking the one that belongs to currentToken.
func (s *Store) ListSessions(ctx context.Context, currentToken string) ([]SessionInfo, error) {
	rows, err := s.readDB().QueryContext(ctx, "SELECT token_hash,expires_at,created_at,last_seen_at FROM sessions WHERE expires_at>? ORDER BY expires_at DESC LIMIT ?", time.Now().UTC().Format(time.RFC3339Nano), maxListedSessions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	current := ""
	if currentToken != "" {
		current = secret.HashToken(currentToken)
	}
	now := time.Now().UTC()
	var out []SessionInfo
	for rows.Next() {
		var hash, expires, created, lastSeen string
		if err := rows.Scan(&hash, &expires, &created, &lastSeen); err != nil {
			return nil, err
		}
		info, err := sessionInfo(hash, expires, created, lastSeen)
		if err != nil || !info.IdleUntil.After(now) {
			continue
		}
		info.Current = hash == current
		out = append(out, info)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

// RevokeOtherSessions signs out every session except the one identified by
// keepToken and returns how many were removed.
func (s *Store) RevokeOtherSessions(ctx context.Context, keepToken string) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash<>?", secret.HashToken(keepToken))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ErrCurrentPasswordMismatch is returned by ChangePassword when the current
// password is wrong.
var ErrCurrentPasswordMismatch = errors.New("current password is incorrect")

// ChangePassword replaces the administrator password after verifying the
// current one, and in the same transaction signs out every other session and
// invalidates any outstanding reset token. The new password must satisfy
// secret.CheckPasswordPolicy; the session identified by keepToken stays
// signed in.
func (s *Store) ChangePassword(ctx context.Context, keepToken, current, password string) error {
	hash, err := secret.PasswordHash(password)
	if err != nil {
		return err
	}
	if !s.Authenticate(ctx, current) {
		return ErrCurrentPasswordMismatch
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "UPDATE admin SET password_hash=?,updated_at=? WHERE id=1", hash, now)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errors.New("administrator is not configured")
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{"DELETE FROM sessions WHERE token_hash<>?", []any{secret.HashToken(keepToken)}},
		{"DELETE FROM auth_tokens WHERE kind='reset'", nil},
		{"DELETE FROM meta WHERE key='reset_token_hash'", nil},
	} {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

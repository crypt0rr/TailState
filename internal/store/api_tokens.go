package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// Read-only API scopes. A token carries one or more of them; each API
// endpoint requires exactly one.
const (
	ScopeStatusRead   = "status:read"
	ScopeHistoryRead  = "history:read"
	ScopeEvidenceRead = "evidence:read"
)

// APIScopes lists every scope in display order.
var APIScopes = []string{ScopeStatusRead, ScopeHistoryRead, ScopeEvidenceRead}

const (
	// APITokenPrefix marks TailState API tokens so they are recognizable in
	// secret scanners and configuration files.
	APITokenPrefix = "tsapi_"
	// MaxAPITokenLifetime bounds token expiry; every token expires.
	MaxAPITokenLifetime = 365 * 24 * time.Hour
	// MaxActiveAPITokens bounds the number of unexpired, unrevoked tokens.
	MaxActiveAPITokens    = 25
	maxAPITokenNameRunes  = 64
	apiTokenTouchInterval = time.Minute
)

// API token errors. ErrAPITokenInvalid deliberately covers unknown, revoked,
// and expired tokens alike.
var (
	ErrAPITokenInvalid = errors.New("API token is invalid, revoked, or expired")
	ErrAPITokenRequest = errors.New("invalid API token request")
)

// APIToken is the stored, non-secret description of an API token. The token
// itself is shown once at creation and only its SHA-256 hash is stored.
type APIToken struct {
	ID         int64
	Name       string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// Active reports whether the token can authenticate at now.
func (t APIToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(now)
}

// HasScope reports whether the token grants scope.
func (t APIToken) HasScope(scope string) bool {
	for _, granted := range t.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

// Status returns "active", "revoked", or "expired".
func (t APIToken) Status() string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case !t.ExpiresAt.After(time.Now()):
		return "expired"
	default:
		return "active"
	}
}

func normalizeAPIScopes(scopes []string) ([]string, error) {
	known := map[string]bool{}
	for _, scope := range APIScopes {
		known[scope] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !known[scope] {
			return nil, fmt.Errorf("%w: unknown scope %q", ErrAPITokenRequest, scope)
		}
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: choose at least one scope", ErrAPITokenRequest)
	}
	sort.Strings(out)
	return out, nil
}

func validAPITokenName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > maxAPITokenNameRunes {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// CreateAPIToken issues a token with the given scopes that expires after
// lifetime. The returned secret is not stored and cannot be recovered.
func (s *Store) CreateAPIToken(ctx context.Context, name string, scopes []string, lifetime time.Duration) (APIToken, string, error) {
	name = strings.TrimSpace(name)
	if !validAPITokenName(name) {
		return APIToken{}, "", fmt.Errorf("%w: name must be 1 to %d printable characters", ErrAPITokenRequest, maxAPITokenNameRunes)
	}
	scopes, err := normalizeAPIScopes(scopes)
	if err != nil {
		return APIToken{}, "", err
	}
	if lifetime < time.Hour || lifetime > MaxAPITokenLifetime {
		return APIToken{}, "", fmt.Errorf("%w: expiry must be between one hour and 365 days", ErrAPITokenRequest)
	}
	random, err := secret.Token(32)
	if err != nil {
		return APIToken{}, "", err
	}
	token := APITokenPrefix + random
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return APIToken{}, "", err
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at>?", nowValue).Scan(&active); err != nil {
		return APIToken{}, "", err
	}
	if active >= MaxActiveAPITokens {
		return APIToken{}, "", fmt.Errorf("%w: at most %d active tokens; revoke one first", ErrAPITokenRequest, MaxActiveAPITokens)
	}
	expires := now.Add(lifetime)
	result, err := tx.ExecContext(ctx, "INSERT INTO api_tokens(name,token_hash,scopes,created_at,expires_at) VALUES(?,?,?,?,?)", name, secret.HashToken(token), strings.Join(scopes, " "), nowValue, expires.Format(time.RFC3339Nano))
	if err != nil {
		return APIToken{}, "", err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return APIToken{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return APIToken{}, "", err
	}
	return APIToken{ID: id, Name: name, Scopes: scopes, CreatedAt: now, ExpiresAt: expires}, token, nil
}

const apiTokenColumns = "id,name,scopes,created_at,expires_at,COALESCE(revoked_at,''),COALESCE(last_used_at,'')"

type apiTokenScanner interface{ Scan(...any) error }

func scanAPIToken(row apiTokenScanner) (APIToken, error) {
	var token APIToken
	var scopes, created, expires, revoked, lastUsed string
	if err := row.Scan(&token.ID, &token.Name, &scopes, &created, &expires, &revoked, &lastUsed); err != nil {
		return APIToken{}, err
	}
	token.Scopes = strings.Fields(scopes)
	var err error
	if token.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return APIToken{}, fmt.Errorf("parse API token creation time: %w", err)
	}
	if token.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires); err != nil {
		return APIToken{}, fmt.Errorf("parse API token expiry: %w", err)
	}
	for _, field := range []struct {
		value string
		dest  **time.Time
	}{{revoked, &token.RevokedAt}, {lastUsed, &token.LastUsedAt}} {
		if field.value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, field.value)
		if err != nil {
			return APIToken{}, fmt.Errorf("parse API token timestamp: %w", err)
		}
		*field.dest = &parsed
	}
	return token, nil
}

// ListAPITokens returns every retained token, newest first. Expired and
// revoked tokens remain listed until retention cleanup removes them.
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.readDB().QueryContext(ctx, "SELECT "+apiTokenColumns+" FROM api_tokens ORDER BY id DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		token, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, token)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes a token immediately: the next request that presents
// it is rejected.
func (s *Store) RevokeAPIToken(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL", time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: token not found or already revoked", ErrAPITokenRequest)
	}
	return nil
}

// AuthenticateAPIToken resolves a presented token. Unknown, revoked, and
// expired tokens all return ErrAPITokenInvalid. The last-used time is
// updated at most once a minute.
func (s *Store) AuthenticateAPIToken(ctx context.Context, presented string) (APIToken, error) {
	if !strings.HasPrefix(presented, APITokenPrefix) || len(presented) > 128 {
		return APIToken{}, ErrAPITokenInvalid
	}
	// The lookup is a pure read on the read-only pool; only the throttled
	// last-used touch below uses the writer.
	token, err := scanAPIToken(s.readDB().QueryRowContext(ctx, "SELECT "+apiTokenColumns+" FROM api_tokens WHERE token_hash=?", secret.HashToken(presented)))
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrAPITokenInvalid
	}
	if err != nil {
		return APIToken{}, err
	}
	now := time.Now().UTC()
	if !token.Active(now) {
		return APIToken{}, ErrAPITokenInvalid
	}
	if token.LastUsedAt == nil || now.Sub(*token.LastUsedAt) >= apiTokenTouchInterval {
		// Best effort and bounded: a busy writer must not stall a read-only
		// API request.
		if err := s.bookkeepingWrite(ctx, "UPDATE api_tokens SET last_used_at=? WHERE id=?", now.Format(time.RFC3339Nano), token.ID); err == nil {
			token.LastUsedAt = &now
		}
	}
	return token, nil
}

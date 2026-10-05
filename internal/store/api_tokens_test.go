package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// TestAPITokensAreHashedScopedAndRevocable guards E-030: only the token's
// hash is stored, scopes are normalized and enforced by HasScope, and a
// revoked or expired token fails on the next authentication.
func TestAPITokensAreHashedScopedAndRevocable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	token, value, err := st.CreateAPIToken(ctx, "  SIEM export  ", []string{ScopeHistoryRead, ScopeStatusRead, ScopeHistoryRead}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, APITokenPrefix) || token.Name != "SIEM export" || strings.Join(token.Scopes, " ") != "history:read status:read" {
		t.Fatalf("token=%+v value=%q", token, value)
	}
	var stored string
	if err := st.db.QueryRow("SELECT token_hash||scopes||name FROM api_tokens").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, strings.TrimPrefix(value, APITokenPrefix)) || !strings.Contains(stored, secret.HashToken(value)) {
		t.Fatal("API token is not stored as a hash only")
	}
	authenticated, err := st.AuthenticateAPIToken(ctx, value)
	if err != nil || !authenticated.HasScope(ScopeStatusRead) || authenticated.HasScope(ScopeEvidenceRead) || authenticated.LastUsedAt == nil || authenticated.Status() != "active" {
		t.Fatalf("authenticate=%+v err=%v", authenticated, err)
	}
	for _, presented := range []string{"", "not-a-token", value + "x", APITokenPrefix + strings.Repeat("a", 200)} {
		if _, err := st.AuthenticateAPIToken(ctx, presented); !errors.Is(err, ErrAPITokenInvalid) {
			t.Fatalf("token %q accepted: %v", presented, err)
		}
	}
	if err := st.RevokeAPIToken(ctx, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateAPIToken(ctx, value); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	if err := st.RevokeAPIToken(ctx, token.ID); !errors.Is(err, ErrAPITokenRequest) {
		t.Fatalf("second revocation: %v", err)
	}
	expiring, expiringValue, _ := st.CreateAPIToken(ctx, "Short", []string{ScopeEvidenceRead}, time.Hour)
	if _, err := st.db.Exec("UPDATE api_tokens SET expires_at=? WHERE id=?", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), expiring.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateAPIToken(ctx, expiringValue); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("expired token accepted: %v", err)
	}
	tokens, err := st.ListAPITokens(ctx)
	if err != nil || len(tokens) != 2 || tokens[0].Status() != "expired" || tokens[1].Status() != "revoked" {
		t.Fatalf("tokens=%+v err=%v", tokens, err)
	}
}

func TestAPITokenRequestsAreValidated(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for name, request := range map[string]struct {
		name     string
		scopes   []string
		lifetime time.Duration
	}{
		"empty name":     {"", []string{ScopeStatusRead}, time.Hour},
		"long name":      {strings.Repeat("n", 65), []string{ScopeStatusRead}, time.Hour},
		"control name":   {"bad\nname", []string{ScopeStatusRead}, time.Hour},
		"no scope":       {"ok", nil, time.Hour},
		"unknown scope":  {"ok", []string{"admin:write"}, time.Hour},
		"short lifetime": {"ok", []string{ScopeStatusRead}, time.Minute},
		"long lifetime":  {"ok", []string{ScopeStatusRead}, MaxAPITokenLifetime + time.Hour},
	} {
		if _, _, err := st.CreateAPIToken(ctx, request.name, request.scopes, request.lifetime); !errors.Is(err, ErrAPITokenRequest) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	for i := 0; i < MaxActiveAPITokens; i++ {
		if _, _, err := st.CreateAPIToken(ctx, "token", []string{ScopeStatusRead}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.CreateAPIToken(ctx, "one too many", []string{ScopeStatusRead}, time.Hour); !errors.Is(err, ErrAPITokenRequest) {
		t.Fatalf("active token limit not enforced: %v", err)
	}
}

// TestAPITokenRetentionRemovesLongExpiredTokens checks that expired and
// revoked tokens stay listed for one retention window and are then removed.
func TestAPITokenRetentionRemovesLongExpiredTokens(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	old, _, _ := st.CreateAPIToken(ctx, "old", []string{ScopeStatusRead}, time.Hour)
	recent, _, _ := st.CreateAPIToken(ctx, "recent", []string{ScopeStatusRead}, time.Hour)
	for id, age := range map[int64]time.Duration{old.ID: 31 * 24 * time.Hour, recent.ID: 24 * time.Hour} {
		if _, err := st.db.Exec("UPDATE api_tokens SET expires_at=? WHERE id=?", time.Now().Add(-age).UTC().Format(time.RFC3339Nano), id); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 30 * 24 * time.Hour})
	if err != nil || stats.APITokensDeleted != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	tokens, _ := st.ListAPITokens(ctx)
	if len(tokens) != 1 || tokens[0].ID != recent.ID {
		t.Fatalf("tokens=%+v", tokens)
	}
}

func TestAPITokenStorageErrors(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	_, value, _ := st.CreateAPIToken(ctx, "token", []string{ScopeStatusRead}, time.Hour)
	for _, column := range []string{"created_at", "expires_at", "last_used_at"} {
		if _, err := st.db.Exec("UPDATE api_tokens SET created_at=?,expires_at=?,last_used_at=NULL", time.Now().UTC().Format(time.RFC3339Nano), time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec("UPDATE api_tokens SET " + column + "='bad'"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListAPITokens(ctx); err == nil {
			t.Fatalf("malformed %s listed", column)
		}
		if _, err := st.AuthenticateAPIToken(ctx, value); err == nil || errors.Is(err, ErrAPITokenInvalid) {
			t.Fatalf("malformed %s: %v", column, err)
		}
	}
	st.Close()
	if _, _, err := st.CreateAPIToken(ctx, "x", []string{ScopeStatusRead}, time.Hour); err == nil {
		t.Fatal("CreateAPIToken succeeded on a closed store")
	}
	if _, err := st.ListAPITokens(ctx); err == nil {
		t.Fatal("ListAPITokens succeeded on a closed store")
	}
	if err := st.RevokeAPIToken(ctx, 1); err == nil {
		t.Fatal("RevokeAPIToken succeeded on a closed store")
	}
	if _, err := st.AuthenticateAPIToken(ctx, value); err == nil {
		t.Fatal("AuthenticateAPIToken succeeded on a closed store")
	}
}

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func claimedStore(t *testing.T) *Store {
	t.Helper()
	st := testStore(t)
	ctx := context.Background()
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "a secure password"); err != nil {
		t.Fatal(err)
	}
	return st
}

func setSessionLastSeen(t *testing.T, st *Store, token string, at time.Time) {
	t.Helper()
	if _, err := st.db.Exec("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", at.UTC().Format(time.RFC3339Nano), secret.HashToken(token)); err != nil {
		t.Fatal(err)
	}
}

// TestSessionIdleTimeoutIgnoresNonActivityChecks guards E-023: a session
// expires after SessionIdleTimeout without activity, checks marked as not
// activity (the status auto-refresh) never extend it, and an idle session is
// removed.
func TestSessionIdleTimeoutIgnoresNonActivityChecks(t *testing.T) {
	st := claimedStore(t)
	ctx := context.Background()
	token, csrf, err := st.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-SessionIdleTimeout + 5*time.Minute)
	setSessionLastSeen(t, st, token, stale)
	info, ok := st.AuthenticateSession(ctx, token, csrf, true, false)
	if !ok || info.LastSeenAt.Sub(stale.UTC()) > time.Second || info.Ref != SessionRef(token) {
		t.Fatalf("non-activity check changed the session: %+v ok=%v", info, ok)
	}
	setSessionLastSeen(t, st, token, time.Now().Add(-SessionIdleTimeout-time.Second))
	if _, ok := st.AuthenticateSession(ctx, token, csrf, false, false); ok {
		t.Fatal("idle session accepted")
	}
	var remaining int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("idle session not removed: %d %v", remaining, err)
	}

	token, csrf, err = st.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setSessionLastSeen(t, st, token, stale)
	if info, ok := st.AuthenticateSession(ctx, token, csrf, true, true); !ok || time.Since(info.LastSeenAt) > time.Minute {
		t.Fatalf("activity did not extend the session: %+v", info)
	}
	if _, ok := st.AuthenticateSession(ctx, token, "wrong", true, true); ok {
		t.Fatal("wrong CSRF accepted")
	}
	if _, ok := st.AuthenticateSession(ctx, "", "", false, true); ok {
		t.Fatal("empty token accepted")
	}
	if SessionRef("") != "" {
		t.Fatal("empty token has a reference")
	}
	// A row without last_seen_at (written before schema v15) falls back to
	// its creation time.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.db.Exec("INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?)", secret.HashToken("legacy"), secret.HashToken("csrf"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), now); err != nil {
		t.Fatal(err)
	}
	if !st.ValidateSession(ctx, "legacy", "csrf", true) {
		t.Fatal("session without last-seen time rejected")
	}
	if _, err := st.db.Exec("UPDATE sessions SET last_seen_at='not-a-time' WHERE token_hash=?", secret.HashToken("legacy")); err != nil {
		t.Fatal(err)
	}
	if st.ValidateSession(ctx, "legacy", "csrf", false) {
		t.Fatal("malformed last-seen time accepted")
	}
}

// TestChangePasswordRevokesOtherSessions guards E-023 and R-052: changing
// the password needs the current password, applies the policy, and in one
// transaction signs out every session (the web handler issues a fresh one),
// invalidates the reset token, and revokes every active API token.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	st := claimedStore(t)
	ctx := context.Background()
	keep, keepCSRF, _ := st.CreateSession(ctx)
	other, otherCSRF, _ := st.CreateSession(ctx)
	if _, err := st.NewResetToken(ctx); err != nil {
		t.Fatal(err)
	}
	_, apiToken, err := st.CreateAPIToken(ctx, "SIEM", []string{ScopeHistoryRead}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const next = "violet harbor lantern"
	if _, err := st.ChangePassword(ctx, "wrong", next); !errors.Is(err, ErrCurrentPasswordMismatch) {
		t.Fatalf("wrong current password: %v", err)
	}
	if _, err := st.ChangePassword(ctx, "a secure password", "short"); !errors.Is(err, secret.ErrPasswordTooShort) {
		t.Fatalf("policy not applied: %v", err)
	}
	if !st.ValidateSession(ctx, other, otherCSRF, true) {
		t.Fatal("a rejected change revoked a session")
	}
	if _, err := st.AuthenticateAPIToken(ctx, apiToken); err != nil {
		t.Fatalf("a rejected change revoked an API token: %v", err)
	}
	if revoked, err := st.ChangePassword(ctx, "a secure password", next); err != nil || revoked != 1 {
		t.Fatalf("change revoked=%d err=%v", revoked, err)
	}
	if st.ValidateSession(ctx, other, otherCSRF, true) || st.ValidateSession(ctx, keep, keepCSRF, true) {
		t.Fatal("password change left a session signed in")
	}
	if _, err := st.AuthenticateAPIToken(ctx, apiToken); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("API token survived a password change: %v", err)
	}
	if !st.Authenticate(ctx, next) || st.Authenticate(ctx, "a secure password") {
		t.Fatal("password was not replaced")
	}
	var resets int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM auth_tokens WHERE kind='reset'").Scan(&resets); err != nil || resets != 0 {
		t.Fatalf("reset token survived a password change: %d %v", resets, err)
	}
	if _, err := st.db.Exec("DELETE FROM admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ChangePassword(ctx, next, "another fine passphrase"); err == nil {
		t.Fatal("password changed without an administrator")
	}
}

func TestListSessionsAndRevokeOthers(t *testing.T) {
	st := claimedStore(t)
	ctx := context.Background()
	current, _, _ := st.CreateSession(ctx)
	other, _, _ := st.CreateSession(ctx)
	idle, _, _ := st.CreateSession(ctx)
	setSessionLastSeen(t, st, other, time.Now().Add(-10*time.Minute))
	setSessionLastSeen(t, st, idle, time.Now().Add(-2*SessionIdleTimeout))
	sessions, err := st.ListSessions(ctx, current)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("sessions=%+v err=%v", sessions, err)
	}
	if !sessions[0].Current || sessions[0].Ref != SessionRef(current) || sessions[1].Ref != SessionRef(other) || sessions[1].Current {
		t.Fatalf("session order or current marker wrong: %+v", sessions)
	}
	removed, err := st.RevokeOtherSessions(ctx, current)
	if err != nil || removed != 2 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	sessions, err = st.ListSessions(ctx, "")
	if err != nil || len(sessions) != 1 || sessions[0].Current {
		t.Fatalf("after revoke sessions=%+v err=%v", sessions, err)
	}
	if _, err := st.db.Exec("UPDATE sessions SET created_at='bad'"); err != nil {
		t.Fatal(err)
	}
	if sessions, err := st.ListSessions(ctx, current); err != nil || len(sessions) != 0 {
		t.Fatalf("malformed session listed: %+v %v", sessions, err)
	}
	st.Close()
	if _, err := st.ListSessions(ctx, current); err == nil {
		t.Fatal("ListSessions succeeded on a closed store")
	}
	if _, err := st.RevokeOtherSessions(ctx, current); err == nil {
		t.Fatal("RevokeOtherSessions succeeded on a closed store")
	}
	if _, err := st.ChangePassword(ctx, "a secure password", "violet harbor lantern"); err == nil {
		t.Fatal("ChangePassword succeeded on a closed store")
	}
}

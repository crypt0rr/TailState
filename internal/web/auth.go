package web

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if !s.authenticated(r, false) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	status, err := s.store.Status(r.Context())
	if err != nil {
		slog.Error("load status for home redirect", "error", err)
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if !status.Configured {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if exists {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	s.renderCredential(w, r, "setup", credentialActionSetup, pageData{})
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if exists {
		http.Error(w, "installation already claimed", http.StatusConflict)
		return
	}
	ip := s.throttleKey(credentialActionSetup, s.clientIP(r))
	if retry, limited := s.throttled(credentialActionSetup, ip); limited {
		s.renderThrottled(w, r, "setup", credentialActionSetup, "Too many setup attempts. Try again later.", retry)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionSetup) {
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: credentialChallengeError})
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if r.FormValue("password") != r.FormValue("confirm") {
		// Password confirmation is part of the unauthenticated setup surface.
		// Count mismatches as failed claims so an attacker cannot bypass the
		// endpoint throttle by repeatedly submitting different confirmations.
		s.recordFailure(credentialActionSetup, ip)
		s.recordCredentialRejection(credentialActionSetup)
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: "Passwords do not match."})
		return
	}
	// The policy is checked before the token so a weak password gets a
	// specific explanation instead of the generic token error. It reveals
	// nothing about the token.
	if err := secret.CheckPasswordPolicy(r.FormValue("password")); err != nil {
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: secret.PasswordPolicyMessage(err)})
		return
	}
	if err := s.store.Claim(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.recordFailure(credentialActionSetup, ip)
		s.recordCredentialRejection(credentialActionSetup)
		// Setup is unauthenticated. Keep storage, token, and migration details
		// out of the response so this endpoint cannot become an oracle.
		slog.Debug("setup claim rejected", "error", err)
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: "Setup could not be completed. Check the setup token and try again."})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionSetup)
	token, ok := s.startSession(w, r)
	if !ok {
		return
	}
	s.recordAdmin(r, store.SessionRef(token), adminChange{event: store.AuditSetupClaim}, nil, 0)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	next, _ := safeReturnPath(r.URL.Query().Get("next"))
	if s.authenticated(r, false) {
		if next == "" {
			next = "/status"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.renderCredential(w, r, "login", credentialActionLogin, pageData{Next: next})
}

func (s *Server) adminExists(w http.ResponseWriter, r *http.Request) (bool, bool) {
	exists, err := s.store.AdminExists(r.Context())
	if err != nil {
		slog.Error("check administrator state", "error", err)
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return false, false
	}
	return exists, true
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := s.throttleKey(credentialActionLogin, s.clientIP(r))
	if retry, limited := s.throttled(credentialActionLogin, ip); limited {
		s.renderThrottled(w, r, "login", credentialActionLogin, "Too many login attempts. Try again later.", retry)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	next, _ := safeReturnPath(r.FormValue("next"))
	if !s.validateCredentialChallenge(r, credentialActionLogin) {
		s.renderCredential(w, r, "login", credentialActionLogin, pageData{Error: credentialChallengeError, Next: next})
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if !s.store.Authenticate(r.Context(), r.FormValue("password")) {
		s.recordFailure(credentialActionLogin, ip)
		s.recordCredentialRejection(credentialActionLogin)
		s.recordAdmin(r, "", adminChange{event: store.AuditLoginFailure, outcome: store.AuditFailure}, nil, 0)
		s.renderCredential(w, r, "login", credentialActionLogin, pageData{Error: "Invalid password.", Next: next})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionLogin)
	token, ok := s.startSession(w, r)
	if !ok {
		return
	}
	s.recordAdmin(r, store.SessionRef(token), adminChange{event: store.AuditLoginSuccess}, nil, 0)
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.session(r, true, true)
	if !ok {
		s.rejectUnauthenticated(w, r, true)
		return
	}
	s.store.DeleteSession(r.Context(), auth.token)
	s.recordAdmin(r, auth.ref, adminChange{event: store.AuditLogout}, nil, 0)
	s.clearCookies(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	s.renderCredential(w, r, "reset", credentialActionReset, pageData{})
}

func (s *Server) resetPost(w http.ResponseWriter, r *http.Request) {
	ip := s.throttleKey(credentialActionReset, s.clientIP(r))
	if retry, limited := s.throttled(credentialActionReset, ip); limited {
		s.renderThrottled(w, r, "reset", credentialActionReset, "Too many reset attempts. Try again later.", retry)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionReset) {
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: credentialChallengeError})
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if r.FormValue("password") != r.FormValue("confirm") {
		s.recordFailure(credentialActionReset, ip)
		s.recordCredentialRejection(credentialActionReset)
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: "Passwords do not match."})
		return
	}
	if err := secret.CheckPasswordPolicy(r.FormValue("password")); err != nil {
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: secret.PasswordPolicyMessage(err)})
		return
	}
	before := s.enabledDestinations(r.Context())
	if err := s.store.ResetWithToken(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.recordFailure(credentialActionReset, ip)
		s.recordCredentialRejection(credentialActionReset)
		// Do not disclose whether a reset token is missing, invalid, expired,
		// or temporarily unreadable. The token is deliberately a single
		// generic oracle to unauthenticated callers.
		slog.Debug("password reset rejected", "error", err)
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: "The reset token is invalid or expired."})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionReset)
	s.recordAdmin(r, "", adminChange{event: store.AuditPasswordReset, highRisk: true}, before, 0)
	s.clearCookies(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, csrf, err := s.store.CreateSession(r.Context())
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return "", false
	}
	// With secure cookies a sign-in expires the unprefixed cookies of an
	// earlier sign-in, so the browser holds one generation only.
	if s.config.CookieSecure {
		for _, name := range []string{sessionCookieBase, csrfCookieBase} {
			http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: name == sessionCookieBase, Secure: true, SameSite: http.SameSiteStrictMode})
		}
	}
	maxAge := int(store.SessionLifetime / time.Second)
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(sessionCookieBase), Value: token, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(csrfCookieBase), Value: csrf, Path: "/", MaxAge: maxAge, HttpOnly: false, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	return token, true
}

// clearCookies expires the session cookies under both namings.
func (s *Server) clearCookies(w http.ResponseWriter) {
	names := []string{sessionCookieBase, csrfCookieBase}
	if s.config.CookieSecure {
		names = append(names, hostCookiePrefix+sessionCookieBase, hostCookiePrefix+csrfCookieBase)
	}
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: strings.HasSuffix(name, sessionCookieBase), Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	}
}

func (s *Server) authenticated(r *http.Request, requireCSRF bool) bool {
	_, ok := s.session(r, requireCSRF, true)
	return ok
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request, csrf bool) (string, bool) {
	auth, ok := s.requireSession(w, r, csrf, true)
	return auth.csrf, ok
}

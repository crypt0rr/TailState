package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

const (
	sessionCookieBase = "tailstate_session"
	csrfCookieBase    = "tailstate_csrf"
	// hostCookiePrefix asks the browser to accept a cookie only when it is
	// Secure, has Path=/ and no Domain, so a sibling host cannot set or
	// shadow it. It is used whenever TAILSTATE_COOKIE_SECURE is enabled.
	hostCookiePrefix = "__Host-"
	// hstsValue is sent only on requests that arrived over HTTPS (see
	// requestIsHTTPS); HSTS on a plain-HTTP response is ignored by browsers
	// and would only mislead a reader of the headers.
	hstsValue = "max-age=31536000"
	// refreshParameter marks the status page's automatic refresh. Such
	// requests are authenticated normally but do not count as activity for
	// the session idle timeout.
	refreshParameter = "refresh"
	// passwordChangeThrottle is the limiter bucket for wrong current
	// passwords on the authenticated change form.
	passwordChangeThrottle credentialAction = "password_change"
)

// cookieName returns the name used for new cookies: __Host-prefixed when
// cookies are Secure.
func (s *Server) cookieName(base string) string {
	if s.config.CookieSecure {
		return hostCookiePrefix + base
	}
	return base
}

// hasSessionCookie reports whether the browser sent a session cookie under
// either naming, valid or not.
func (s *Server) hasSessionCookie(r *http.Request) bool {
	for _, name := range []string{hostCookiePrefix + sessionCookieBase, sessionCookieBase} {
		if _, err := r.Cookie(name); err == nil {
			return true
		}
	}
	return false
}

// sessionCookies returns the session and CSRF cookies of one generation.
// The __Host- names are preferred; the unprefixed names issued before the
// prefix was introduced (or before TAILSTATE_COOKIE_SECURE was enabled) are
// still accepted so upgrading does not sign anyone out. A request never mixes
// a session cookie of one naming with a CSRF cookie of the other.
func (s *Server) sessionCookies(r *http.Request) (session, csrf *http.Cookie, ok bool) {
	names := []string{sessionCookieBase}
	if s.config.CookieSecure {
		names = []string{hostCookiePrefix + sessionCookieBase, sessionCookieBase}
	}
	for _, name := range names {
		sessionCookie, err1 := r.Cookie(name)
		csrfCookie, err2 := r.Cookie(strings.Replace(name, sessionCookieBase, csrfCookieBase, 1))
		if err1 == nil && err2 == nil && sessionCookie.Value != "" && csrfCookie.Value != "" {
			return sessionCookie, csrfCookie, true
		}
	}
	return nil, nil, false
}

// authSession is the authenticated session of one request.
type authSession struct {
	token string
	csrf  string
	ref   string
}

// session authenticates the request. activity is false only for requests
// that a browser makes on its own (the status auto-refresh), so they do not
// extend the idle timeout.
func (s *Server) session(r *http.Request, requireCSRF, activity bool) (authSession, bool) {
	sessionCookie, csrfCookie, ok := s.sessionCookies(r)
	if !ok {
		return authSession{}, false
	}
	provided := csrfCookie.Value
	if requireCSRF {
		provided = r.FormValue("_csrf")
		if provided == "" || provided != csrfCookie.Value {
			return authSession{}, false
		}
	}
	info, valid := s.store.AuthenticateSession(r.Context(), sessionCookie.Value, provided, requireCSRF, activity)
	if !valid {
		return authSession{}, false
	}
	return authSession{token: sessionCookie.Value, csrf: csrfCookie.Value, ref: info.Ref}, true
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, csrf, activity bool) (authSession, bool) {
	if csrf {
		_ = r.ParseForm()
	}
	auth, ok := s.session(r, csrf, activity)
	if !ok {
		s.rejectUnauthenticated(w, r, csrf)
		return authSession{}, false
	}
	return auth, true
}

// requestIsHTTPS reports whether the client reached TailState over HTTPS:
// either directly over TLS or through a trusted proxy that says so. An
// X-Forwarded-Proto header from any other peer is ignored.
func (s *Server) requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.isTrustedProxy(remoteIP(r)) {
		return false
	}
	values := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(values[len(values)-1]), "https")
}

// accountSection is where account-security form outcomes return to: the top
// of Settings, where the flash message is shown and announced.
const accountSection = "/settings"

// passwordPost changes the administrator password. It requires the current
// password, applies the password policy before anything else, and signs out
// every other session. Every outcome is reported with Post/Redirect/Get and
// a one-time flash message, so a reload never resubmits a password.
func (s *Server) passwordPost(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	ctx := r.Context()
	fail := func(message string) {
		s.redirectWithFlash(w, r, accountSection, flashKindError, message)
	}
	key := s.throttleKey(passwordChangeThrottle, s.clientIP(r))
	if _, limited := s.throttled(passwordChangeThrottle, key); limited {
		fail("Too many incorrect current passwords. Try again later.")
		return
	}
	password := r.FormValue("password")
	if password != r.FormValue("confirm") {
		fail("Password was not changed: the new passwords do not match.")
		return
	}
	if err := secret.CheckPasswordPolicy(password); err != nil {
		fail("Password was not changed. " + secret.PasswordPolicyMessage(err))
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if err := s.store.ChangePassword(ctx, auth.token, r.FormValue("current_password"), password); err != nil {
		if errors.Is(err, store.ErrCurrentPasswordMismatch) {
			s.recordFailure(passwordChangeThrottle, key)
			fail("Password was not changed: the current password is incorrect.")
			return
		}
		slog.Error("change administrator password", "error", err)
		fail("Password could not be changed. Try again.")
		return
	}
	s.clearFailures(key)
	s.redirectWithFlash(w, r, accountSection, flashKindSuccess, "Password changed. Every other session was signed out.")
}

// sessionsPost signs out every session except the current one.
func (s *Server) sessionsPost(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	removed, err := s.store.RevokeOtherSessions(r.Context(), auth.token)
	if err != nil {
		slog.Error("revoke other sessions", "error", err)
		s.redirectWithFlash(w, r, accountSection, flashKindError, "Other sessions could not be signed out. Try again.")
		return
	}
	message := "Signed out every other session."
	if removed == 0 {
		message = "No other session was active."
	}
	s.redirectWithFlash(w, r, accountSection, flashKindSuccess, message)
}

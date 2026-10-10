package web

import (
	"net/http"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// credentialFlow is the sequence shared by the unauthenticated credential
// forms (setup, login, and password reset): the per-client and global
// throttle, form parsing, the one-time form challenge, a slot in the bounded
// password-hashing pool, and the failure accounting that feeds the throttle
// and the rejection metrics.
type credentialFlow struct {
	server *Server
	// page is the template re-rendered on every outcome.
	page   string
	action credentialAction
	// throttledMessage explains a 429 response.
	throttledMessage string
	// form, when set, returns the page data that a re-rendered form keeps
	// (for example the login return path). It runs once, after parsing.
	form func(*http.Request) pageData
	// setsPassword marks a form that sets a new password (setup and reset).
	// Its password policy is checked before the challenge, so a rejected
	// password never consumes a nonce from the shared replay cache.
	setsPassword bool

	key  string
	base pageData
}

// begin runs the throttle → parse → policy → challenge → hash-slot sequence
// (the policy step only for forms that set a password). When it
// returns ok, the caller holds a hashing slot and must call release once the
// submission is handled; otherwise the response has been written.
func (f *credentialFlow) begin(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	s := f.server
	f.key = s.throttleKey(f.action, s.clientIP(r))
	if retry, limited := s.throttled(f.action, f.key); limited {
		s.renderThrottled(w, r, f.page, f.action, f.throttledMessage, retry)
		return nil, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return nil, false
	}
	if f.form != nil {
		f.base = f.form(r)
	}
	if f.setsPassword {
		if err := secret.CheckPasswordPolicy(r.FormValue("password")); err != nil {
			f.render(w, r, secret.PasswordPolicyMessage(err))
			return nil, false
		}
	}
	if !s.validateCredentialChallenge(r, f.action) {
		f.render(w, r, credentialChallengeError)
		return nil, false
	}
	select {
	case s.authWork <- struct{}{}:
		return func() { <-s.authWork }, true
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return nil, false
	}
}

// newPassword checks the confirmation field of a form that sets a password.
// A mismatch counts as a failed submission, so changing the confirmation
// cannot bypass the throttle. A policy failure does not count: begin has
// already rejected it, before the challenge and before any token, so a weak
// password gets a specific explanation that reveals nothing about the token
// and spends no challenge.
func (f *credentialFlow) newPassword(w http.ResponseWriter, r *http.Request) bool {
	if r.FormValue("password") != r.FormValue("confirm") {
		f.reject(w, r, "Passwords do not match.")
		return false
	}
	return true
}

// countFailure records a rejected submission against the throttle and in
// the rejection metrics.
func (f *credentialFlow) countFailure() {
	f.server.recordFailure(f.action, f.key)
	f.server.recordCredentialRejection(f.action)
}

// reject counts a failed submission and re-renders the form with message.
func (f *credentialFlow) reject(w http.ResponseWriter, r *http.Request, message string) {
	f.countFailure()
	f.render(w, r, message)
}

// render re-renders the form with message and a fresh challenge.
func (f *credentialFlow) render(w http.ResponseWriter, r *http.Request, message string) {
	data := f.base
	data.Error = message
	f.server.renderCredential(w, r, f.page, f.action, data)
}

// succeed clears the client's throttle bucket and the spent challenge.
func (f *credentialFlow) succeed(w http.ResponseWriter) {
	f.server.clearFailures(f.key)
	f.server.clearCredentialChallengeCookie(w, f.action)
}

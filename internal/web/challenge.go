package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

const (
	credentialChallengeLifetime = 5 * time.Minute
	// maxConsumedCredentialChallenges bounds the replay cache. Entries are
	// only added for submissions whose signed challenge validated, and are
	// pruned once their expiry passes.
	maxConsumedCredentialChallenges = 1 << 16
	maxCredentialChallengeBytes     = 512
	credentialChallengeError        = "This form has expired or is invalid. Reload the page and try again."
)

type credentialAction string

const (
	credentialActionSetup credentialAction = "setup"
	credentialActionLogin credentialAction = "login"
	credentialActionReset credentialAction = "reset"
)

var credentialActions = []credentialAction{
	credentialActionSetup,
	credentialActionLogin,
	credentialActionReset,
}

var credentialChallengeOutcomes = []string{
	challengeOutcomeMissing,
	challengeOutcomeExpired,
	challengeOutcomeInvalid,
	challengeOutcomeAccepted,
}

type credentialChallengeMetric struct {
	action  credentialAction
	outcome string
}

const (
	challengeOutcomeMissing  = "missing"
	challengeOutcomeExpired  = "expired"
	challengeOutcomeInvalid  = "invalid"
	challengeOutcomeAccepted = "accepted"
)

func newCredentialChallengeKey() ([]byte, error) {
	key, err := secret.Token(32)
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

func (a credentialAction) valid() bool {
	return a == credentialActionSetup || a == credentialActionLogin || a == credentialActionReset
}

func (a credentialAction) cookieName() string { return "tailstate_" + string(a) + "_challenge" }

func (a credentialAction) pagePath() string {
	switch a {
	case credentialActionSetup:
		return "/setup"
	case credentialActionLogin:
		return "/login"
	case credentialActionReset:
		return "/reset"
	default:
		return "/"
	}
}

func (a credentialAction) postPath() string {
	switch a {
	case credentialActionSetup:
		return "/setup/claim"
	case credentialActionLogin:
		return "/login"
	case credentialActionReset:
		return "/reset"
	default:
		return "/"
	}
}

func (s *Server) renderCredential(w http.ResponseWriter, r *http.Request, name string, action credentialAction, data pageData) {
	s.renderCredentialStatus(w, r, name, action, data, http.StatusOK)
}

func (s *Server) renderCredentialStatus(w http.ResponseWriter, r *http.Request, name string, action credentialAction, data pageData, code int) {
	challenge, err := s.issueCredentialChallenge(w, r, action)
	if err != nil {
		slog.Error("issue credential form challenge", "action", action, "error", err)
		http.Error(w, "credential form temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	data.Challenge = challenge
	s.renderStatus(w, name, data, code)
}

// issueCredentialChallenge is deliberately stateless. The signed form value
// (action, nonce, browser binding, expiry) together with the HMAC-protected
// browser binding cookie prove that TailState issued the form, so
// unauthenticated page views cannot exhaust or evict server-side state. Only
// consumed nonces are remembered (see consumeCredentialChallenge). A
// still-valid binding cookie is reused, so several tabs opened in the same
// browser can all submit.
func (s *Server) issueCredentialChallenge(w http.ResponseWriter, r *http.Request, action credentialAction) (string, error) {
	if !action.valid() {
		return "", errors.New("unsupported credential action")
	}
	if len(s.challengeKey) == 0 {
		return "", errors.New("credential challenge key is unavailable")
	}
	now := time.Now().UTC()
	binding := ""
	if r != nil {
		if cookie, err := r.Cookie(action.cookieName()); err == nil {
			if existing, ok := s.credentialChallengeBinding(action, cookie.Value, now); ok {
				binding = existing
			}
		}
	}
	if binding == "" {
		fresh, err := secret.Token(32)
		if err != nil {
			return "", err
		}
		binding = fresh
	}
	nonce, err := secret.Token(32)
	if err != nil {
		return "", err
	}
	expiresAt := now.Add(credentialChallengeLifetime)
	expires := strconv.FormatInt(expiresAt.Unix(), 10)
	payload := strings.Join([]string{string(action), nonce, binding, expires}, ".")
	formValue := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(s.signCredentialChallenge([]byte(payload)))

	// Refresh the binding cookie so it outlives every form issued with it.
	http.SetCookie(w, &http.Cookie{
		Name:     action.cookieName(),
		Value:    s.credentialChallengeCookieValue(action, binding, expires),
		Path:     action.pagePath(),
		MaxAge:   int(credentialChallengeLifetime / time.Second),
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	return formValue, nil
}

func (s *Server) credentialChallengeCookieValue(action credentialAction, binding, expires string) string {
	payload := strings.Join([]string{"cookie", string(action), binding, expires}, ".")
	return binding + "." + expires + "." + base64.RawURLEncoding.EncodeToString(s.signCredentialChallenge([]byte(payload)))
}

// credentialChallengeBinding verifies a browser binding cookie issued by this
// process for action and returns its binding token. A zero now skips the
// cookie expiry check.
func (s *Server) credentialChallengeBinding(action credentialAction, value string, now time.Time) (string, bool) {
	if value == "" || len(value) > maxCredentialChallengeBytes {
		return "", false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] == "" {
		return "", false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size {
		return "", false
	}
	expected := s.signCredentialChallenge([]byte(strings.Join([]string{"cookie", string(action), parts[0], parts[1]}, ".")))
	if subtle.ConstantTimeCompare(signature, expected) != 1 {
		return "", false
	}
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || (!now.IsZero() && !time.Unix(expiresUnix, 0).After(now)) {
		return "", false
	}
	return parts[0], true
}

func (s *Server) signCredentialChallenge(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.challengeKey)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func (s *Server) pruneConsumedChallengesLocked(now time.Time) {
	for nonce, expiresAt := range s.consumedChallenges {
		if !expiresAt.After(now) {
			delete(s.consumedChallenges, nonce)
		}
	}
	s.consumedPrunedAt = now
}

// consumeCredentialChallenge marks nonce as used until it expires. It returns
// false for a replay, or when the bounded consumed set is full of unexpired
// nonces: evicting one of those would reopen it for replay, so the submission
// fails closed instead.
func (s *Server) consumeCredentialChallenge(nonce string, expiresAt, now time.Time) bool {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	if now.Sub(s.consumedPrunedAt) >= time.Minute || len(s.consumedChallenges) >= maxConsumedCredentialChallenges {
		s.pruneConsumedChallengesLocked(now)
	}
	if _, used := s.consumedChallenges[nonce]; used {
		return false
	}
	if len(s.consumedChallenges) >= maxConsumedCredentialChallenges {
		slog.Warn("credential challenge replay cache is full; rejecting submission")
		return false
	}
	s.consumedChallenges[nonce] = expiresAt
	return true
}

func (s *Server) validateCredentialChallenge(r *http.Request, action credentialAction) bool {
	outcome := challengeOutcomeInvalid
	defer func() {
		s.recordCredentialChallenge(action, outcome)
	}()

	provided := strings.TrimSpace(r.FormValue("_challenge"))
	cookie, cookieErr := r.Cookie(action.cookieName())
	if provided == "" || cookieErr != nil || cookie.Value == "" {
		outcome = challengeOutcomeMissing
		return false
	}
	if len(provided) > maxCredentialChallengeBytes {
		return false
	}
	parts := strings.Split(provided, ".")
	if len(parts) != 2 {
		return false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	signature, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(signature) != sha256.Size {
		return false
	}
	expected := s.signCredentialChallenge(payload)
	if subtle.ConstantTimeCompare(signature, expected) != 1 {
		return false
	}
	fields := strings.Split(string(payload), ".")
	if len(fields) != 4 || credentialAction(fields[0]) != action || fields[1] == "" {
		return false
	}
	expiresUnix, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if !expiresAt.After(now) {
		outcome = challengeOutcomeExpired
		return false
	}
	// The cookie's own expiry is not checked here: the signed form expiry
	// above is authoritative and every issued form refreshes the cookie past
	// it. The binding ties the form to the browser that loaded it.
	binding, ok := s.credentialChallengeBinding(action, cookie.Value, time.Time{})
	if !ok || subtle.ConstantTimeCompare([]byte(binding), []byte(fields[2])) != 1 {
		return false
	}
	if !s.consumeCredentialChallenge(fields[1], expiresAt, now) {
		return false
	}
	outcome = challengeOutcomeAccepted
	return true
}

func (s *Server) clearCredentialChallengeCookie(w http.ResponseWriter, action credentialAction) {
	http.SetCookie(w, &http.Cookie{
		Name:     action.cookieName(),
		Path:     action.pagePath(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) recordCredentialChallenge(action credentialAction, outcome string) {
	s.metricsMu.Lock()
	s.challengeCounts[credentialChallengeMetric{action: action, outcome: outcome}]++
	s.metricsMu.Unlock()
	slog.Debug("credential form challenge", "route", action.postPath(), "outcome", outcome)
}

func (s *Server) recordCredentialRejection(action credentialAction) {
	s.metricsMu.Lock()
	s.credentialRejections[string(action)]++
	s.metricsMu.Unlock()
}

func (s *Server) credentialChallengeCount(action credentialAction, outcome string) uint64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	return s.challengeCounts[credentialChallengeMetric{action: action, outcome: outcome}]
}

func (s *Server) credentialRejectionCount(action credentialAction) uint64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	return s.credentialRejections[string(action)]
}

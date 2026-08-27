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
	maxCredentialChallenges     = 4096
	maxCredentialChallengeBytes = 512
	credentialChallengeError    = "This form has expired or is invalid. Reload the page and try again."
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

type credentialChallengeRecord struct {
	action    credentialAction
	expiresAt time.Time
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

func (s *Server) renderCredential(w http.ResponseWriter, name string, action credentialAction, data pageData) {
	challenge, err := s.issueCredentialChallenge(w, action)
	if err != nil {
		slog.Error("issue credential form challenge", "action", action, "error", err)
		http.Error(w, "credential form temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	data.Challenge = challenge
	s.render(w, name, data)
}

func (s *Server) issueCredentialChallenge(w http.ResponseWriter, action credentialAction) (string, error) {
	if !action.valid() {
		return "", errors.New("unsupported credential action")
	}
	if len(s.challengeKey) == 0 {
		return "", errors.New("credential challenge key is unavailable")
	}
	nonce, err := secret.Token(32)
	if err != nil {
		return "", err
	}
	expiresAt := time.Now().UTC().Add(credentialChallengeLifetime)
	payload := strings.Join([]string{string(action), nonce, strconv.FormatInt(expiresAt.Unix(), 10)}, ".")
	signature := s.signCredentialChallenge([]byte(payload))
	formValue := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(signature)

	s.challengeMu.Lock()
	s.pruneCredentialChallengesLocked(time.Now().UTC())
	if len(s.challenges) >= maxCredentialChallenges {
		var oldestNonce string
		var oldest time.Time
		for candidate, record := range s.challenges {
			if oldestNonce == "" || record.expiresAt.Before(oldest) {
				oldestNonce, oldest = candidate, record.expiresAt
			}
		}
		delete(s.challenges, oldestNonce)
	}
	s.challenges[nonce] = credentialChallengeRecord{action: action, expiresAt: expiresAt}
	s.challengeMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     action.cookieName(),
		Value:    nonce,
		Path:     action.pagePath(),
		MaxAge:   int(credentialChallengeLifetime / time.Second),
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	return formValue, nil
}

func (s *Server) signCredentialChallenge(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.challengeKey)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func (s *Server) pruneCredentialChallengesLocked(now time.Time) {
	for nonce, record := range s.challenges {
		if !record.expiresAt.After(now) {
			delete(s.challenges, nonce)
		}
	}
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
	if len(fields) != 3 || credentialAction(fields[0]) != action || fields[1] != cookie.Value {
		return false
	}
	expiresUnix, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	if !time.Unix(expiresUnix, 0).After(now) {
		outcome = challengeOutcomeExpired
		return false
	}

	s.challengeMu.Lock()
	record, ok := s.challenges[fields[1]]
	if ok {
		delete(s.challenges, fields[1])
	}
	s.challengeMu.Unlock()
	if !ok || record.action != action || record.expiresAt.Unix() != expiresUnix {
		return false
	}
	if !record.expiresAt.After(now) {
		outcome = challengeOutcomeExpired
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

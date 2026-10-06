package web

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// throttleKey returns the per-client limiter bucket for action. IPv6 clients
// are aggregated by their /64, which a single host or customer site usually
// controls in full; IPv4 (including IPv4-mapped IPv6) keeps one bucket per
// address.
func (s *Server) throttleKey(action credentialAction, client string) string {
	return string(action) + ":" + limiterAddress(client)
}

func limiterAddress(client string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(client))
	if err != nil {
		return client
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(loginIPv6PrefixBits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

// throttled reports whether a credential submission must be refused, and for
// how long. Two independent limits apply: each client bucket allows
// loginFailuresPerClient failures per loginFailureWindow, and every action has
// a global failure budget across all sources. Once the global budget is spent,
// each further failure doubles the wait (capped at loginGlobalBackoffMax), so
// distributed guessing slows down exponentially instead of being bounded only
// by the password hash cost.
func (s *Server) throttled(action credentialAction, key string) (time.Duration, bool) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	s.pruneLoginAttemptsLocked(now.Add(-loginFailureWindow))
	var retry time.Duration
	if attempts := s.loginAttempts[key]; len(attempts) >= loginFailuresPerClient {
		// The bucket reopens when its oldest counted failure leaves the window.
		retry = attempts[len(attempts)-loginFailuresPerClient].Add(loginFailureWindow).Sub(now)
	}
	if global := s.globalFailures[action]; len(global) >= loginGlobalFailureBudget {
		until := global[len(global)-1].Add(globalBackoff(len(global) - loginGlobalFailureBudget))
		if wait := until.Sub(now); wait > retry {
			retry = wait
		}
	}
	return retry, retry > 0
}

// globalBackoff returns the delay after the excess-th failure beyond the
// global budget: 1s, 2s, 4s, ... capped at loginGlobalBackoffMax.
func globalBackoff(excess int) time.Duration {
	if excess > 16 {
		excess = 16
	}
	delay := loginGlobalBackoffBase << excess
	if delay > loginGlobalBackoffMax {
		delay = loginGlobalBackoffMax
	}
	return delay
}

func (s *Server) recordFailure(action credentialAction, key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	s.pruneLoginAttemptsLocked(now.Add(-loginFailureWindow))
	s.loginAttempts[key] = append(s.loginAttempts[key], now)
	global := append(s.globalFailures[action], now)
	// Beyond the budget only the count up to the backoff cap matters.
	if limit := loginGlobalFailureBudget + 17; len(global) > limit {
		global = append(global[:0:0], global[len(global)-limit:]...)
	}
	s.globalFailures[action] = global
	// Keep the map bounded even when this is called without a preceding
	// throttled check (for example, from a future authentication flow).
	s.pruneLoginAttemptsLocked(now.Add(-loginFailureWindow))
}

// clearFailures resets one client bucket after a successful submission. The
// global budget is deliberately left alone: it measures failures from every
// source and must not be reset by the success it is protecting.
func (s *Server) clearFailures(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginAttempts, key)
}

func (s *Server) pruneLoginAttemptsLocked(cutoff time.Time) {
	for key, attempts := range s.loginAttempts {
		kept := attempts[:0]
		for _, at := range attempts {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(s.loginAttempts, key)
			continue
		}
		s.loginAttempts[key] = kept
	}
	for len(s.loginAttempts) > maxTrackedLoginIPs {
		var oldestKey string
		var oldest time.Time
		for key, attempts := range s.loginAttempts {
			candidate := attempts[0]
			if oldestKey == "" || candidate.Before(oldest) {
				oldestKey, oldest = key, candidate
			}
		}
		delete(s.loginAttempts, oldestKey)
	}
	for action, failures := range s.globalFailures {
		kept := failures[:0]
		for _, at := range failures {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(s.globalFailures, action)
			continue
		}
		s.globalFailures[action] = kept
	}
}

// renderThrottled answers a throttled credential submission with 429 and a
// Retry-After header (whole seconds, rounded up) while still rendering the
// form so a browser user sees the reason.
func (s *Server) renderThrottled(w http.ResponseWriter, r *http.Request, name string, action credentialAction, message string, retry time.Duration) {
	seconds := int64((retry + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	s.renderCredentialStatus(w, r, name, action, pageData{Error: message}, http.StatusTooManyRequests)
}

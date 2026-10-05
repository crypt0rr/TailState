package web

import (
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// A newly created API token must be shown exactly once, after the
// Post/Redirect/Get redirect that follows its creation. The secret is held
// here, in process memory only, under a random reference that travels in
// the signed flash cookie. The reference is redeemed once, by the session
// that created the token, within flashMaxAge; afterwards (or after a
// restart) the secret is gone and only its hash remains in the database.
const (
	revealLifetime = flashMaxAge * time.Second
	maxReveals     = 64
)

var errRevealsFull = errors.New("too many API tokens are waiting to be displayed")

type pendingReveal struct {
	secret     string
	sessionRef string
	expires    time.Time
}

type revealStore struct {
	mu      sync.Mutex
	pending map[string]pendingReveal
}

func newRevealStore() *revealStore {
	return &revealStore{pending: map[string]pendingReveal{}}
}

func (r *revealStore) prune(now time.Time) {
	for key, reveal := range r.pending {
		if !now.Before(reveal.expires) {
			delete(r.pending, key)
		}
	}
}

// put holds secretValue for sessionRef and returns its one-time reference.
func (r *revealStore) put(secretValue, sessionRef string, now time.Time) (string, error) {
	reference, err := secret.Token(18)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	if len(r.pending) >= maxReveals {
		return "", errRevealsFull
	}
	r.pending[reference] = pendingReveal{secret: secretValue, sessionRef: sessionRef, expires: now.Add(revealLifetime)}
	return reference, nil
}

// take returns and forgets the secret held under reference. It succeeds only
// once, before expiry, and only for the session that created it; a wrong
// session leaves the entry untouched so it cannot be used to discard it.
func (r *revealStore) take(reference, sessionRef string, now time.Time) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	reveal, ok := r.pending[reference]
	if !ok || sessionRef == "" || subtle.ConstantTimeCompare([]byte(reveal.sessionRef), []byte(sessionRef)) != 1 {
		return "", false
	}
	delete(r.pending, reference)
	return reveal.secret, true
}

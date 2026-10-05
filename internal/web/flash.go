package web

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/textutil"
)

// Flash messages carry the outcome of a POST across the Post/Redirect/Get
// redirect. The value is HMAC-signed with the process key, so another site
// or a sibling host cannot plant text on a TailState page, and it is cleared
// when the next page displays it, so a reload never shows (or repeats) it.
const (
	flashCookieName  = "tailstate_flash"
	flashMaxAge      = 60
	flashMaxMessage  = 512
	flashKindSuccess = "success"
	flashKindError   = "error"
)

type flashMessage struct {
	Kind    string `json:"k"`
	Message string `json:"m"`
	// Reveal is an opaque reference to a one-time secret held in server
	// memory (a newly created API token); the secret itself is never put in
	// the cookie.
	Reveal string `json:"r,omitempty"`
}

func (s *Server) flashSignature(payload string) []byte {
	return s.signCredentialChallenge([]byte("flash\x00" + payload))
}

// setFlash stores one message for the next page view.
func (s *Server) setFlash(w http.ResponseWriter, kind, message string) {
	s.setFlashWith(w, flashMessage{Kind: kind, Message: message})
}

// setFlashWith stores a complete flash message for the next page view.
func (s *Server) setFlashWith(w http.ResponseWriter, message flashMessage) {
	message.Message = textutil.Truncate(message.Message, flashMaxMessage)
	encoded, _ := json.Marshal(message)
	payload := base64.RawURLEncoding.EncodeToString(encoded)
	value := payload + "." + base64.RawURLEncoding.EncodeToString(s.flashSignature(payload))
	http.SetCookie(w, &http.Cookie{Name: flashCookieName, Value: value, Path: "/", MaxAge: flashMaxAge, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
}

// takeFlash returns and clears the pending message, if any. A tampered or
// malformed cookie is discarded silently.
func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) (flashMessage, bool) {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return flashMessage{}, false
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	payload, signature, found := strings.Cut(cookie.Value, ".")
	if !found {
		return flashMessage{}, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(mac, s.flashSignature(payload)) {
		return flashMessage{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return flashMessage{}, false
	}
	var message flashMessage
	if json.Unmarshal(raw, &message) != nil || message.Message == "" || (message.Kind != flashKindSuccess && message.Kind != flashKindError) {
		return flashMessage{}, false
	}
	return message, true
}

// applyFlash moves a pending flash message into the page data. A reveal
// reference is redeemed only by the session that created it.
func (s *Server) applyFlash(w http.ResponseWriter, r *http.Request, data *pageData) {
	message, ok := s.takeFlash(w, r)
	if !ok {
		return
	}
	if message.Reveal != "" {
		ref := ""
		if session, _, found := s.sessionCookies(r); found {
			ref = store.SessionRef(session.Value)
		}
		if secretValue, found := s.tokenReveals.take(message.Reveal, ref, time.Now()); found {
			data.NewAPIToken = secretValue
		} else {
			data.Error = "The new API token can no longer be displayed. Revoke it and create another."
			return
		}
	}
	if message.Kind == flashKindError {
		data.Error = message.Message
		return
	}
	data.Message = message.Message
}

// redirectWithFlash completes a Post/Redirect/Get step.
func (s *Server) redirectWithFlash(w http.ResponseWriter, r *http.Request, target, kind, message string) {
	s.setFlash(w, kind, message)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

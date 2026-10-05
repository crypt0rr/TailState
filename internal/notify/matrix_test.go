package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// homeserver is a minimal Matrix client-server API mock that counts logins
// and room messages.
type homeserver struct {
	mu       sync.Mutex
	logins   int
	flows    int
	messages []string
	// login, when set, replaces the successful password-login response.
	login http.HandlerFunc
}

func (h *homeserver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/login":
		h.flows++
		_, _ = w.Write([]byte(`{"flows":[{"type":"m.login.password"}]}`))
	case r.Method == http.MethodPost && r.URL.Path == "/_matrix/client/v3/login":
		h.logins++
		if h.login != nil {
			h.login(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"session-token","user_id":"@bot:example","device_id":"SHDEVICE"}`))
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/rooms/!room:example/send/m.room.message/"):
		h.messages = append(h.messages, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"event_id":"$event"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *homeserver) counts() (flows, logins, messages int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.flows, h.logins, len(h.messages)
}

func matrixURL(server *httptest.Server, credentials string) string {
	return "matrix://" + credentials + "@" + strings.TrimPrefix(server.URL, "http://") + "/?rooms=!room:example&disableTLS=yes"
}

// TestMatrixPasswordURLLogsInOncePerDelivery guards the regression where
// Send validated the URL by constructing one sender (logging in) and then
// constructed a second sender (logging in again) for every delivery.
func TestMatrixPasswordURLLogsInOncePerDelivery(t *testing.T) {
	mock := &homeserver{}
	server := httptest.NewServer(mock)
	defer server.Close()
	if err := New().Send(context.Background(), matrixURL(server, "bot:password"), "hello"); err != nil {
		t.Fatalf("send: %v", err)
	}
	flows, logins, messages := mock.counts()
	if flows != 1 || logins != 1 || messages != 1 {
		t.Fatalf("one delivery made %d login-flow requests, %d logins, %d messages; want 1, 1, 1", flows, logins, messages)
	}
	if mock.messages[0] != "Bearer session-token" {
		t.Fatalf("message used authorization %q", mock.messages[0])
	}
}

// TestMatrixTokenURLNeverLogsIn documents the supported way to avoid a login
// per delivery: an access-token URL authenticates without a login request.
func TestMatrixTokenURLNeverLogsIn(t *testing.T) {
	mock := &homeserver{}
	server := httptest.NewServer(mock)
	defer server.Close()
	serviceURL := matrixURL(server, ":access-token")
	if err := Validate(serviceURL); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := New().Send(context.Background(), serviceURL, "hello"); err != nil {
		t.Fatalf("send: %v", err)
	}
	flows, logins, messages := mock.counts()
	if flows != 0 || logins != 0 || messages != 1 {
		t.Fatalf("token URL made %d login-flow requests, %d logins, %d messages; want 0, 0, 1", flows, logins, messages)
	}
	if mock.messages[0] != "Bearer access-token" {
		t.Fatalf("message used authorization %q", mock.messages[0])
	}
}

// TestMatrixLoginUsesTailStateTransport verifies that the login performed
// while the Matrix sender is constructed goes through TailState's
// redirect-rejecting, response-recording transport.
func TestMatrixLoginUsesTailStateTransport(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer target.Close()
	mock := &homeserver{login: func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/_matrix/client/v3/login", http.StatusTemporaryRedirect)
	}}
	server := httptest.NewServer(mock)
	defer server.Close()
	err := New().Send(context.Background(), matrixURL(server, "bot:password"), "hello")
	if redirected {
		t.Fatal("Matrix login followed a redirect outside TailState's transport policy")
	}
	var delivery *DeliveryError
	if !errors.As(err, &delivery) || delivery.Status != http.StatusTemporaryRedirect {
		t.Fatalf("login redirect error = %#v, want DeliveryError with HTTP 307", err)
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("login error leaked the password: %v", err)
	}
}

// TestMatrixLoginRejectionIsClassified verifies that a failed login is a
// delivery outcome: a rejected password dead-letters and a login rate limit
// carries its Retry-After hint.
func TestMatrixLoginRejectionIsClassified(t *testing.T) {
	forbidden := &homeserver{login: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"Invalid password"}`))
	}}
	server := httptest.NewServer(forbidden)
	defer server.Close()
	err := New().Send(context.Background(), matrixURL(server, "bot:wrong"), "hello")
	if !IsPermanent(err) || SafeDeliveryError(err) != "notification rejected by provider (HTTP 403)" {
		t.Fatalf("rejected login = %#v (%q)", err, SafeDeliveryError(err))
	}

	limited := &homeserver{login: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errcode":"M_LIMIT_EXCEEDED","error":"Too many requests"}`))
	}}
	limitedServer := httptest.NewServer(limited)
	defer limitedServer.Close()
	err = New().Send(context.Background(), matrixURL(limitedServer, "bot:password"), "hello")
	var delivery *DeliveryError
	if !errors.As(err, &delivery) || delivery.Status != http.StatusTooManyRequests || delivery.RetryAfter.Seconds() != 30 || delivery.Permanent {
		t.Fatalf("rate-limited login = %#v", err)
	}
}

func TestMatrixSendFailureAndInvalidURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	err := New().Send(context.Background(), matrixURL(server, ":access-token"), "hello")
	var delivery *DeliveryError
	if !errors.As(err, &delivery) || delivery.Status != http.StatusBadGateway || delivery.Permanent {
		t.Fatalf("matrix send failure = %#v", err)
	}
	if err := New().Send(context.Background(), "  ", "hello"); err == nil || err.Error() != "notification URL is required" {
		t.Fatalf("empty URL error = %v", err)
	}
	err = New().Send(context.Background(), "matrix://bot:password@host.example/?disableTLS=maybe", "hello")
	if err == nil || IsPermanent(err) || !strings.HasPrefix(err.Error(), "invalid notification URL") || strings.Contains(err.Error(), "password") {
		t.Fatalf("invalid Matrix URL error = %v", err)
	}
	if err := Validate("matrix://bot:password@host.example/?disableTLS=maybe"); err == nil {
		t.Fatal("invalid Matrix URL was accepted")
	}
}

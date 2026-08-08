package tailscale

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type coverageRoundTripper func(*http.Request) (*http.Response, error)

func (f coverageRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOAuthResponseValidation(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "http failure", status: http.StatusBadGateway, body: `upstream`, want: "OAuth token request returned 502"},
		{name: "malformed json", status: http.StatusOK, body: `{`, want: "unexpected end of JSON input"},
		{name: "missing access token", status: http.StatusOK, body: `{"expires_in":3600}`, want: "did not include access_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/token" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
			if _, err := client.Collect(context.Background(), "devices"); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":0}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "devices"); err != nil {
		t.Fatalf("non-positive expires_in should use the fallback: %v", err)
	}

	closedURL := server.URL
	server.Close()
	client = New(closedURL+"/api/v2", closedURL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "devices"); err == nil {
		t.Fatal("closed OAuth endpoint unexpectedly succeeded")
	}
}

func TestCollectorEdgeResponsesAndFallbackIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case r.URL.Path == "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"hostname":"no-id"}]}`))
		case r.URL.Path == "/api/v2/tailnet/-/users":
			_, _ = w.Write([]byte(`{"users":[{"description":"anonymous"}]}`))
		case strings.Contains(r.URL.Path, "/dns/"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/logging/configuration/stream"):
			_, _ = w.Write([]byte(`{"enabled":true}`))
		case strings.HasSuffix(r.URL.Path, "/logging/configuration/stream/status"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	newClient := func() *Client {
		return New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	}
	if resources, err := newClient().Collect(context.Background(), "device_details"); err != nil || len(resources) != 0 {
		t.Fatalf("device without an ID = %#v, %v", resources, err)
	}
	resources, err := newClient().Collect(context.Background(), "users")
	if err != nil || len(resources) != 1 || !strings.HasPrefix(resources[0].ID, "users-") {
		t.Fatalf("fallback collection ID = %#v, %v", resources, err)
	}
	if _, err := newClient().Collect(context.Background(), "dns"); err == nil || !IsUnsupported(err) {
		t.Fatalf("all-unsupported DNS error = %v", err)
	}
	if _, err := newClient().Collect(context.Background(), "log_streaming"); err == nil || !strings.Contains(err.Error(), "returned 500") {
		t.Fatalf("log status failure = %v", err)
	}
}

func TestPaginationURLValidationAndExhaustion(t *testing.T) {
	client := New("https://api.example.test/api/v2", "https://oauth.example.test/token", "test", Credentials{})
	for name, args := range map[string][2]string{
		"bad current":   {"://bad", "?cursor=1"},
		"bad candidate": {"/api/v2/devices", "://bad"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.resolvePaginationURL(args[0], args[1]); err == nil {
				t.Fatal("invalid pagination URL unexpectedly succeeded")
			}
		})
	}
	outsidePath, err := client.resolvePaginationURL("/api/v2/devices", "https://api.example.test/other/devices")
	if err == nil || !strings.Contains(err.Error(), "outside the configured Tailscale API path") || outsidePath != "" {
		t.Fatalf("outside path result = %q, %v", outsidePath, err)
	}

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		requests++
		_, _ = w.Write([]byte(fmt.Sprintf(`{"devices":[],"next":"?cursor=%d"}`, requests)))
	}))
	defer server.Close()
	client = New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "devices"); err == nil || !strings.Contains(err.Error(), "exceeded 100 pages") {
		t.Fatalf("pagination exhaustion error = %v", err)
	}
	if requests != 100 {
		t.Fatalf("pagination requests = %d, want 100", requests)
	}
}

func TestPaginationHelpersAndGetRetryBranches(t *testing.T) {
	if got := nextURL(map[string]any{"next": "/next"}); got != "/next" {
		t.Fatalf("direct next URL=%q", got)
	}
	if got := nextURL(map[string]any{"pagination": map[string]any{"next": "/page"}}); got != "/page" {
		t.Fatalf("nested next URL=%q", got)
	}
	if got := nextURL(map[string]any{"pagination": map[string]any{"nextCursor": "a b"}}); got != "?cursor=a+b" {
		t.Fatalf("cursor next URL=%q", got)
	}
	if got := nextURL(map[string]any{"pagination": map[string]any{"nextCursor": ""}}); got != "" {
		t.Fatalf("empty cursor next URL=%q", got)
	}

	responses := []int{http.StatusUnauthorized, http.StatusNoContent}
	getAttempts := 0
	client := New("https://api.example.test/api/v2", "https://oauth.example.test/token", "test", Credentials{})
	client.token = "cached"
	client.expires = time.Now().Add(time.Hour)
	client.http = &http.Client{Transport: coverageRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return &http.Response{StatusCode: http.StatusOK, Status: "200", Body: io.NopCloser(strings.NewReader(`{"access_token":"refreshed","expires_in":3600}`))}, nil
		}
		status := responses[0]
		responses = responses[1:]
		getAttempts++
		body := "{}"
		if status == http.StatusNoContent {
			body = ""
		}
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d", status), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	value, err := client.get(context.Background(), "https://api.example.test/api/v2/devices")
	if err != nil || value != nil || len(responses) != 0 || getAttempts != 2 {
		t.Fatalf("401 retry/empty response value=%#v err=%v remaining=%d attempts=%d", value, err, len(responses), getAttempts)
	}

	badJSON := New("https://api.example.test/api/v2", "https://oauth.example.test/token", "test", Credentials{})
	badJSON.token, badJSON.expires = "cached", time.Now().Add(time.Hour)
	badJSON.http = &http.Client{Transport: coverageRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200", Body: io.NopCloser(strings.NewReader("{"))}, nil
	})}
	if _, err := badJSON.get(context.Background(), "https://api.example.test/api/v2/devices"); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("invalid JSON error=%v", err)
	}
	rate := New("https://api.example.test/api/v2", "https://oauth.example.test/token", "test", Credentials{})
	rate.token, rate.expires = "cached", time.Now().Add(time.Hour)
	rateAttempts := 0
	rate.http = &http.Client{Transport: coverageRoundTripper(func(*http.Request) (*http.Response, error) {
		rateAttempts++
		if rateAttempts == 1 {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Status: "429", Header: http.Header{"Retry-After": []string{"0"}}, Body: io.NopCloser(strings.NewReader("busy"))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200", Body: io.NopCloser(strings.NewReader(`{"devices":[]}`))}, nil
	})}
	if value, err := rate.get(context.Background(), "https://api.example.test/api/v2/devices"); err != nil || value == nil || rateAttempts != 2 {
		t.Fatalf("429 retry value=%#v err=%v attempts=%d", value, err, rateAttempts)
	}
}

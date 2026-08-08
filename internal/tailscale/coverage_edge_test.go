package tailscale

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

package tailscale

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthPaginationAndCollection(t *testing.T) {
	tokenCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			tokenCalls++
			_ = r.ParseForm()
			if r.FormValue("scope") != "all:read" {
				t.Errorf("scope=%q", r.FormValue("scope"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case r.URL.Path == "/api/v2/tailnet/-/devices":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Errorf("authorization missing")
			}
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("cursor") == "2" {
				_, _ = w.Write([]byte(`{"devices":[{"id":"2","hostname":"two"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"devices":[{"id":"1","hostname":"one"}],"next":"/api/v2/tailnet/-/devices?fields=all&cursor=2"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{Tailnet: "-", ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "devices")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 || resources[0].ID != "1" || resources[1].ID != "2" {
		t.Fatalf("unexpected resources: %#v", resources)
	}
	if tokenCalls != 1 {
		t.Fatalf("token requested %d times", tokenCalls)
	}
}

func TestEmptyCollectionResponses(t *testing.T) {
	tests := []struct {
		name      string
		collector string
		path      string
		body      string
		wantErr   bool
		wantMatch string
	}{
		{name: "user invites missing array", collector: "user_invites", path: "/api/v2/tailnet/-/user-invites", body: `{}`, wantErr: true},
		{name: "user invites top-level array", collector: "user_invites", path: "/api/v2/tailnet/-/user-invites", body: `[]`},
		{name: "webhooks missing array", collector: "webhooks", path: "/api/v2/tailnet/-/webhooks", body: `{}`, wantErr: true},
		{name: "webhooks null array", collector: "webhooks", path: "/api/v2/tailnet/-/webhooks", body: `{"webhooks":null}`, wantErr: true},
		{name: "webhooks empty array", collector: "webhooks", path: "/api/v2/tailnet/-/webhooks", body: `{"webhooks":[]}`},
		{name: "webhooks non-object item", collector: "webhooks", path: "/api/v2/tailnet/-/webhooks", body: `{"webhooks":[null]}`, wantErr: true, wantMatch: "contains a non-object item"},
		{name: "strict collection still rejects missing array", collector: "users", path: "/api/v2/tailnet/-/users", body: `{}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
				case tt.path:
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tt.body))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
			resources, err := client.Collect(context.Background(), tt.collector)
			if tt.wantErr {
				match := tt.wantMatch
				if match == "" {
					match = "response has no"
				}
				if err == nil || !strings.Contains(err.Error(), match) {
					t.Fatalf("expected missing-array error, got resources=%#v err=%v", resources, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("empty collection failed: %v", err)
			}
			if len(resources) != 0 {
				t.Fatalf("expected no resources, got %#v", resources)
			}
		})
	}
}

func TestAbsentCollectionKeyIsNotEmpty(t *testing.T) {
	for _, collector := range []string{"user_invites", "webhooks"} {
		t.Run(collector, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
				case "/api/v2/tailnet/-/user-invites", "/api/v2/tailnet/-/webhooks":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
			resources, err := client.Collect(context.Background(), collector)
			if err == nil || len(resources) != 0 || !strings.Contains(err.Error(), "response has no") {
				t.Fatalf("absent %s key was treated as empty: resources=%#v err=%v", collector, resources, err)
			}
		})
	}
}

func TestCollectionRejectsWrongArrayType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"webhooks":"not-an-array"}`))
	}))
	defer server.Close()

	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "webhooks"); err == nil || !strings.Contains(err.Error(), "webhooks response webhooks is not an array") {
		t.Fatalf("expected wrong-array-type error, got %v", err)
	}
}

func TestUnsupportedCollector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	_, err := client.Collect(context.Background(), "contacts")
	if err == nil || !IsUnsupported(err) {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func TestCoreCollectorNotFoundIsNotUnsupported(t *testing.T) {
	err := &HTTPError{Status: http.StatusNotFound, URL: "devices"}
	if IsUnsupportedCollector("devices", err) || IsUnsupportedCollector("device_details", err) {
		t.Fatal("core collector 404 was treated as a plan limitation")
	}
	if !IsUnsupportedCollector("users", err) {
		t.Fatal("optional collector 404 was not treated as unsupported")
	}
}

func TestDNSKeepsSupportedSubresources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		if r.URL.Path == "/api/v2/tailnet/-/dns/split-dns" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "dns")
	if err != nil || len(resources) != 1 {
		t.Fatalf("DNS collection failed: %#v %v", resources, err)
	}
}

func TestDeviceDetailsDoNotRefetchCoreDevice(t *testing.T) {
	coreDetailCalls := 0
	deviceListCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case r.URL.Path == "/api/v2/tailnet/-/devices":
			deviceListCalls++
			_, _ = w.Write([]byte(`{"devices":[{"id":"1","hostname":"server","addresses":["100.64.0.1"]}]}`))
		case r.URL.Path == "/api/v2/device/1":
			coreDetailCalls++
			_, _ = w.Write([]byte(`{"id":"1","hostname":"server"}`))
		case r.URL.Path == "/api/v2/device/1/routes":
			_, _ = w.Write([]byte(`{"enabledRoutes":["10.0.0.0/24"]}`))
		case r.URL.Path == "/api/v2/device/1/attributes":
			_, _ = w.Write([]byte(`{"attributes":{"node:os":"linux"}}`))
		case r.URL.Path == "/api/v2/device/1/device-invites":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "devices"); err != nil {
		t.Fatal(err)
	}
	resources, err := client.Collect(context.Background(), "device_details")
	if err != nil {
		t.Fatal(err)
	}
	if coreDetailCalls != 0 {
		t.Fatalf("core device was fetched %d additional time(s)", coreDetailCalls)
	}
	if deviceListCalls != 1 {
		t.Fatalf("device list was fetched %d time(s), want one shared response", deviceListCalls)
	}
	if len(resources) != 1 {
		t.Fatalf("unexpected device details: %#v", resources)
	}
	data, ok := resources[0].Data.(map[string]any)
	if !ok || data["routes"] == nil || data["postureAttributes"] == nil || data["deviceInvites"] == nil {
		t.Fatalf("secondary details missing: %#v", resources[0].Data)
	}
}

func TestDeviceDetailNotFoundIsPartialNotUnsupported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"missing","hostname":"missing"},{"id":"healthy","hostname":"healthy"}]}`))
		case "/api/v2/device/missing/routes":
			http.NotFound(w, r)
		case "/api/v2/device/healthy/routes":
			_, _ = w.Write([]byte(`{"enabledRoutes":[]}`))
		case "/api/v2/device/missing/attributes", "/api/v2/device/missing/device-invites",
			"/api/v2/device/healthy/attributes", "/api/v2/device/healthy/device-invites":
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "device_details")
	if err == nil || !strings.Contains(err.Error(), "partial collector response") {
		t.Fatalf("expected partial detail error, got resources=%#v err=%v", resources, err)
	}
	var partial *PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("partial detail error did not retain its type: %v", err)
	}
	if partial.Count != 1 {
		t.Fatalf("partial detail error count=%d, err=%v", partial.Count, err)
	}
	if len(resources) != 1 || resources[0].ID != "healthy" {
		t.Fatalf("expected only the healthy device detail, got %#v", resources)
	}
	data, ok := resources[0].Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected resource data %#v", resources[0].Data)
	}
	routes, ok := data["routes"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected routes data: %#v", data["routes"])
	}
	if _, unsupported := routes["unsupported"]; unsupported {
		t.Fatalf("404 detail endpoint was marked unsupported: %#v", data)
	}
}

func TestDeviceDetailsDeadlineKeepsHealthyResults(t *testing.T) {
	previousTimeout := deviceDetailsPollTimeout
	// Leave enough room for the healthy device's three quick requests under the
	// race detector while keeping the slow device well outside the deadline.
	deviceDetailsPollTimeout = 200 * time.Millisecond
	t.Cleanup(func() { deviceDetailsPollTimeout = previousTimeout })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"healthy","hostname":"healthy"},{"id":"slow","hostname":"slow"}]}`))
		case "/api/v2/device/slow/routes", "/api/v2/device/slow/attributes", "/api/v2/device/slow/device-invites":
			time.Sleep(1 * time.Second)
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "device_details")
	if err == nil || !strings.Contains(err.Error(), "partial collector response") {
		t.Fatalf("deadline did not produce partial result: resources=%#v err=%v", resources, err)
	}
	if len(resources) != 1 || resources[0].ID != "healthy" {
		t.Fatalf("healthy device detail was lost at deadline: %#v", resources)
	}
}

func TestDeviceDetailsFanoutIsBounded(t *testing.T) {
	var active, maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},{"id":"6"},{"id":"7"},{"id":"8"},{"id":"9"},{"id":"10"},{"id":"11"},{"id":"12"}]}`))
		default:
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			active.Add(-1)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "device_details"); err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got > 8 {
		t.Fatalf("device detail fan-out reached %d concurrent requests, want <=8", got)
	}
}

func TestLogStreamingUsesCurrentStatusEndpoint(t *testing.T) {
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/tailnet/-/logging/configuration/stream",
			"/api/v2/tailnet/-/logging/network/stream":
			_, _ = w.Write([]byte(`{"destinationType":"http"}`))
		case "/api/v2/tailnet/-/logging/configuration/stream/status",
			"/api/v2/tailnet/-/logging/network/stream/status":
			_, _ = w.Write([]byte(`{"lastActivity":"now","numEntriesSent":42,"lastError":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "log_streaming")
	if err != nil || len(resources) != 1 {
		t.Fatalf("log streaming collection failed: %#v %v", resources, err)
	}
	for _, path := range requested {
		if strings.HasSuffix(path, "/logging/configuration/status") || strings.HasSuffix(path, "/logging/network/status") {
			t.Fatalf("obsolete status endpoint requested: %s", path)
		}
	}
}

func TestSuccessfulNonJSONResponseFailsCollection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte("upstream unavailable"))
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "contacts"); err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}
}

func TestOversizedSuccessfulResponseFailsCollection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(strconv.Quote(strings.Repeat("x", maxAPIResponseBytes))))
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "contacts"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized response error, got %v", err)
	}
}

func TestPaginationCannotLeaveConfiguredAPIOrigin(t *testing.T) {
	var externalCalls int
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalCalls++
		_, _ = w.Write([]byte(`{"devices":[]}`))
	}))
	defer external.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`{"devices":[{"id":"1"}],"next":"` + external.URL + `/api/v2/tailnet/-/devices"}`))
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "devices"); err == nil || !strings.Contains(err.Error(), "outside the configured Tailscale API") {
		t.Fatalf("expected pagination origin error, got %v", err)
	}
	if externalCalls != 0 {
		t.Fatalf("external pagination target was requested %d time(s)", externalCalls)
	}
}

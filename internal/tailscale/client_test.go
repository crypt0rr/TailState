package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case r.URL.Path == "/api/v2/tailnet/-/devices":
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
	resources, err := client.Collect(context.Background(), "device_details")
	if err != nil {
		t.Fatal(err)
	}
	if coreDetailCalls != 0 {
		t.Fatalf("core device was fetched %d additional time(s)", coreDetailCalls)
	}
	if len(resources) != 1 {
		t.Fatalf("unexpected device details: %#v", resources)
	}
	data, ok := resources[0].Data.(map[string]any)
	if !ok || data["routes"] == nil || data["postureAttributes"] == nil || data["deviceInvites"] == nil {
		t.Fatalf("secondary details missing: %#v", resources[0].Data)
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

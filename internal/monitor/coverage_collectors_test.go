package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// fakeTailnetAPI serves spec-shaped responses from a mutable path table. A
// path missing from the table returns 404. When granted is non-nil, only the
// listed scopes are honored: the token request must ask for exactly them and
// endpoints that need another scope return 403.
type fakeTailnetAPI struct {
	mu        sync.Mutex
	responses map[string]string
	granted   map[string]bool
	scope     string
}

func (a *fakeTailnetAPI) set(path, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if body == "" {
		delete(a.responses, path)
		return
	}
	a.responses[path] = body
}

var endpointScopes = map[string]string{
	"/api/v2/tailnet/-/devices":              "devices:core:read",
	"/api/v2/tailnet/-/users":                "users:read",
	"/api/v2/tailnet/-/user-invites":         "user_invites:read",
	"/api/v2/tailnet/-/dns/configuration":    "dns:read",
	"/api/v2/tailnet/-/dns/nameservers":      "dns:read",
	"/api/v2/tailnet/-/dns/preferences":      "dns:read",
	"/api/v2/tailnet/-/dns/searchpaths":      "dns:read",
	"/api/v2/tailnet/-/dns/split-dns":        "dns:read",
	"/api/v2/tailnet/-/acl":                  "policy_file:read",
	"/api/v2/tailnet/-/keys":                 "auth_keys:read",
	"/api/v2/tailnet/-/webhooks":             "webhooks:read",
	"/api/v2/tailnet/-/contacts":             "account_settings:read",
	"/api/v2/tailnet/-/posture/integrations": "feature_settings:read",
	"/api/v2/tailnet/-/settings":             "feature_settings:read",
	"/api/v2/tailnet/-/services":             "services:read",
	"/api/v2/tailnet/-/oauth-apps":           "oauth_apps:read",
}

func (a *fakeTailnetAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/oauth/token" {
		_ = r.ParseForm()
		a.scope = r.FormValue("scope")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		return
	}
	if a.granted != nil {
		needed, known := endpointScopes[r.URL.Path]
		if strings.HasPrefix(r.URL.Path, "/api/v2/tailnet/-/logging/") {
			needed, known = "log_streaming:read", true
		}
		if !known || !a.granted[needed] {
			http.Error(w, `{"message":"insufficient scope"}`, http.StatusForbidden)
			return
		}
	}
	body, ok := a.responses[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func newFakeTailnet(t *testing.T, scopes ...string) (*fakeTailnetAPI, *httptest.Server) {
	t.Helper()
	api := &fakeTailnetAPI{responses: map[string]string{
		"/api/v2/tailnet/-/devices": `{"devices":[{"id":"d1","name":"server.example.ts.net"}]}`,
	}}
	if len(scopes) > 0 {
		api.granted = map[string]bool{}
		for _, scope := range scopes {
			api.granted[scope] = true
		}
	}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	return api, server
}

func collectorEvents(t *testing.T, st *store.Store, collector string) []store.HistoryEvent {
	t.Helper()
	page, err := st.ListHistory(context.Background(), store.HistoryFilter{Collector: collector, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var events []store.HistoryEvent
	for _, batch := range page.Batches {
		events = append(events, batch.Events...)
	}
	return events
}

const (
	legacyNameservers = `{"dns":["8.8.8.8","1.1.1.1"]}`
	legacyPreferences = `{"magicDNS":true}`
	legacySearchPaths = `{"searchPaths":["corp.example.com"]}`
	legacySplitDNS    = `{"corp.example.com":["10.0.0.53","10.0.1.53"],"empty.example.com":null}`
	// The same configuration as returned by dns/configuration (spec shape),
	// including the fields the legacy endpoints cannot express.
	dnsConfiguration = `{"nameservers":[{"address":"8.8.8.8","useWithExitNode":true},{"address":"1.1.1.1","useWithExitNode":false}],"preferences":{"overrideLocalDNS":true,"magicDNS":true},"searchPaths":["corp.example.com"],"splitDNS":{"corp.example.com":[{"address":"10.0.1.53","useWithExitNode":true},{"address":"10.0.0.53","useWithExitNode":true}],"empty.example.com":null}}`
)

func serveLegacyDNS(api *fakeTailnetAPI) {
	api.set("/api/v2/tailnet/-/dns/nameservers", legacyNameservers)
	api.set("/api/v2/tailnet/-/dns/preferences", legacyPreferences)
	api.set("/api/v2/tailnet/-/dns/searchpaths", legacySearchPaths)
	api.set("/api/v2/tailnet/-/dns/split-dns", legacySplitDNS)
}

// TestDNSConfigurationMigrationProducesNoEventsOnUpgrade baselines DNS through
// the legacy endpoints (as a previous release stored it), then upgrades to
// the dns/configuration endpoint. The shape change and the newly visible
// useWithExitNode/overrideLocalDNS fields must not be reported; a later real
// change is reported normally, and falling back to the legacy endpoints is
// silent as well.
func TestDNSConfigurationMigrationProducesNoEventsOnUpgrade(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api, server := newFakeTailnet(t)
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test")
	serveLegacyDNS(api)
	poll := func(label string) {
		t.Helper()
		if !engine.poll(ctx, client, settings, []string{"devices", "dns"}, true) {
			t.Fatalf("%s poll failed", label)
		}
	}
	poll("legacy baseline")
	poll("legacy steady state")
	if events := collectorEvents(t, st, "dns"); len(events) != 0 {
		t.Fatalf("legacy baseline reported %d events", len(events))
	}

	api.set("/api/v2/tailnet/-/dns/configuration", dnsConfiguration)
	poll("upgrade")
	poll("post-upgrade steady state")
	if events := collectorEvents(t, st, "dns"); len(events) != 0 {
		t.Fatalf("DNS migration reported drift on upgrade: %#v", events)
	}
	records, err := st.CollectorSnapshots(ctx, settings.Generation, "dns")
	if err != nil || len(records) != 1 || !strings.Contains(string(records[0].Raw), "useWithExitNode") {
		t.Fatalf("snapshot was not migrated to the configuration shape: %v err=%v", records, err)
	}

	// The configuration endpoint exposes useWithExitNode; changing it is drift.
	api.set("/api/v2/tailnet/-/dns/configuration", strings.Replace(dnsConfiguration, `"address":"1.1.1.1","useWithExitNode":false`, `"address":"1.1.1.1","useWithExitNode":true`, 1))
	poll("exit-node change")
	events := collectorEvents(t, st, "dns")
	if len(events) != 1 || events[0].EventType != "changed" {
		t.Fatalf("useWithExitNode change events=%#v", events)
	}

	// Falling back to the legacy endpoints (configuration returns 404) is
	// silent when the comparable configuration is unchanged.
	api.set("/api/v2/tailnet/-/dns/configuration", "")
	poll("fallback")
	if events := collectorEvents(t, st, "dns"); len(events) != 1 {
		t.Fatalf("fallback to legacy endpoints reported drift: %#v", events)
	}
	// A real change across a shape transition is still reported.
	api.set("/api/v2/tailnet/-/dns/configuration", strings.Replace(dnsConfiguration, `"searchPaths":["corp.example.com"]`, `"searchPaths":["corp.example.com","lab.example.com"]`, 1))
	poll("changed upgrade")
	events = collectorEvents(t, st, "dns")
	if len(events) != 2 {
		t.Fatalf("real change across shape transition events=%#v", events)
	}
	found := false
	for _, field := range events[0].Fields {
		if strings.HasPrefix(field.Field, "searchPaths") {
			found = true
		}
	}
	if !found {
		t.Fatalf("transition diff does not name the search path change: %#v", events[0].Fields)
	}
}

// TestNewCollectorsBaselineSilentlyOnExistingInstall upgrades an established
// installation: the services and oauth_apps collectors appear for the first
// time and must baseline silently; later changes are reported.
func TestNewCollectorsBaselineSilentlyOnExistingInstall(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api, server := newFakeTailnet(t)
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test")
	if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
		t.Fatal("existing baseline poll failed")
	}
	api.set("/api/v2/tailnet/-/services", `{"vipServices":[{"name":"svc:web","displayName":"Web","addrs":["100.100.100.10","fd7a:115c:a1e0::10"],"comment":"intranet","ports":["tcp:443"],"tags":["tag:web"]}]}`)
	api.set("/api/v2/tailnet/-/oauth-apps", `{"oauthApps":[{"id":"a123","name":"provisioner","description":"provisioning","redirectURIs":["https://example.com/cb"],"scopes":["auth_keys:create"],"allowedNodeAttributes":[],"created":"2026-01-01T00:00:00Z","updated":"2026-01-02T00:00:00Z"}]}`)
	collectors := []string{"services", "oauth_apps"}
	if !engine.poll(ctx, client, settings, collectors, true) {
		t.Fatal("first poll of new collectors failed")
	}
	for _, collector := range collectors {
		if events := collectorEvents(t, st, collector); len(events) != 0 {
			t.Fatalf("%s first baseline was not silent: %#v", collector, events)
		}
	}
	// Volatile timestamps do not count as drift; exposure changes do.
	api.set("/api/v2/tailnet/-/oauth-apps", `{"oauthApps":[{"id":"a123","name":"provisioner","description":"provisioning","redirectURIs":["https://example.com/cb"],"scopes":["auth_keys:create","devices:core"],"allowedNodeAttributes":[],"created":"2026-01-01T00:00:00Z","updated":"2026-03-02T00:00:00Z"}]}`)
	api.set("/api/v2/tailnet/-/services", `{"vipServices":[{"name":"svc:web","displayName":"Web","addrs":["100.100.100.10","fd7a:115c:a1e0::10"],"comment":"intranet","ports":["tcp:443","tcp:22"],"tags":["tag:web"]},{"name":"svc:db","addrs":["100.100.100.11"],"ports":["tcp:5432"]}]}`)
	if !engine.poll(ctx, client, settings, collectors, true) {
		t.Fatal("change poll failed")
	}
	services := collectorEvents(t, st, "services")
	if len(services) != 2 {
		t.Fatalf("services events=%#v", services)
	}
	apps := collectorEvents(t, st, "oauth_apps")
	if len(apps) != 1 || apps[0].EventType != "changed" || len(apps[0].Fields) != 1 || !strings.HasPrefix(apps[0].Fields[0].Field, "scopes") {
		t.Fatalf("oauth_apps events=%#v", apps)
	}
}

// TestLeastPrivilegeClientLabelsUnsupportedCollectors runs a full poll with an
// OAuth client that was granted only some read scopes. The token request
// asks for exactly the configured scopes, the granted collectors baseline,
// and every other optional collector is reported as unsupported with an
// explicit insufficient-scope label instead of failing.
func TestLeastPrivilegeClientLabelsUnsupportedCollectors(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	granted := []string{"devices:core:read", "dns:read", "services:read"}
	api, server := newFakeTailnet(t, granted...)
	api.set("/api/v2/tailnet/-/dns/configuration", dnsConfiguration)
	api.set("/api/v2/tailnet/-/services", `{"vipServices":[]}`)
	settings.OAuthScopes = granted
	if _, err := st.SaveSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	saved, err := st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret", Scopes: saved.OAuthScopes})
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test")
	engine.poll(ctx, client, saved, allCollectors(), true)
	if api.scope != "devices:core:read dns:read services:read" {
		t.Fatalf("token scope=%q", api.scope)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.BaselineReady {
		t.Fatalf("least-privilege baseline not ready: %#v", status)
	}
	states := map[string]store.CollectorState{}
	for _, collector := range status.Collectors {
		states[collector.Name] = collector
	}
	for _, collector := range []string{"devices", "dns", "services"} {
		if state := states[collector]; !state.Supported || !state.Baseline || state.LastError != "" {
			t.Fatalf("%s state=%#v", collector, state)
		}
	}
	for _, collector := range []string{"users", "user_invites", "policy", "keys", "webhooks", "log_streaming", "contacts", "posture", "settings", "oauth_apps"} {
		state := states[collector]
		if state.Supported || !strings.Contains(state.LastError, "insufficient OAuth scope") {
			t.Fatalf("%s state=%#v, want unsupported with an insufficient-scope label", collector, state)
		}
	}
	// device_details is part of the core device inventory; its per-device
	// posture and invite requests degrade to explicit unsupported values.
	if state := states["device_details"]; !state.Supported {
		t.Fatalf("device_details state=%#v", state)
	}
	for _, collector := range []string{"users", "dns", "services", "oauth_apps"} {
		if events := collectorEvents(t, st, collector); len(events) != 0 {
			t.Fatalf("%s reported events: %#v", collector, events)
		}
	}
}

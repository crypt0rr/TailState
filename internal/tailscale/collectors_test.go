package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

type specAPI struct {
	mu       sync.Mutex
	routes   map[string]func(http.ResponseWriter)
	requests []string
	scope    string
}

func (a *specAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/oauth/token" {
		_ = r.ParseForm()
		a.scope = r.FormValue("scope")
		_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		return
	}
	a.requests = append(a.requests, r.URL.Path)
	if route, ok := a.routes[r.URL.Path]; ok {
		route(w)
		return
	}
	http.NotFound(w, r)
}

func body(text string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(text))
	}
}

func status(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { http.Error(w, `{"message":"denied"}`, code) }
}

func specClient(t *testing.T, routes map[string]func(http.ResponseWriter), scopes ...string) (*Client, *specAPI) {
	t.Helper()
	api := &specAPI{routes: routes}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	return New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{Tailnet: "-", ClientID: "id", ClientSecret: "secret", Scopes: scopes}), api
}

func TestServicesCollectorReadsSpecShapedVIPServices(t *testing.T) {
	client, _ := specClient(t, map[string]func(http.ResponseWriter){
		"/api/v2/tailnet/-/services": body(`{"vipServices":[{"name":"svc:example","displayName":"Example Service","addrs":["100.93.49.180","fd7a:115c:a1e0::3456:3cb4"],"comment":"Example Service","ports":["tcp:80","tcp:443"],"tags":["tag:example"]}]}`),
	})
	resources, err := client.Collect(context.Background(), "services")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].ID != "svc:example" || resources[0].Type != "service" || resources[0].Name != "svc:example" || resources[0].Collector != "services" {
		t.Fatalf("services=%#v", resources)
	}
	raw, _, err := model.CanonicalFor("services", resources[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp:443", "tag:example", "100.93.49.180", "Example Service"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("canonical service missing %q: %s", want, raw)
		}
	}
}

func TestOAuthAppsCollectorReadsSpecShapedApps(t *testing.T) {
	client, _ := specClient(t, map[string]func(http.ResponseWriter){
		"/api/v2/tailnet/-/oauth-apps": body(`{"oauthApps":[{"id":"a123456CNTRL","name":"my-oauth-app","description":"An OAuth app used to provision devices.","redirectURIs":["https://example.com/oauth/callback"],"scopes":["auth_keys:create"],"allowedNodeAttributes":["custom:myattribute"],"clientSecret":"xxxxx","created":"2022-12-01T05:23:30Z","updated":"2022-12-01T05:23:30Z"}]}`),
	})
	resources, err := client.Collect(context.Background(), "oauth_apps")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].ID != "a123456CNTRL" || resources[0].Type != "oauth_app" || resources[0].Name != "my-oauth-app" {
		t.Fatalf("oauth apps=%#v", resources)
	}
	raw, _, err := model.CanonicalFor("oauth_apps", resources[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, excluded := range []string{"xxxxx", "clientSecret", "2022-12-01"} {
		if strings.Contains(text, excluded) {
			t.Fatalf("canonical oauth app kept %q: %s", excluded, text)
		}
	}
	for _, want := range []string{"auth_keys:create", "https://example.com/oauth/callback", "custom:myattribute"} {
		if !strings.Contains(text, want) {
			t.Fatalf("canonical oauth app missing %q: %s", want, text)
		}
	}
}

func TestNewCollectorsTreatForbiddenAndMissingAsUnsupported(t *testing.T) {
	for _, test := range []struct {
		code int
		want string
	}{
		{http.StatusForbidden, "insufficient OAuth scope or plan"},
		{http.StatusNotFound, "not available for this tailnet"},
	} {
		client, _ := specClient(t, map[string]func(http.ResponseWriter){
			"/api/v2/tailnet/-/services":   status(test.code),
			"/api/v2/tailnet/-/oauth-apps": status(test.code),
		})
		for _, collector := range []string{"services", "oauth_apps"} {
			_, err := client.Collect(context.Background(), collector)
			if !IsUnsupportedCollector(collector, err) {
				t.Fatalf("%s %d was not unsupported: %v", collector, test.code, err)
			}
			if reason := UnsupportedReason(err); !strings.Contains(reason, test.want) || strings.Contains(reason, "denied") {
				t.Fatalf("%s %d reason=%q", collector, test.code, reason)
			}
		}
	}
	if UnsupportedReason(context.Canceled) != "unsupported" {
		t.Fatal("non-HTTP reason must stay generic")
	}
}

func TestDNSCollectorUsesConfigurationEndpoint(t *testing.T) {
	client, api := specClient(t, map[string]func(http.ResponseWriter){
		"/api/v2/tailnet/-/dns/configuration": body(`{"nameservers":[{"address":"8.8.8.8","useWithExitNode":true}],"splitDNS":{"corp.example.com":[{"address":"10.0.0.53","useWithExitNode":true}]},"searchPaths":["user1.example.com"],"preferences":{"overrideLocalDNS":true,"magicDNS":true}}`),
	})
	resources, err := client.Collect(context.Background(), "dns")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := resources[0].Data.(map[string]any)
	if len(resources) != 1 || resources[0].ID != "dns" || data["splitDNS"] == nil {
		t.Fatalf("dns=%#v", resources)
	}
	if len(api.requests) != 1 || api.requests[0] != "/api/v2/tailnet/-/dns/configuration" {
		t.Fatalf("configuration endpoint must be a single request, got %v", api.requests)
	}
}

func TestDNSCollectorFallsBackToLegacyEndpointsOn404(t *testing.T) {
	client, api := specClient(t, map[string]func(http.ResponseWriter){
		"/api/v2/tailnet/-/dns/nameservers": body(`{"dns":["8.8.8.8"]}`),
		"/api/v2/tailnet/-/dns/preferences": body(`{"magicDNS":true}`),
		"/api/v2/tailnet/-/dns/searchpaths": body(`{"searchPaths":[]}`),
		"/api/v2/tailnet/-/dns/split-dns":   body(`{}`),
	})
	resources, err := client.Collect(context.Background(), "dns")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := resources[0].Data.(map[string]any)
	if data["split-dns"] == nil || data["nameservers"] == nil || len(api.requests) != 5 {
		t.Fatalf("legacy fallback data=%#v requests=%v", data, api.requests)
	}
}

func TestDNSConfigurationErrorsOtherThan404DoNotFallBack(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusBadRequest} {
		client, api := specClient(t, map[string]func(http.ResponseWriter){
			"/api/v2/tailnet/-/dns/configuration": status(code),
			"/api/v2/tailnet/-/dns/nameservers":   body(`{"dns":[]}`),
		})
		_, err := client.Collect(context.Background(), "dns")
		if err == nil || len(api.requests) != 1 {
			t.Fatalf("status %d err=%v requests=%v", code, err, api.requests)
		}
		if code == http.StatusForbidden && !IsUnsupportedCollector("dns", err) {
			t.Fatalf("forbidden DNS configuration must be unsupported: %v", err)
		}
	}
	client, _ := specClient(t, map[string]func(http.ResponseWriter){
		"/api/v2/tailnet/-/dns/configuration": body(`[]`),
	})
	if _, err := client.Collect(context.Background(), "dns"); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("non-object DNS configuration err=%v", err)
	}
}

func TestOAuthScopeIsConfigurable(t *testing.T) {
	devices := map[string]func(http.ResponseWriter){"/api/v2/tailnet/-/devices": body(`{"devices":[]}`)}
	client, api := specClient(t, devices, " devices:core:read ", "", "dns:read")
	if err := client.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.scope != "devices:core:read dns:read" {
		t.Fatalf("scope=%q", api.scope)
	}
	client, api = specClient(t, devices)
	if err := client.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.scope != DefaultOAuthScope {
		t.Fatalf("default scope=%q", api.scope)
	}
}

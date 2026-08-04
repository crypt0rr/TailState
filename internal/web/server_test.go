package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := store.Open(filepath.Join(t.TempDir(), "tailstate.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	token, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	engine := monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version)
	server, err := New(config, st, engine)
	if err != nil {
		t.Fatal(err)
	}
	return server, st, token
}

func TestClaimLoginSurfaceAndSecurityHeaders(t *testing.T) {
	server, st, token := testServer(t)
	form := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("security headers missing")
	}
	exists, _ := st.AdminExists(context.Background())
	if !exists {
		t.Fatal("administrator not created")
	}
	cookies := response.Result().Cookies()
	settingsRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	for _, cookie := range cookies {
		settingsRequest.AddCookie(cookie)
	}
	settingsResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(settingsResponse, settingsRequest)
	if settingsResponse.Code != http.StatusOK || !strings.Contains(settingsResponse.Body.String(), "Monitoring settings") {
		t.Fatalf("settings status %d: %s", settingsResponse.Code, settingsResponse.Body.String())
	}
}

func TestReadyBeforeSetup(t *testing.T) {
	server, _, _ := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status %d", response.Code)
	}
}

func TestLoginAttemptTrackingIsBoundedAndPruned(t *testing.T) {
	server, _, _ := testServer(t)
	now := time.Now()
	for i := 0; i < maxTrackedLoginIPs+100; i++ {
		server.loginAttempts["ip-"+strconv.Itoa(i)] = []time.Time{now}
	}
	server.loginAttempts["stale"] = []time.Time{now.Add(-16 * time.Minute)}
	server.rateLimited("new-ip")
	server.recordFailure("new-ip")
	if _, ok := server.loginAttempts["stale"]; ok {
		t.Fatal("stale login attempt state was retained")
	}
	if len(server.loginAttempts) > maxTrackedLoginIPs {
		t.Fatalf("login attempt state exceeded bound: %d", len(server.loginAttempts))
	}
}

func TestMetricsExposeCollectorHealthWithoutErrorDetails(t *testing.T) {
	server, st, _ := testServer(t)
	generation, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordCollectorFailure(context.Background(), generation, "devices", "secret response must not be exported"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `tailstate_collector_failures{collector="devices"} 1`) {
		t.Fatalf("collector metric missing: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, "secret response") {
		t.Fatal("collector error details leaked into metrics")
	}
}

func TestSettingsRedactsDestinationCredentials(t *testing.T) {
	server, st, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/super-secret-token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	settingsRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	for _, cookie := range cookies {
		settingsRequest.AddCookie(cookie)
	}
	settingsResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(settingsResponse, settingsRequest)
	body := settingsResponse.Body.String()
	if strings.Contains(body, "super-secret-token") || strings.Contains(body, "/hooks/") {
		t.Fatalf("destination credential leaked into settings HTML: %s", body)
	}
	if !strings.Contains(body, "mattermost://mattermost.example") {
		t.Fatal("redacted destination endpoint missing")
	}
}

func TestHistoryRequiresAuthenticationAndShowsExplainableChanges(t *testing.T) {
	server, st, setupToken := testServer(t)
	ctx := context.Background()
	claim := url.Values{"token": {setupToken}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	unauthenticated := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/history", nil))
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatalf("history was not protected: status=%d location=%q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}}}}}
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, changed, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/history?event_type=changed&resource=device-1", nil)
	for _, cookie := range claimResponse.Result().Cookies() {
		authenticated.AddCookie(cookie)
	}
	historyResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(historyResponse, authenticated)
	body := historyResponse.Body.String()
	if historyResponse.Code != http.StatusOK || !strings.Contains(body, "Change history") || !strings.Contains(body, "changed") || !strings.Contains(body, "server-new") {
		t.Fatalf("history page missing explainable change: status=%d body=%s", historyResponse.Code, body)
	}
	if strings.Contains(body, "mattermost.example") || strings.Contains(body, "token") {
		t.Fatalf("history page leaked notification credentials: %s", body)
	}
}

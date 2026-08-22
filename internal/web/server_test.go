package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	"github.com/crypt0rr/tailstate/internal/webhook"
	_ "modernc.org/sqlite"
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

func TestTailscaleWebhookAcceptsSignedDeliveryAndDeduplicates(t *testing.T) {
	server, st, _ := testServer(t)
	if _, err := st.SaveSettings(context.Background(), store.Settings{
		Tailnet:           "-",
		OAuthClientID:     "client",
		OAuthClientSecret: "secret",
		WebhookSecret:     "webhook-secret",
		MattermostURL:     "https://mattermost.example/hooks/token",
		DeviceInterval:    time.Minute,
		InventoryInterval: 5 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`[{"timestamp":"2026-08-05T10:00:00Z","version":1,"type":"policyUpdate","tailnet":"example.ts.net"}]`)
	timestamp := time.Now().Unix()
	request := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(string(body)))
	request.Header.Set("Tailscale-Webhook-Signature", webhook.SignatureForTest(body, "webhook-secret", timestamp))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"status":"accepted"`) {
		t.Fatalf("webhook response %d: %s", response.Code, response.Body.String())
	}
	bodyHash := sha256.Sum256(body)
	trigger, created, err := st.RecordWebhookTrigger(context.Background(), hex.EncodeToString(bodyHash[:]), nil, nil)
	if err != nil || created || trigger.Status != "pending" {
		t.Fatalf("accepted webhook was not durably queued: %#v created=%v err=%v", trigger, created, err)
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(string(body)))
	duplicate.Header.Set("Tailscale-Webhook-Signature", webhook.SignatureForTest(body, "webhook-secret", timestamp))
	duplicateResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusAccepted || !strings.Contains(duplicateResponse.Body.String(), `"status":"duplicate"`) {
		t.Fatalf("duplicate webhook response %d: %s", duplicateResponse.Code, duplicateResponse.Body.String())
	}
}

func TestTailscaleWebhookRejectsInvalidSignature(t *testing.T) {
	server, st, _ := testServer(t)
	if _, err := st.SaveSettings(context.Background(), store.Settings{
		Tailnet:           "-",
		OAuthClientID:     "client",
		OAuthClientSecret: "secret",
		WebhookSecret:     "webhook-secret",
		MattermostURL:     "https://mattermost.example/hooks/token",
		DeviceInterval:    time.Minute,
		InventoryInterval: 5 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`[{"type":"nodeCreated"}]`)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(string(body)))
	request.Header.Set("Tailscale-Webhook-Signature", "t=1,v1=invalid")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature status %d: %s", response.Code, response.Body.String())
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

func TestSetupPasswordMismatchConsumesThrottleBudget(t *testing.T) {
	server, _, token := testServer(t)
	form := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"different password"}}
	for attempt := 0; attempt < 5; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(form.Encode()))
		request.RemoteAddr = "198.51.100.25:1234"
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Passwords do not match") {
			t.Fatalf("mismatch attempt %d status=%d body=%s", attempt+1, response.Code, response.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(form.Encode()))
	request.RemoteAddr = "198.51.100.25:1234"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Too many setup attempts") {
		t.Fatalf("sixth mismatch was not throttled: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLoginRejectsCrossOriginRequests(t *testing.T) {
	server, _, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(login.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status %d: %s", response.Code, response.Body.String())
	}
}

func TestLoginRejectsCrossOriginReferer(t *testing.T) {
	server, _, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(login.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", "https://attacker.example/login")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin Referer login status %d: %s", response.Code, response.Body.String())
	}
}

func TestLoginRejectsSameSiteFetchWithoutOrigin(t *testing.T) {
	server, _, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(login.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Sec-Fetch-Site", "same-site")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("same-site login without Origin status %d: %s", response.Code, response.Body.String())
	}
}

func TestLoginAcceptsExplicitSameOriginWithSameSiteMetadata(t *testing.T) {
	server, _, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(login.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.Header.Set("Sec-Fetch-Site", "same-site")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("same-origin login status %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
}

func TestLoginAllowsSameOriginBehindTLSProxy(t *testing.T) {
	server, _, token := testServer(t)
	server.config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(login.Encode()))
	request.Host = "example.com"
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://example.com")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("proxied same-origin login status %d: %s", response.Code, response.Body.String())
	}
}

func TestSameOriginNormalizesDefaultPorts(t *testing.T) {
	server, _, _ := testServer(t)
	server.config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/login", nil)
	request.Host = "example.com:443"
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	if !server.sameOriginURL(request, "https://example.com") {
		t.Fatal("default HTTPS Origin port was rejected for an explicit proxy host port")
	}
	if server.sameOriginURL(request, "https://example.com:8443") {
		t.Fatal("mismatched HTTPS Origin port was accepted")
	}
}

func TestLoginRejectsForwardedTLSFromUntrustedPeer(t *testing.T) {
	server, _, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(login.Encode()))
	request.Host = "example.com"
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://example.com")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("untrusted forwarded TLS status %d: %s", response.Code, response.Body.String())
	}
}

func TestForwardedClientAddressRequiresTrustedProxy(t *testing.T) {
	server, _, _ := testServer(t)
	server.config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	request := httptest.NewRequest(http.MethodPost, "/login", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.8, 192.0.2.9")
	if got := server.clientIP(request); got != "198.51.100.8" {
		t.Fatalf("trusted proxy client address=%q", got)
	}
	request.RemoteAddr = "203.0.113.10:1234"
	if got := server.clientIP(request); got != "203.0.113.10" {
		t.Fatalf("untrusted proxy client address=%q", got)
	}
}

func TestLoginRejectsWhenAuthenticationCapacityIsExhausted(t *testing.T) {
	server, _, token := testServer(t)
	claim := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	claimRequest := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(claim.Encode()))
	claimRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claimResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimResponse.Code, claimResponse.Body.String())
	}

	server.authWork <- struct{}{}
	server.authWork <- struct{}{}
	defer func() {
		<-server.authWork
		<-server.authWork
	}()
	login := url.Values{"password": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(login.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy login status %d: %s", response.Code, response.Body.String())
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
	request.RemoteAddr = "127.0.0.1:1234"
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

func TestMetricsTokenProtectsMetricsWhenConfigured(t *testing.T) {
	server, st, _ := testServer(t)
	server.config.MetricsToken = "metrics-secret"
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing metrics token status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	authorizedRequest := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer metrics-secret")
	authorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), "tailstate_ready") || !strings.Contains(authorized.Body.String(), "tailstate_collector_poll_duration_seconds") || !strings.Contains(authorized.Body.String(), "tailstate_collector_partial") || !strings.Contains(authorized.Body.String(), "tailstate_collector_partial_errors") || !strings.Contains(authorized.Body.String(), "tailstate_collector_due_errors_total") {
		t.Fatalf("authorized metrics status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}

func TestMetricsWithoutTokenIsLoopbackOnly(t *testing.T) {
	server, st, _ := testServer(t)
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	remote.RemoteAddr = "203.0.113.10:1234"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, remote)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("remote metrics status=%d body=%s", response.Code, response.Body.String())
	}
	local := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	local.RemoteAddr = "127.0.0.1:1234"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, local)
	if response.Code != http.StatusOK {
		t.Fatalf("loopback metrics status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestReadinessCollectorReasonUsesBoundedVocabulary(t *testing.T) {
	tests := []struct {
		name     string
		state    store.CollectorState
		expected string
	}{
		{name: "unsupported", state: store.CollectorState{}, expected: "unsupported"},
		{name: "partial", state: store.CollectorState{Supported: true, Partial: true, Baseline: true}, expected: "partial"},
		{name: "retrying", state: store.CollectorState{Supported: true, FailureCount: 1}, expected: "retrying"},
		{name: "baseline pending", state: store.CollectorState{Supported: true}, expected: "baseline pending"},
		{name: "healthy", state: store.CollectorState{Supported: true, Baseline: true}, expected: "healthy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readinessCollectorReason(tt.state); got != tt.expected {
				t.Fatalf("reason=%q, want %q", got, tt.expected)
			}
		})
	}
}

func TestReadyReportsDegradedBaselineAfterGracePeriod(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := store.Open(dbPath, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "upstream secret must stay private"); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	legacyDB.SetMaxOpenConns(1)
	defer legacyDB.Close()
	if _, err := legacyDB.ExecContext(ctx, "UPDATE settings SET configured_at=? WHERE id=1", time.Now().UTC().Add(-20*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"status":"degraded"`) || !strings.Contains(body, `"baseline":true`) || !strings.Contains(body, `"degraded":true`) || !strings.Contains(body, `"name":"devices"`) {
		t.Fatalf("degraded readiness response %d: %s", response.Code, body)
	}
	if strings.Contains(body, "upstream secret") {
		t.Fatalf("readiness exposed collector error: %s", body)
	}
}

func TestReadyDegradesWhenASecondCollectorStaysUnbaselined(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := store.Open(dbPath, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordCollectorFailure(ctx, generation, "users", "upstream unavailable"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}

	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"baseline":true`) || strings.Contains(ready.Body.String(), `"degraded":true`) {
		t.Fatalf("partial baseline readiness response %d: %s", ready.Code, ready.Body.String())
	}

	legacyDB, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer legacyDB.Close()
	if _, err := legacyDB.ExecContext(ctx, "UPDATE settings SET configured_at=? WHERE id=1", time.Now().UTC().Add(-20*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	ready = httptest.NewRecorder()
	server.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	body := ready.Body.String()
	if ready.Code != http.StatusOK || !strings.Contains(body, `"status":"degraded"`) || !strings.Contains(body, `"baseline":true`) || !strings.Contains(body, `"degraded":true`) || !strings.Contains(body, `"name":"users"`) {
		t.Fatalf("partial baseline degraded response %d: %s", ready.Code, body)
	}
	if strings.Contains(body, "upstream unavailable") {
		t.Fatalf("readiness exposed collector error: %s", body)
	}
}

func TestReadyReportsPostBaselineCollectorDegradation(t *testing.T) {
	server, st, _ := testServer(t)
	ctx := context.Background()
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "provider secret must stay private"); err != nil {
		t.Fatal(err)
	}
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	body := ready.Body.String()
	if ready.Code != http.StatusOK || !strings.Contains(body, `"status":"degraded"`) || !strings.Contains(body, `"baseline":true`) || !strings.Contains(body, `"degraded":true`) || !strings.Contains(body, `"name":"devices"`) {
		t.Fatalf("post-baseline degradation was hidden: status=%d body=%s", ready.Code, body)
	}
	if strings.Contains(body, "provider secret") {
		t.Fatalf("readiness exposed collector error: %s", body)
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
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", WebhookSecret: "webhook-super-secret", MattermostURL: "https://mattermost.example/hooks/super-secret-token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	settingsRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	for _, cookie := range cookies {
		settingsRequest.AddCookie(cookie)
	}
	settingsResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(settingsResponse, settingsRequest)
	body := settingsResponse.Body.String()
	if strings.Contains(body, "super-secret-token") || strings.Contains(body, "webhook-super-secret") || strings.Contains(body, "/hooks/") {
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
	unauthenticatedExport := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedExport, httptest.NewRequest(http.MethodGet, "/history/export", nil))
	if unauthenticatedExport.Code != http.StatusSeeOther || unauthenticatedExport.Header().Get("Location") != "/login" {
		t.Fatalf("history export was not protected: status=%d location=%q", unauthenticatedExport.Code, unauthenticatedExport.Header().Get("Location"))
	}
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}}}}}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, changed, func([]model.Change) string { return "digest" }); err != nil {
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
	if !strings.Contains(body, "Download evidence pack") || !strings.Contains(body, "/history/export") {
		t.Fatalf("history page is missing the evidence export action: %s", body)
	}
	if !strings.Contains(body, "Signed key") || !strings.Contains(body, "ed25519:") {
		t.Fatalf("history page is missing the evidence signing fingerprint: %s", body)
	}
	exportRequest := httptest.NewRequest(http.MethodGet, "/history/export?event_type=changed&resource=device-1", nil)
	for _, cookie := range claimResponse.Result().Cookies() {
		exportRequest.AddCookie(cookie)
	}
	exportResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(exportResponse, exportRequest)
	if exportResponse.Code != http.StatusOK || !strings.Contains(exportResponse.Header().Get("Content-Disposition"), "tailstate-drift-evidence-") {
		t.Fatalf("evidence export failed: status=%d headers=%v body=%s", exportResponse.Code, exportResponse.Header(), exportResponse.Body.String())
	}
	if err := store.VerifyEvidencePack(exportResponse.Body.Bytes()); err != nil {
		t.Fatalf("web evidence export did not verify: %v", err)
	}
	if strings.Contains(exportResponse.Body.String(), "mattermost.example") || strings.Contains(exportResponse.Body.String(), "/hooks/") {
		t.Fatal("web evidence export leaked destination credentials")
	}
}

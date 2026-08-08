package web

import (
	"context"
	"database/sql"
	"errors"
	"html/template"
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
	"github.com/crypt0rr/tailstate/internal/webhook"
)

type webFailingBody struct{}

func (webFailingBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (webFailingBody) Close() error             { return nil }

func claimCoverageAdmin(t *testing.T, server *Server, token string) []*http.Cookie {
	t.Helper()
	form := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", response.Code, response.Body.String())
	}
	return response.Result().Cookies()
}

func coverageCSRF(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == "tailstate_csrf" {
			return cookie.Value
		}
	}
	t.Fatal("claim response did not contain CSRF cookie")
	return ""
}

func coveragePost(t *testing.T, server *Server, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func webServerWithDatabase(t *testing.T) (*Server, *store.Store, *sql.DB, []*http.Cookie) {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	token, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return server, st, db, claimCoverageAdmin(t, server, token)
}

func TestHealthReadyMetricsAndSecurityHeaders(t *testing.T) {
	server, st, _ := testServer(t)
	handler := server.Handler()
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) {
		t.Fatalf("health response %d: %s", health.Code, health.Body.String())
	}
	for name, want := range map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "camera=()",
	} {
		if got := health.Header().Get(name); !strings.Contains(got, want) {
			t.Fatalf("security header %s=%q, want %q", name, got, want)
		}
	}
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), `"configured":false`) {
		t.Fatalf("unconfigured ready response %d: %s", ready.Code, ready.Body.String())
	}

	tooLarge := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(strings.Repeat("x", 1<<20+1)))
	tooLarge.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tooLargeResponse := httptest.NewRecorder()
	handler.ServeHTTP(tooLargeResponse, tooLarge)
	if tooLargeResponse.Code != http.StatusBadRequest {
		t.Fatalf("oversized form status=%d body=%s", tooLargeResponse.Code, tooLargeResponse.Body.String())
	}

	generation, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(context.Background(), generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	ready = httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"status":"ready"`) {
		t.Fatalf("configured ready response %d: %s", ready.Code, ready.Body.String())
	}
	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), "tailstate_ready 1") || !strings.Contains(metrics.Header().Get("Content-Type"), "0.0.4") {
		t.Fatalf("ready metrics response %d headers=%v body=%s", metrics.Code, metrics.Header(), metrics.Body.String())
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	unhealthy := httptest.NewRecorder()
	server.health(unhealthy, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if unhealthy.Code != http.StatusServiceUnavailable || !strings.Contains(unhealthy.Body.String(), "unhealthy") {
		t.Fatalf("closed-store health response %d: %s", unhealthy.Code, unhealthy.Body.String())
	}
}

func TestNavigationAndClaimValidationBranches(t *testing.T) {
	server, st, token := testServer(t)
	handler := server.Handler()
	for path, want := range map[string]string{"/": "/setup", "/login": "/setup"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want {
			t.Fatalf("%s redirect status=%d location=%q", path, response.Code, response.Header().Get("Location"))
		}
	}
	setup := httptest.NewRecorder()
	handler.ServeHTTP(setup, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if setup.Code != http.StatusOK || !strings.Contains(setup.Body.String(), "Claim TailState") {
		t.Fatalf("setup page status=%d body=%s", setup.Code, setup.Body.String())
	}

	mismatch := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"different password"}}
	mismatchResponse := coveragePost(t, server, "/setup/claim", mismatch, nil)
	if mismatchResponse.Code != http.StatusOK || !strings.Contains(mismatchResponse.Body.String(), "Passwords do not match") {
		t.Fatalf("mismatch response %d: %s", mismatchResponse.Code, mismatchResponse.Body.String())
	}
	invalid := url.Values{"token": {"wrong-token"}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	invalidResponse := coveragePost(t, server, "/setup/claim", invalid, nil)
	if invalidResponse.Code != http.StatusOK || !strings.Contains(invalidResponse.Body.String(), "invalid") {
		t.Fatalf("invalid token response %d: %s", invalidResponse.Code, invalidResponse.Body.String())
	}

	cookies := claimCoverageAdmin(t, server, token)
	for path, want := range map[string]string{"/": "/settings", "/setup": "/settings", "/login": "/status"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want {
			t.Fatalf("authenticated %s redirect status=%d location=%q", path, response.Code, response.Header().Get("Location"))
		}
	}
	alreadyClaimed := coveragePost(t, server, "/setup/claim", url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}, nil)
	if alreadyClaimed.Code != http.StatusConflict {
		t.Fatalf("second claim status=%d body=%s", alreadyClaimed.Code, alreadyClaimed.Body.String())
	}
	if exists, err := st.AdminExists(context.Background()); err != nil || !exists {
		t.Fatalf("admin state after claim exists=%v err=%v", exists, err)
	}
}

func TestLoginLogoutAndResetBranches(t *testing.T) {
	server, st, token := testServer(t)
	claimCoverageAdmin(t, server, token)
	wrong := coveragePost(t, server, "/login", url.Values{"password": {"wrong password"}}, nil)
	if wrong.Code != http.StatusOK || !strings.Contains(wrong.Body.String(), "Invalid password") {
		t.Fatalf("wrong login response %d: %s", wrong.Code, wrong.Body.String())
	}
	correct := coveragePost(t, server, "/login", url.Values{"password": {"a secure password"}}, nil)
	if correct.Code != http.StatusSeeOther || correct.Header().Get("Location") != "/" {
		t.Fatalf("correct login response %d location=%q", correct.Code, correct.Header().Get("Location"))
	}
	cookies := correct.Result().Cookies()
	ip := "192.0.2.1"
	for i := 0; i < 5; i++ {
		server.recordFailure(ip)
	}
	rateLimited := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("password=wrong"))
	rateLimited.RemoteAddr = ip + ":1234"
	rateLimited.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rateLimitedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(rateLimitedResponse, rateLimited)
	if rateLimitedResponse.Code != http.StatusOK || !strings.Contains(rateLimitedResponse.Body.String(), "Too many login attempts") {
		t.Fatalf("rate limited login response %d: %s", rateLimitedResponse.Code, rateLimitedResponse.Body.String())
	}

	csrf := coverageCSRF(t, cookies)
	logout := coveragePost(t, server, "/logout", url.Values{"_csrf": {csrf}}, cookies)
	if logout.Code != http.StatusSeeOther || logout.Header().Get("Location") != "/login" {
		t.Fatalf("logout response %d location=%q", logout.Code, logout.Header().Get("Location"))
	}
	resetPage := httptest.NewRecorder()
	server.Handler().ServeHTTP(resetPage, httptest.NewRequest(http.MethodGet, "/reset", nil))
	if resetPage.Code != http.StatusOK || !strings.Contains(resetPage.Body.String(), "Reset administrator password") {
		t.Fatalf("reset page response %d: %s", resetPage.Code, resetPage.Body.String())
	}
	mismatch := coveragePost(t, server, "/reset", url.Values{"token": {"bad"}, "password": {"new secure password"}, "confirm": {"different password"}}, nil)
	if mismatch.Code != http.StatusOK || !strings.Contains(mismatch.Body.String(), "Passwords do not match") {
		t.Fatalf("reset mismatch response %d: %s", mismatch.Code, mismatch.Body.String())
	}
	resetToken, err := st.NewResetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reset := coveragePost(t, server, "/reset", url.Values{"token": {resetToken}, "password": {"new secure password"}, "confirm": {"new secure password"}}, nil)
	if reset.Code != http.StatusSeeOther || reset.Header().Get("Location") != "/login" {
		t.Fatalf("reset response %d location=%q", reset.Code, reset.Header().Get("Location"))
	}
}

func TestHistoryFilterAndURLHelpers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/history?collector=%20devices%20&event_type=changed&resource=device%2F1&cursor=42", nil)
	filter := historyFilter(request)
	if filter.Collector != "devices" || filter.EventType != "changed" || filter.ResourceID != "device/1" || filter.Cursor != 42 || filter.Limit != 20 {
		t.Fatalf("unexpected history filter: %#v", filter)
	}
	for _, cursor := range []string{"0", "-1", "not-a-number"} {
		if got := historyFilter(httptest.NewRequest(http.MethodGet, "/history?cursor="+url.QueryEscape(cursor), nil)).Cursor; got != 0 {
			t.Fatalf("invalid cursor %q parsed as %d", cursor, got)
		}
	}
	next := historyURL(filter, 99)
	if !strings.Contains(next, "collector=devices") || !strings.Contains(next, "event_type=changed") || !strings.Contains(next, "resource=device%2F1") || !strings.Contains(next, "cursor=99") {
		t.Fatalf("history URL missing encoded filters: %s", next)
	}
	if got := historyExportURL(store.HistoryFilter{}); got != "/history/export" {
		t.Fatalf("empty history export URL=%q", got)
	}
	if got := historyExportURL(filter); !strings.Contains(got, "resource=device%2F1") {
		t.Fatalf("filtered history export URL=%q", got)
	}
}

func TestWebhookConfigurationAndEngineNilBranches(t *testing.T) {
	server, st, _ := testServer(t)
	missing := httptest.NewRecorder()
	server.tailscaleWebhook(missing, httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(`[{"type":"nodeCreated"}]`)))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing webhook secret status=%d body=%s", missing.Code, missing.Body.String())
	}
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", WebhookSecret: "webhook-secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`[{"type":"nodeCreated"}]`)
	timestamp := time.Now().Unix()
	request := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(string(body)))
	request.Header.Set("Tailscale-Webhook-Signature", webhook.SignatureForTest(body, "webhook-secret", timestamp))
	server.engine = nil
	accepted := httptest.NewRecorder()
	server.tailscaleWebhook(accepted, request)
	if accepted.Code != http.StatusAccepted || !strings.Contains(accepted.Body.String(), `"status":"accepted"`) {
		t.Fatalf("nil-engine webhook response %d: %s", accepted.Code, accepted.Body.String())
	}
	wrongMethod := httptest.NewRecorder()
	server.tailscaleWebhook(wrongMethod, httptest.NewRequest(http.MethodGet, "/webhooks/tailscale", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong webhook method status=%d", wrongMethod.Code)
	}
}

func TestSettingsAndDestinationMutationBranches(t *testing.T) {
	server, st, setupToken := testServer(t)
	cookies := claimCoverageAdmin(t, server, setupToken)
	csrf := coverageCSRF(t, cookies)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		if r.URL.Path == "/api/v2/tailnet/-/devices" {
			_, _ = w.Write([]byte(`{"devices":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	server.config.TailscaleBase = api.URL + "/api/v2"
	server.config.OAuthTokenURL = api.URL + "/oauth/token"

	badIntervals := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"not-a-number"}, "inventory_interval": {"300"}}
	badResponse := coveragePost(t, server, "/settings", badIntervals, cookies)
	if badResponse.Code != http.StatusOK || !strings.Contains(badResponse.Body.String(), "Poll intervals must be whole seconds") {
		t.Fatalf("invalid settings response %d: %s", badResponse.Code, badResponse.Body.String())
	}
	validSettings := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "webhook_secret": {"webhook-secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}
	noDestination := coveragePost(t, server, "/settings", validSettings, cookies)
	if noDestination.Code != http.StatusOK || !strings.Contains(noDestination.Body.String(), "at least one enabled notification destination") {
		t.Fatalf("initial destination gate response %d: %s", noDestination.Code, noDestination.Body.String())
	}

	serviceURL := "mattermost://TailState@example.invalid/token?disabletls=true"
	saveDestination := url.Values{"_csrf": {csrf}, "action": {"save"}, "name": {"Primary"}, "service_url": {serviceURL}, "enabled": {"on"}}
	saved := coveragePost(t, server, "/settings/destinations", saveDestination, cookies)
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Location") != "/settings" {
		t.Fatalf("save destination response %d location=%q body=%s", saved.Code, saved.Header().Get("Location"), saved.Body.String())
	}
	destinations, err := st.ListDestinations(context.Background())
	if err != nil || len(destinations) != 1 {
		t.Fatalf("saved destinations=%#v err=%v", destinations, err)
	}
	destinationID := destinations[0].ID

	savedSettings := coveragePost(t, server, "/settings", validSettings, cookies)
	if savedSettings.Code != http.StatusSeeOther || savedSettings.Header().Get("Location") != "/status" {
		t.Fatalf("settings save response %d location=%q body=%s", savedSettings.Code, savedSettings.Header().Get("Location"), savedSettings.Body.String())
	}
	current, err := st.Settings(context.Background())
	if err != nil || current.WebhookSecret != "webhook-secret" {
		t.Fatalf("saved settings=%#v err=%v", current, err)
	}

	blankSecrets := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {""}, "webhook_secret": {""}, "device_interval": {"90"}, "inventory_interval": {"300"}}
	updated := coveragePost(t, server, "/settings", blankSecrets, cookies)
	if updated.Code != http.StatusSeeOther {
		t.Fatalf("blank-secret settings update status=%d body=%s", updated.Code, updated.Body.String())
	}
	current, err = st.Settings(context.Background())
	if err != nil || current.OAuthClientSecret != "secret" || current.WebhookSecret != "webhook-secret" {
		t.Fatalf("blank-secret update lost values: %#v err=%v", current, err)
	}

	disable := coveragePost(t, server, "/settings/destinations/disable", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(destinationID, 10)}}, cookies)
	if disable.Code != http.StatusSeeOther {
		t.Fatalf("disable destination status=%d body=%s", disable.Code, disable.Body.String())
	}
	settingsPage := httptest.NewRecorder()
	settingsRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	for _, cookie := range cookies {
		settingsRequest.AddCookie(cookie)
	}
	server.Handler().ServeHTTP(settingsPage, settingsRequest)
	if settingsPage.Code != http.StatusOK || !strings.Contains(settingsPage.Body.String(), "Notifications are paused") {
		t.Fatalf("paused settings page status=%d body=%s", settingsPage.Code, settingsPage.Body.String())
	}
	enable := coveragePost(t, server, "/settings/destinations/enable", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(destinationID, 10)}, "enabled": {"false"}}, cookies)
	if enable.Code != http.StatusSeeOther {
		t.Fatalf("enable destination status=%d body=%s", enable.Code, enable.Body.String())
	}

	edit := coveragePost(t, server, "/settings/destinations", url.Values{"_csrf": {csrf}, "action": {"save"}, "id": {strconv.FormatInt(destinationID, 10)}, "name": {"Edited"}, "service_url": {""}, "enabled": {"on"}}, cookies)
	if edit.Code != http.StatusSeeOther {
		t.Fatalf("edit destination status=%d body=%s", edit.Code, edit.Body.String())
	}
	destinations, err = st.ListDestinations(context.Background())
	if err != nil || len(destinations) != 1 || destinations[0].Name != "Edited" || destinations[0].ServiceURL != serviceURL {
		t.Fatalf("edited destination=%#v err=%v", destinations, err)
	}

	testResponse := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(destinationID, 10)}, "service_url": {"not-a-shoutrrr-url"}}, cookies)
	if testResponse.Code != http.StatusOK || !strings.Contains(testResponse.Body.String(), "Notification test failed") {
		t.Fatalf("invalid destination test response %d: %s", testResponse.Code, testResponse.Body.String())
	}
	unknown := coveragePost(t, server, "/settings/destinations", url.Values{"_csrf": {csrf}, "action": {"unknown"}}, cookies)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "unknown destination action") {
		t.Fatalf("unknown destination action status=%d body=%s", unknown.Code, unknown.Body.String())
	}
	removed := coveragePost(t, server, "/settings/destinations/remove", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(destinationID, 10)}}, cookies)
	if removed.Code != http.StatusSeeOther {
		t.Fatalf("remove destination status=%d body=%s", removed.Code, removed.Body.String())
	}
	active, err := st.ListDestinations(context.Background())
	if err != nil || len(active) != 0 {
		t.Fatalf("removed destination still active: %#v err=%v", active, err)
	}
	all, err := st.ListDestinations(context.Background(), true)
	if err != nil || len(all) != 1 || all[0].DeletedAt == nil {
		t.Fatalf("soft-deleted destination missing: %#v err=%v", all, err)
	}
}

func TestDestinationTestAndUnknownMutationErrors(t *testing.T) {
	server, st, setupToken := testServer(t)
	cookies := claimCoverageAdmin(t, server, setupToken)
	csrf := coverageCSRF(t, cookies)
	server.config.TailscaleBase = "http://127.0.0.1:1/api/v2"
	server.config.OAuthTokenURL = "http://127.0.0.1:1/oauth/token"
	failedSettings := coveragePost(t, server, "/settings", url.Values{
		"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"},
	}, cookies)
	if failedSettings.Code != http.StatusOK || !strings.Contains(failedSettings.Body.String(), "Tailscale test failed") {
		t.Fatalf("failed Tailscale settings status=%d body=%s", failedSettings.Code, failedSettings.Body.String())
	}

	invalid := coveragePost(t, server, "/settings/destinations", url.Values{
		"_csrf": {csrf}, "action": {"save"}, "name": {"Invalid"}, "service_url": {"not-a-shoutrrr-url"}, "enabled": {"on"},
	}, cookies)
	if invalid.Code != http.StatusOK || !strings.Contains(invalid.Body.String(), "Notification destination was not saved") {
		t.Fatalf("invalid destination save status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("notification test method=%s, want POST", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	serviceURL := strings.Replace(upstream.URL, "http://", "generic://", 1) + "?disabletls=true&template=json&messagekey=text"
	saved := coveragePost(t, server, "/settings/destinations", url.Values{
		"_csrf": {csrf}, "action": {"save"}, "name": {"Webhook"}, "service_url": {serviceURL}, "enabled": {"on"},
	}, cookies)
	if saved.Code != http.StatusSeeOther {
		t.Fatalf("valid destination save status=%d body=%s", saved.Code, saved.Body.String())
	}
	destinations, err := st.ListDestinations(context.Background())
	if err != nil || len(destinations) != 1 {
		t.Fatalf("saved destinations=%#v err=%v", destinations, err)
	}
	id := strconv.FormatInt(destinations[0].ID, 10)

	tested := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "id": {id}}, cookies)
	if tested.Code != http.StatusOK || !strings.Contains(tested.Body.String(), "Notification test sent") {
		t.Fatalf("successful destination test status=%d body=%s", tested.Code, tested.Body.String())
	}
	unknownToggle := coveragePost(t, server, "/settings/destinations/toggle", url.Values{"_csrf": {csrf}, "id": {"999999"}, "enabled": {"true"}}, cookies)
	if unknownToggle.Code != http.StatusBadRequest || !strings.Contains(unknownToggle.Body.String(), "notification destination not found") {
		t.Fatalf("unknown destination toggle status=%d body=%s", unknownToggle.Code, unknownToggle.Body.String())
	}
	unknownDelete := coveragePost(t, server, "/settings/destinations/remove", url.Values{"_csrf": {csrf}, "id": {"999999"}}, cookies)
	if unknownDelete.Code != http.StatusBadRequest || !strings.Contains(unknownDelete.Body.String(), "notification destination not found") {
		t.Fatalf("unknown destination delete status=%d body=%s", unknownDelete.Code, unknownDelete.Body.String())
	}
}

func TestWebAuthenticationAndHelperErrorBranches(t *testing.T) {
	server, st, _ := testServer(t)
	unauthorized := coveragePost(t, server, "/logout", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logout status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	if got := remoteIP(&http.Request{RemoteAddr: "198.51.100.7"}); got != "198.51.100.7" {
		t.Fatalf("remoteIP without port=%q", got)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if server.startSession(response, httptest.NewRequest(http.MethodPost, "/login", nil)) {
		t.Fatal("startSession succeeded with a closed store")
	}
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("closed-store startSession status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestResetRejectsInvalidToken(t *testing.T) {
	server, st, setupToken := testServer(t)
	claimCoverageAdmin(t, server, setupToken)
	if _, err := st.NewResetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	response := coveragePost(t, server, "/reset", url.Values{
		"token": {"invalid-reset-token"}, "password": {"new secure password"}, "confirm": {"new secure password"},
	}, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "invalid reset token") {
		t.Fatalf("invalid reset response status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestServeShutdownAndConfiguredHome(t *testing.T) {
	server, st, setupToken := testServer(t)
	cookies := claimCoverageAdmin(t, server, setupToken)
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/status" {
		t.Fatalf("configured home status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Serve(ctx); err != nil {
		t.Fatalf("pre-canceled server shutdown error=%v", err)
	}
}

func TestWebAdditionalErrorAndMetricsBranches(t *testing.T) {
	server, st, setupToken := testServer(t)
	claimCoverageAdmin(t, server, setupToken)
	unauthHome := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthHome, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthHome.Code != http.StatusSeeOther || unauthHome.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated home status=%d location=%q", unauthHome.Code, unauthHome.Header().Get("Location"))
	}
	loginPage := httptest.NewRecorder()
	server.Handler().ServeHTTP(loginPage, httptest.NewRequest(http.MethodGet, "/login", nil))
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), "Sign in") {
		t.Fatalf("login page status=%d body=%s", loginPage.Code, loginPage.Body.String())
	}
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", WebhookSecret: "webhook-secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	settings, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st.SetNextPoll(context.Background(), settings.Generation, []string{"devices"}, time.Now().Add(time.Minute))
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "tailstate_collector_next_poll_timestamp_seconds") {
		t.Fatal("next-poll metric missing")
	}
	oldListenAddr := server.config.ListenAddr
	server.config.ListenAddr = "bad"
	serveErr := server.Serve(context.Background())
	server.config.ListenAddr = oldListenAddr
	if serveErr == nil {
		t.Fatal("invalid listen address unexpectedly succeeded")
	}
	webhookBody := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", nil)
	webhookBody.Body = webFailingBody{}
	webhookResponse := httptest.NewRecorder()
	server.tailscaleWebhook(webhookResponse, webhookBody)
	if webhookResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("failing webhook body status=%d body=%s", webhookResponse.Code, webhookResponse.Body.String())
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := httptest.NewRecorder()
	server.tailscaleWebhook(unavailable, httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader("[]")))
	if unavailable.Code != http.StatusNotFound {
		t.Fatalf("closed-store webhook status=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
}

func TestRenderTemplateError(t *testing.T) {
	server, _, _ := testServer(t)
	server.templates["status"] = template.Must(template.New("status").Option("missingkey=error").Parse("{{.MissingField}}"))
	rendered := httptest.NewRecorder()
	server.render(rendered, "status", pageData{})
}

func TestSettingsAndWebhookDatabaseErrorResponses(t *testing.T) {
	ctx := context.Background()
	newAPI := func(t *testing.T) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
				return
			}
			if r.URL.Path == "/api/v2/tailnet/-/devices" {
				_, _ = w.Write([]byte(`{"devices":[]}`))
				return
			}
			http.NotFound(w, r)
		}))
	}
	settingsForm := func(csrf string) url.Values {
		return url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}
	}

	t.Run("notification destination list failure", func(t *testing.T) {
		server, st, db, cookies := webServerWithDatabase(t)
		if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
			t.Fatal(err)
		}
		api := newAPI(t)
		defer api.Close()
		server.config.TailscaleBase = api.URL + "/api/v2"
		server.config.OAuthTokenURL = api.URL + "/oauth/token"
		if _, err := db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		response := coveragePost(t, server, "/settings", settingsForm(coverageCSRF(t, cookies)), cookies)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "load notification destinations failed") {
			t.Fatalf("destination list failure response=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("settings save failure", func(t *testing.T) {
		server, st, db, cookies := webServerWithDatabase(t)
		if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
			t.Fatal(err)
		}
		api := newAPI(t)
		defer api.Close()
		server.config.TailscaleBase = api.URL + "/api/v2"
		server.config.OAuthTokenURL = api.URL + "/oauth/token"
		if _, err := db.ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatal(err)
		}
		response := coveragePost(t, server, "/settings", settingsForm(coverageCSRF(t, cookies)), cookies)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "no such table") {
			t.Fatalf("settings save failure response=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("settings fallback", func(t *testing.T) {
		server, st, db, cookies := webServerWithDatabase(t)
		if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "UPDATE settings SET oauth_secret_enc='invalid-envelope'"); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/settings", nil)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Monitoring settings") {
			t.Fatalf("settings fallback response=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("history load failure", func(t *testing.T) {
		server, st, db, cookies := webServerWithDatabase(t)
		if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "DROP TABLE event_batches"); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/history", nil)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "load history") {
			t.Fatalf("history failure response=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("webhook record failure", func(t *testing.T) {
		server, st, db, _ := webServerWithDatabase(t)
		if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", WebhookSecret: "webhook-secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "DROP TABLE webhook_triggers"); err != nil {
			t.Fatal(err)
		}
		body := []byte(`[{"type":"nodeCreated"}]`)
		request := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(string(body)))
		timestamp := time.Now().Unix()
		request.Header.Set("Tailscale-Webhook-Signature", webhook.SignatureForTest(body, "webhook-secret", timestamp))
		response := httptest.NewRecorder()
		server.tailscaleWebhook(response, request)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "record webhook") {
			t.Fatalf("webhook record failure response=%d body=%s", response.Code, response.Body.String())
		}
	})
}

func TestWebCSRFAndFormBoundaryBranches(t *testing.T) {
	server, _, _, cookies := webServerWithDatabase(t)
	unauthSettings := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthSettings, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if unauthSettings.Code != http.StatusSeeOther || unauthSettings.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated settings status=%d location=%q", unauthSettings.Code, unauthSettings.Header().Get("Location"))
	}
	unauthSettingsPost := coveragePost(t, server, "/settings", url.Values{}, nil)
	if unauthSettingsPost.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated settings POST status=%d body=%s", unauthSettingsPost.Code, unauthSettingsPost.Body.String())
	}
	unauthStatus := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthStatus, httptest.NewRequest(http.MethodGet, "/status", nil))
	if unauthStatus.Code != http.StatusSeeOther || unauthStatus.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated status status=%d location=%q", unauthStatus.Code, unauthStatus.Header().Get("Location"))
	}
	unauthorized := coveragePost(t, server, "/settings/destinations", url.Values{}, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized destination status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	wrongCSRF := coveragePost(t, server, "/settings/destinations", url.Values{"_csrf": {"wrong"}}, cookies)
	if wrongCSRF.Code != http.StatusUnauthorized {
		t.Fatalf("wrong csrf destination status=%d body=%s", wrongCSRF.Code, wrongCSRF.Body.String())
	}
	defaultSave := coveragePost(t, server, "/settings/destinations", url.Values{"_csrf": {coverageCSRF(t, cookies)}, "name": {"Default action"}, "service_url": {"generic://example.invalid/path"}, "enabled": {"on"}}, cookies)
	if defaultSave.Code != http.StatusSeeOther {
		t.Fatalf("default destination action status=%d body=%s", defaultSave.Code, defaultSave.Body.String())
	}
	server.loginAttempts["stale"] = []time.Time{time.Now().Add(-16 * time.Minute)}
	if server.rateLimited("stale") {
		t.Fatal("stale login attempts were rate limited")
	}
	if _, ok := server.loginAttempts["stale"]; ok {
		t.Fatal("stale login attempts were not pruned")
	}
}

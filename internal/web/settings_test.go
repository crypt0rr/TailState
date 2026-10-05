package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

// TestSettingsTestBudgetStaysBelowWriteDeadline keeps the handler budget
// (test plus render allowance) below the server's write deadline.
func TestSettingsTestBudgetStaysBelowWriteDeadline(t *testing.T) {
	if defaultSettingsTestTimeout+settingsRenderAllowance >= serverWriteTimeout {
		t.Fatalf("settings test %s + render %s must stay below the write timeout %s", defaultSettingsTestTimeout, settingsRenderAllowance, serverWriteTimeout)
	}
}

// TestSlowTailscaleTestRendersFailurePage drives a real HTTP server whose
// write deadline is shorter than the Tailscale test budget. The stalled API
// must still produce the rendered "Tailscale test failed" page rather than a
// dropped connection.
func TestSlowTailscaleTestRendersFailurePage(t *testing.T) {
	server, _, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	release := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer api.Close()
	defer close(release)
	server.config.TailscaleBase = api.URL + "/api/v2"
	server.config.OAuthTokenURL = api.URL + "/oauth/token"
	server.settingsTestTimeout = 600 * time.Millisecond

	site := httptest.NewUnstartedServer(server.Handler())
	site.Config.WriteTimeout = 300 * time.Millisecond
	site.Start()
	defer site.Close()

	form := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}
	request, err := http.NewRequest(http.MethodPost, site.URL+"/settings", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	started := time.Now()
	response, err := site.Client().Do(request)
	if err != nil {
		t.Fatalf("slow Tailscale test dropped the response after %s: %v", time.Since(started), err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read settings response: %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Tailscale test failed") {
		t.Fatalf("slow Tailscale test status=%d body=%s", response.StatusCode, body)
	}
}

// TestSettingsRejectsInvalidInputBeforeOutboundRequest proves that local
// validation runs first, with specific messages, and that no request reaches
// Tailscale for an invalid form.
func TestSettingsRejectsInvalidInputBeforeOutboundRequest(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	var outbound atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outbound.Add(1)
		http.NotFound(w, r)
	}))
	defer api.Close()
	server.config.TailscaleBase = api.URL + "/api/v2"
	server.config.OAuthTokenURL = api.URL + "/oauth/token"

	valid := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}
	with := func(key, value string) url.Values {
		form := cloneForm(valid)
		form.Set(key, value)
		return form
	}
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"non-numeric device", with("device_interval", "soon"), "Device poll interval must be a whole number of seconds."},
		{"fractional inventory", with("inventory_interval", "1.5"), "Inventory poll interval must be a whole number of seconds."},
		{"device too short", with("device_interval", "14"), "Device poll interval must be between 15 and 86400 seconds."},
		{"device too long", with("device_interval", "86401"), "Device poll interval must be between 15 and 86400 seconds."},
		{"device duration overflow", with("device_interval", "10000000000"), "Device poll interval must be between 15 and 86400 seconds."},
		{"device int64 overflow", with("device_interval", "99999999999999999999"), "Device poll interval must be between 15 and 86400 seconds."},
		{"negative inventory", with("inventory_interval", "-300"), "Inventory poll interval must be between 30 and 86400 seconds."},
		{"inventory effectively disabled", with("inventory_interval", "3000000000"), "Inventory poll interval must be between 30 and 86400 seconds."},
		{"missing client id", with("client_id", " "), "OAuth client ID and secret are required."},
		{"missing client secret", with("client_secret", ""), "OAuth client ID and secret are required."},
		{"webhook secret too long", with("webhook_secret", strings.Repeat("s", store.MaxWebhookSecretBytes+1)), "Webhook secret must be at most 1024 bytes."},
		{"tailnet with path", with("tailnet", "example.com/../keys"), "Tailnet must be"},
		{"tailnet too long", with("tailnet", strings.Repeat("t", store.MaxTailnetBytes+1)), "Tailnet must be"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			before := outbound.Load()
			started := time.Now()
			response := coveragePost(t, server, "/settings", test.form, cookies)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("status=%d, want message %q in body=%s", response.Code, test.want, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "Tailscale test failed") {
				t.Fatal("invalid settings reached the Tailscale test")
			}
			if got := outbound.Load(); got != before {
				t.Fatalf("invalid settings made %d outbound requests", got-before)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("local validation took %s", elapsed)
			}
		})
	}
	if _, err := st.Settings(context.Background()); err == nil {
		t.Fatal("invalid settings were persisted")
	}
}

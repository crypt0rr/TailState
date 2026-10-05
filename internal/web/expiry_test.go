package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// configuredExpiryServer returns a claimed, configured server whose fake
// Tailscale API accepts the settings connection test.
func configuredExpiryServer(t *testing.T) (*Server, *store.Store, []*http.Cookie, string) {
	t.Helper()
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	server.config.TailscaleBase = api.URL + "/api/v2"
	server.config.OAuthTokenURL = api.URL + "/oauth/token"
	if _, err := st.SaveDestination(context.Background(), store.NotificationDestination{Name: "Primary", ServiceURL: "generic://notify.example/hook", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return server, st, cookies, csrf
}

func TestSettingsExposeExpiryWindowsAndTagFilter(t *testing.T) {
	server, st, cookies, csrf := configuredExpiryServer(t)
	base := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}

	// The unconfigured form shows the defaults.
	page := authenticatedGet(t, server, "/settings", cookies)
	if !strings.Contains(page.Body.String(), `name="expiry_warning_days" value="14, 3"`) || !strings.Contains(page.Body.String(), `name="expiry_tag_filter"`) {
		t.Fatalf("settings page does not expose expiry options: %s", page.Body.String())
	}

	form := cloneForm(base)
	form.Set("expiry_warning_days", "7, 30 7")
	form.Set("expiry_tag_filter", "tag:server, tag:ci")
	if response := coveragePost(t, server, "/settings", form, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("save status=%d body=%s", response.Code, response.Body.String())
	}
	saved, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.ExpiryWarningDays) != 2 || saved.ExpiryWarningDays[0] != 30 || saved.ExpiryWarningDays[1] != 7 {
		t.Fatalf("saved windows=%v", saved.ExpiryWarningDays)
	}
	if strings.Join(saved.ExpiryTagFilter, ",") != "tag:ci,tag:server" {
		t.Fatalf("saved tag filter=%v", saved.ExpiryTagFilter)
	}
	page = authenticatedGet(t, server, "/settings", cookies)
	if !strings.Contains(page.Body.String(), `value="30, 7"`) || !strings.Contains(page.Body.String(), `value="tag:ci, tag:server"`) {
		t.Fatalf("settings page does not show saved expiry options: %s", page.Body.String())
	}

	// A form without the expiry fields keeps the saved options.
	if response := coveragePost(t, server, "/settings", base, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("legacy form status=%d", response.Code)
	}
	if kept, err := st.Settings(context.Background()); err != nil || len(kept.ExpiryWarningDays) != 2 || len(kept.ExpiryTagFilter) != 2 {
		t.Fatalf("legacy form changed options: %#v err=%v", kept, err)
	}

	// A blank value disables warnings explicitly.
	disabled := cloneForm(base)
	disabled.Set("expiry_warning_days", "")
	disabled.Set("expiry_tag_filter", "")
	if response := coveragePost(t, server, "/settings", disabled, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("disable status=%d", response.Code)
	}
	if off, err := st.Settings(context.Background()); err != nil || off.ExpiryWarningDays == nil || len(off.ExpiryWarningDays) != 0 || len(off.ExpiryTagFilter) != 0 {
		t.Fatalf("disabled options=%#v err=%v", off, err)
	}

	for _, test := range []struct{ field, value, want string }{
		{"expiry_warning_days", "soon", "Expiry warning windows must be whole numbers of days"},
		{"expiry_warning_days", "0", "Expiry warning windows must be at most 4 whole numbers of days between 1 and 365."},
		{"expiry_warning_days", "1,2,3,4,5", "Expiry warning windows must be at most 4"},
		{"expiry_tag_filter", "server", "Expiry tag filter must be a comma-separated list of at most 32 tags such as tag:server."},
	} {
		invalid := cloneForm(base)
		invalid.Set(test.field, test.value)
		response := coveragePost(t, server, "/settings", invalid, cookies)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.want) {
			t.Fatalf("%s=%q status=%d body=%s", test.field, test.value, response.Code, response.Body.String())
		}
	}
}

func TestStatusPageShowsExpiringSoonCard(t *testing.T) {
	server, st, cookies, csrf := configuredExpiryServer(t)
	form := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}
	if response := coveragePost(t, server, "/settings", form, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("save status=%d body=%s", response.Code, response.Body.String())
	}
	settings, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	devices := []model.Resource{
		{ID: "n1", Type: "device", Name: "server.example.ts.net", Data: map[string]any{"name": "server.example.ts.net", "expires": now.Add(5 * 24 * time.Hour).Format(time.RFC3339), "tags": []any{"tag:server"}}},
		{ID: "n2", Type: "device", Name: "disabled.example.ts.net", Data: map[string]any{"name": "disabled.example.ts.net", "expires": now.Add(5 * 24 * time.Hour).Format(time.RFC3339), "keyExpiryDisabled": true}},
		{ID: "n3", Type: "device", Name: "later.example.ts.net", Data: map[string]any{"name": "later.example.ts.net", "expires": now.Add(60 * 24 * time.Hour).Format(time.RFC3339)}},
	}
	keys := []model.Resource{{ID: "k1", Type: "credential", Name: "ci", Data: map[string]any{"keyType": "auth", "description": "ci enrolment", "expires": now.Add(2 * 24 * time.Hour).Format(time.RFC3339)}}}
	if _, err := st.ApplyBatchWithBatch(context.Background(), settings.Generation, []model.Collected{{Collector: "devices", Resources: devices}, {Collector: "keys", Resources: keys}}, notify.Context{}.Digest); err != nil {
		t.Fatal(err)
	}
	body := authenticatedGet(t, server, "/status", cookies).Body.String()
	for _, want := range []string{"Expiring soon", "server.example.ts.net", "tag:server", "ci enrolment", "Auth key", "within 14 days"} {
		if !strings.Contains(body, want) {
			t.Fatalf("status page missing %q: %s", want, body)
		}
	}
	for _, excluded := range []string{"disabled.example.ts.net", "later.example.ts.net"} {
		if strings.Contains(body, excluded) {
			t.Fatalf("status page lists %q: %s", excluded, body)
		}
	}
	if strings.Index(body, "ci enrolment") > strings.Index(body, "server.example.ts.net") {
		t.Fatal("expiring resources are not ordered by expiry")
	}

	settings.ExpiryTagFilter = []string{"tag:other"}
	if _, err := st.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	body = authenticatedGet(t, server, "/status", cookies).Body.String()
	if !strings.Contains(body, "match the expiry tag filter") || !strings.Contains(body, "Nothing expires within 14 days.") {
		t.Fatalf("filtered status page: %s", body)
	}
}

func TestExpiringSoonToleratesStoreFailures(t *testing.T) {
	server, st, db, _ := webServerWithDatabase(t)
	if items, horizon, _ := server.expiringSoon(context.Background(), time.Now()); items != nil || horizon != 14 {
		t.Fatalf("unconfigured card=%v horizon=%d", items, horizon)
	}
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute, ExpiryWarningDays: []int{3}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE snapshots"); err != nil {
		t.Fatal(err)
	}
	if items, horizon, _ := server.expiringSoon(context.Background(), time.Now()); items != nil || horizon != 3 {
		t.Fatalf("failing card=%v horizon=%d", items, horizon)
	}
}

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

func TestSettingsConfigureOAuthScopesAndStatusLabelsInsufficientScope(t *testing.T) {
	server, st, cookies, csrf := configuredExpiryServer(t)
	base := url.Values{"_csrf": {csrf}, "tailnet": {"-"}, "client_id": {"client"}, "client_secret": {"secret"}, "device_interval": {"60"}, "inventory_interval": {"300"}}

	page := authenticatedGet(t, server, "/settings", cookies).Body.String()
	if !strings.Contains(page, `name="oauth_scopes" value="all:read"`) {
		t.Fatalf("settings page does not show the default scope: %s", page)
	}
	for _, scope := range []string{"devices:core", "all:read auth_keys"} {
		invalid := cloneForm(base)
		invalid.Set("oauth_scopes", scope)
		response := coveragePost(t, server, "/settings", invalid, cookies)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "write scopes are not accepted") {
			t.Fatalf("scope %q status=%d body=%s", scope, response.Code, response.Body.String())
		}
	}
	form := cloneForm(base)
	form.Set("oauth_scopes", "devices:core:read, dns:read services:read")
	if response := coveragePost(t, server, "/settings", form, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("save status=%d body=%s", response.Code, response.Body.String())
	}
	saved, err := st.Settings(context.Background())
	if err != nil || strings.Join(saved.OAuthScopes, " ") != "devices:core:read dns:read services:read" {
		t.Fatalf("scopes=%v err=%v", saved.OAuthScopes, err)
	}
	if !strings.Contains(authenticatedGet(t, server, "/settings", cookies).Body.String(), `value="devices:core:read dns:read services:read"`) {
		t.Fatal("settings page does not show the saved scopes")
	}
	// A form without the field keeps the configured scopes.
	if response := coveragePost(t, server, "/settings", base, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("legacy form status=%d", response.Code)
	}
	if kept, err := st.Settings(context.Background()); err != nil || len(kept.OAuthScopes) != 3 {
		t.Fatalf("legacy form changed scopes: %v err=%v", kept.OAuthScopes, err)
	}

	results := []model.Collected{{Collector: "oauth_apps", Unsupported: true, UnsupportedReason: "unsupported (insufficient OAuth scope or plan: HTTP 403)"}}
	if _, err := st.ApplyBatchWithBatch(context.Background(), saved.Generation, results, notify.Context{}.Digest); err != nil {
		t.Fatal(err)
	}
	status := authenticatedGet(t, server, "/status", cookies).Body.String()
	if !strings.Contains(status, "<code>oauth_apps</code></th>") || !strings.Contains(status, `<td data-label="State">Unsupported</td>`) || !strings.Contains(status, "insufficient OAuth scope or plan") {
		t.Fatalf("status page does not label the insufficient scope: %s", status)
	}
}

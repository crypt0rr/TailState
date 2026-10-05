package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestMuteRulesAreManagedInSettingsWithCSRF guards E-009: mute rules are
// added and removed from Settings behind CSRF, validated, and muted changes
// are shown (flagged) in History.
func TestMuteRulesAreManagedInSettingsWithCSRF(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	ctx := context.Background()

	add := url.Values{"action": {"add"}, "kind": {"field"}, "value": {"devices.clientVersion"}}
	if forged := coveragePost(t, server, "/settings/mutes", add, cookies); forged.Code != http.StatusUnauthorized {
		t.Fatalf("mute rule without CSRF status=%d", forged.Code)
	}
	add.Set("_csrf", csrf)
	if saved := coveragePost(t, server, "/settings/mutes", add, cookies); saved.Code != http.StatusSeeOther {
		t.Fatalf("mute rule save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if duplicate := coveragePost(t, server, "/settings/mutes", add, cookies); !strings.Contains(duplicate.Body.String(), "an identical rule already exists") {
		t.Fatalf("duplicate rule response: %s", duplicate.Body.String())
	}
	for _, invalid := range []url.Values{
		{"_csrf": {csrf}, "action": {"add"}, "kind": {"collector"}, "value": {"nonsense"}},
		{"_csrf": {csrf}, "action": {"add"}, "kind": {"field"}, "value": {"nonsense.field"}},
		{"_csrf": {csrf}, "action": {"add"}, "kind": {"tag"}, "value": {"ci"}},
	} {
		if response := coveragePost(t, server, "/settings/mutes", invalid, cookies); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Mute rule was not saved") {
			t.Fatalf("invalid rule %v status=%d body=%s", invalid, response.Code, response.Body.String())
		}
	}
	page := authenticatedGet(t, server, "/settings", cookies).Body.String()
	if !strings.Contains(page, "Noise controls") || !strings.Contains(page, "<code>devices.clientVersion</code>") {
		t.Fatalf("settings page does not list the mute rule: %s", page)
	}

	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0", "1.1"} {
		if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"clientVersion": version}}}}}, notify.Context{}.Digest); err != nil {
			t.Fatal(err)
		}
	}
	history := authenticatedGet(t, server, "/history", cookies).Body.String()
	if !strings.Contains(history, `class="muted-flag"`) {
		t.Fatalf("History does not flag the muted change: %s", history)
	}

	rules, err := st.ListMuteRules(ctx)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	remove := url.Values{"_csrf": {csrf}, "action": {"delete"}, "id": {fmt.Sprint(rules[0].ID)}}
	if removed := coveragePost(t, server, "/settings/mutes", remove, cookies); removed.Code != http.StatusSeeOther {
		t.Fatalf("remove status=%d", removed.Code)
	}
	if missing := coveragePost(t, server, "/settings/mutes", remove, cookies); missing.Code != http.StatusBadRequest {
		t.Fatalf("removing a missing rule status=%d", missing.Code)
	}
	if unknown := coveragePost(t, server, "/settings/mutes", url.Values{"_csrf": {csrf}, "action": {"rename"}}, cookies); unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown action status=%d", unknown.Code)
	}
}

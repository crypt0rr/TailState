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
	if forged := coveragePost(t, server, "/settings/mutes", add, cookies); forged.Code != http.StatusForbidden {
		t.Fatalf("mute rule without CSRF status=%d", forged.Code)
	}
	add.Set("_csrf", csrf)
	if saved := coveragePost(t, server, "/settings/mutes", add, cookies); saved.Code != http.StatusSeeOther {
		t.Fatalf("mute rule save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if duplicate := followFlash(t, server, cookies, coveragePost(t, server, "/settings/mutes", add, cookies)); !strings.Contains(duplicate, "an identical rule already exists") {
		t.Fatalf("duplicate rule response: %s", duplicate)
	}
	for _, invalid := range []url.Values{
		{"_csrf": {csrf}, "action": {"add"}, "kind": {"collector"}, "value": {"nonsense"}},
		{"_csrf": {csrf}, "action": {"add"}, "kind": {"field"}, "value": {"nonsense.field"}},
		{"_csrf": {csrf}, "action": {"add"}, "kind": {"tag"}, "value": {"ci"}},
	} {
		response := coveragePost(t, server, "/settings/mutes", invalid, cookies)
		if body := followFlash(t, server, cookies, response); response.Code != http.StatusSeeOther || !strings.Contains(body, "Mute rule was not saved") {
			t.Fatalf("invalid rule %v status=%d body=%s", invalid, response.Code, body)
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
	removed := coveragePost(t, server, "/settings/mutes", remove, cookies)
	if body := followFlash(t, server, cookies, removed); removed.Code != http.StatusSeeOther || !strings.Contains(body, "Mute rule removed.") {
		t.Fatalf("remove status=%d body=%s", removed.Code, body)
	}
	missing := coveragePost(t, server, "/settings/mutes", remove, cookies)
	if body := followFlash(t, server, cookies, missing); missing.Code != http.StatusSeeOther || !strings.Contains(body, "Mute rule not found.") || !strings.Contains(body, `role="alert"`) {
		t.Fatalf("removing a missing rule status=%d body=%s", missing.Code, body)
	}
	if unknown := coveragePost(t, server, "/settings/mutes", url.Values{"_csrf": {csrf}, "action": {"rename"}}, cookies); unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown action status=%d", unknown.Code)
	}
}

package web

import (
	"context"
	"fmt"
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

// TestDestinationRoutingIsEditableWithCSRF guards E-008: routing rules are
// edited from Settings, require a valid CSRF token, reject unknown
// collectors, and are never reset by a form that does not carry them.
func TestDestinationRoutingIsEditableWithCSRF(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	ctx := context.Background()
	id, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Pager", ServiceURL: "generic://notify.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"action": {"save"}, "id": {fmt.Sprint(id)}, "name": {"Pager"}, "enabled": {"on"}, "routing": {"1"},
		"min_severity": {"high"}, "include_collectors": {"policy, keys"}, "exclude_collectors": {""}, "change_kinds": {"created", "changed"},
	}
	forged := coveragePost(t, server, "/settings/destinations", form, cookies)
	if forged.Code != http.StatusUnauthorized {
		t.Fatalf("routing change without CSRF status=%d", forged.Code)
	}
	form.Set("_csrf", csrf)
	saved := coveragePost(t, server, "/settings/destinations", form, cookies)
	if saved.Code != http.StatusSeeOther {
		t.Fatalf("routing save status=%d body=%s", saved.Code, saved.Body.String())
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%+v err=%v", destinations, err)
	}
	rules := destinations[0].Routing
	if rules.MinSeverity != "high" || strings.Join(rules.IncludeCollectors, ",") != "keys,policy" || strings.Join(rules.ChangeKinds, ",") != "changed,created" {
		t.Fatalf("saved routing=%+v", rules)
	}
	page := authenticatedGet(t, server, "/settings", cookies)
	if !strings.Contains(page.Body.String(), "Routing: severity high or higher; only keys, policy; changed, created changes") || !strings.Contains(page.Body.String(), `value="keys, policy"`) {
		t.Fatalf("settings page does not show routing: %s", page.Body.String())
	}

	invalid := cloneForm(form)
	invalid.Set("include_collectors", "policy, nonsense")
	rejected := coveragePost(t, server, "/settings/destinations", invalid, cookies)
	if rejected.Code != http.StatusOK || !strings.Contains(rejected.Body.String(), "Notification routing was not saved") {
		t.Fatalf("unknown collector status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	invalid = cloneForm(form)
	invalid.Set("exclude_collectors", "nonsense")
	if rejected := coveragePost(t, server, "/settings/destinations", invalid, cookies); !strings.Contains(rejected.Body.String(), "Notification routing was not saved") {
		t.Fatalf("unknown excluded collector accepted: %s", rejected.Body.String())
	}
	invalid = cloneForm(form)
	invalid.Set("min_severity", "critical")
	if rejected := coveragePost(t, server, "/settings/destinations", invalid, cookies); !strings.Contains(rejected.Body.String(), "Notification routing was not saved") {
		t.Fatalf("unknown severity accepted: %s", rejected.Body.String())
	}

	rename := url.Values{"_csrf": {csrf}, "action": {"save"}, "id": {fmt.Sprint(id)}, "name": {"Pager renamed"}, "enabled": {"on"}}
	if response := coveragePost(t, server, "/settings/destinations", rename, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("rename status=%d", response.Code)
	}
	destinations, _ = st.ListDestinations(ctx)
	if destinations[0].Name != "Pager renamed" || destinations[0].Routing.MinSeverity != "high" {
		t.Fatalf("a save without routing fields changed the rules: %+v", destinations[0])
	}

	reset := cloneForm(form)
	reset.Set("min_severity", "")
	reset.Set("include_collectors", "")
	reset.Del("change_kinds")
	if response := coveragePost(t, server, "/settings/destinations", reset, cookies); response.Code != http.StatusSeeOther {
		t.Fatalf("reset status=%d", response.Code)
	}
	destinations, _ = st.ListDestinations(ctx)
	if !destinations[0].Routing.AllChanges() {
		t.Fatalf("routing was not reset to all changes: %+v", destinations[0].Routing)
	}
	if got := routingSummary(store.RoutingRules{ExcludeCollectors: []string{"devices"}}); got != "excluding devices" {
		t.Fatalf("summary=%q", got)
	}
}

func TestHistorySeverityFilterIsOffered(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	ctx := context.Background()
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0", "1.1"} {
		if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"clientVersion": version}}}}}, notify.TextDigest("digest")); err != nil {
			t.Fatal(err)
		}
	}
	low := authenticatedGet(t, server, "/history?severity=low", cookies).Body.String()
	if !strings.Contains(low, `<option value="low" selected>`) || !strings.Contains(low, `class="severity severity-low"`) || !strings.Contains(low, "/history/export?severity=low") {
		t.Fatalf("low severity history page: %s", low)
	}
	high := authenticatedGet(t, server, "/history?severity=high", cookies).Body.String()
	if !strings.Contains(high, "No changes match these filters") {
		t.Fatalf("high severity history page lists a low change: %s", high)
	}
	if ignored := historyFilter(httptest.NewRequest(http.MethodGet, "/history?severity=critical", nil)); ignored.Severity != "" {
		t.Fatalf("invalid severity filter=%q", ignored.Severity)
	}
}

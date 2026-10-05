package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// TestSingleObjectCollectorsRejectNonObjectResponses checks that a null,
// empty, array or scalar body from a single-object endpoint is a collector
// failure: no events are recorded, the snapshot is preserved, and a later
// valid response equal to the baseline produces no drift either.
func TestSingleObjectCollectorsRejectNonObjectResponses(t *testing.T) {
	cases := []struct {
		collector string
		path      string
		valid     string
	}{
		{collector: "settings", path: "/api/v2/tailnet/-/settings", valid: `{"devicesApprovalOn":true}`},
		{collector: "contacts", path: "/api/v2/tailnet/-/contacts", valid: `{"account":{"email":"owner@example.com"}}`},
		{collector: "policy", path: "/api/v2/tailnet/-/acl", valid: `{"acls":[{"action":"accept"}]}`},
		{collector: "dns", path: "/api/v2/tailnet/-/dns/preferences", valid: `{"magicDNS":true}`},
		{collector: "log_streaming", path: "/api/v2/tailnet/-/logging/configuration/stream", valid: `{"destinationType":"splunk"}`},
		{collector: "log_streaming", path: "/api/v2/tailnet/-/logging/configuration/stream/status", valid: `{"lastActivity":"2026-10-01T00:00:00Z"}`},
	}
	invalidBodies := map[string]string{"null": `null`, "empty": ``, "array": `[]`, "number": `42`, "string": `"text"`, "boolean": `true`}
	for _, tc := range cases {
		for name, invalid := range invalidBodies {
			t.Run(tc.collector+"/"+tc.path+"/"+name, func(t *testing.T) {
				ctx := context.Background()
				st, settings, db := monitorTestStoreWithDB(t)
				var broken atomic.Bool
				api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/oauth/token":
						_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
					case tc.path:
						if broken.Load() {
							_, _ = w.Write([]byte(invalid))
							return
						}
						_, _ = w.Write([]byte(tc.valid))
					case "/api/v2/tailnet/-/dns/nameservers", "/api/v2/tailnet/-/dns/searchpaths", "/api/v2/tailnet/-/dns/split-dns":
						_, _ = w.Write([]byte(`{}`))
					case "/api/v2/tailnet/-/logging/configuration/stream":
						_, _ = w.Write([]byte(`{"destinationType":"splunk"}`))
					case "/api/v2/tailnet/-/logging/configuration/stream/status":
						_, _ = w.Write([]byte(`{}`))
					default:
						http.NotFound(w, r)
					}
				}))
				defer api.Close()
				client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
				engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
				if !engine.poll(ctx, client, settings, []string{tc.collector}, true) {
					t.Fatal("baseline poll failed")
				}
				snapshotHash := func() string {
					var hash string
					if err := db.QueryRowContext(ctx, "SELECT content_hash FROM snapshots WHERE generation=? AND collector=?", settings.Generation, tc.collector).Scan(&hash); err != nil {
						t.Fatal(err)
					}
					return hash
				}
				baseline := snapshotHash()

				broken.Store(true)
				if engine.poll(ctx, client, settings, []string{tc.collector}, true) {
					t.Fatalf("%s body %q was accepted as a successful poll", name, invalid)
				}
				if got := snapshotHash(); got != baseline {
					t.Fatalf("invalid %s response replaced the snapshot", name)
				}
				collectorFailed := false
				status, err := st.Status(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, state := range status.Collectors {
					if state.Name == tc.collector {
						collectorFailed = state.FailureCount == 1 && state.LastError != ""
					}
				}
				if !collectorFailed {
					t.Fatalf("invalid %s response was not recorded as a collector failure: %#v", name, status.Collectors)
				}

				broken.Store(false)
				if !engine.poll(ctx, client, settings, []string{tc.collector}, true) {
					t.Fatal("recovery poll failed")
				}
				page, err := st.ListHistory(ctx, store.HistoryFilter{Collector: tc.collector, Limit: 10})
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Batches) != 0 {
					t.Fatalf("invalid %s response produced history: %#v", name, page.Batches)
				}
			})
		}
	}
}

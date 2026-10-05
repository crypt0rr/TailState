package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

type fakeDevice struct {
	id, version, os, osVersion string
	routes                     []string
}

// deviceInventoryAPI serves devices?fields=all plus the per-device detail
// endpoints with consistent data, the way Tailscale reports the same route
// and client version on several endpoints.
type deviceInventoryAPI struct {
	mu      sync.Mutex
	devices []fakeDevice
}

func (a *deviceInventoryAPI) set(devices ...fakeDevice) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.devices = devices
}

func quoted(values []string) string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = `"` + value + `"`
	}
	return "[" + strings.Join(out, ",") + "]"
}

func (a *deviceInventoryAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/oauth/token" {
		_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		return
	}
	if r.URL.Path == "/api/v2/tailnet/-/devices" {
		items := make([]string, 0, len(a.devices))
		for _, device := range a.devices {
			items = append(items, fmt.Sprintf(`{"id":%q,"hostname":%q,"clientVersion":%q,"os":%q,"advertisedRoutes":%s,"enabledRoutes":%s}`, device.id, device.id, device.version, device.os, quoted(device.routes), quoted(device.routes)))
		}
		_, _ = w.Write([]byte(`{"devices":[` + strings.Join(items, ",") + `]}`))
		return
	}
	for _, device := range a.devices {
		prefix := "/api/v2/device/" + device.id + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			continue
		}
		switch strings.TrimPrefix(r.URL.Path, prefix) {
		case "routes":
			_, _ = fmt.Fprintf(w, `{"advertisedRoutes":%s,"enabledRoutes":%s}`, quoted(device.routes), quoted(device.routes))
		case "attributes":
			_, _ = fmt.Fprintf(w, `{"attributes":{"custom:tier":"prod","node:os":%q,"node:osVersion":%q,"node:tsVersion":%q}}`, device.os, device.osVersion, device.version)
		case "device-invites":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
		return
	}
	http.NotFound(w, r)
}

func deviceEventCount(t *testing.T, st *store.Store) int {
	t.Helper()
	page, err := st.ListHistory(context.Background(), store.HistoryFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, batch := range page.Batches {
		count += len(batch.Events)
	}
	return count
}

// TestOneDeviceChangeProducesOneEvent checks that the devices and
// device_details collectors never report the same change twice.
func TestOneDeviceChangeProducesOneEvent(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api := &deviceInventoryAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test", &scriptedSender{})
	collectors := []string{"devices", "device_details"}
	poll := func() {
		t.Helper()
		if !engine.poll(ctx, client, settings, collectors, true) {
			t.Fatal("poll failed")
		}
	}
	expect := func(step string, want int) {
		t.Helper()
		if got := deviceEventCount(t, st); got != want {
			t.Fatalf("%s: total events=%d, want %d", step, got, want)
		}
	}

	base := fakeDevice{id: "d1", version: "1.80.0", os: "linux", osVersion: "6.1", routes: []string{"10.0.0.0/24"}}
	api.set(base)
	poll()
	expect("baseline", 0)

	added := fakeDevice{id: "d2", version: "1.80.0", os: "linux", osVersion: "6.1"}
	api.set(base, added)
	poll()
	expect("new device", 1)

	rerouted := base
	rerouted.routes = []string{"10.0.0.0/24", "10.1.0.0/24"}
	api.set(rerouted, added)
	poll()
	expect("route change", 2)

	upgraded := rerouted
	upgraded.version, upgraded.osVersion = "1.82.0", "6.6"
	api.set(upgraded, added)
	poll()
	expect("client upgrade", 3)

	api.set(upgraded)
	poll()
	expect("first poll without the removed device", 3)
	poll()
	expect("confirmed removal", 4)
}

// TestDeviceDetailsUpgradeDoesNotReportDrift checks that snapshots stored by
// releases that also kept routes and OS/version posture attributes in
// device_details are re-normalized before diffing.
func TestDeviceDetailsUpgradeDoesNotReportDrift(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	api := &deviceInventoryAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test", &scriptedSender{})
	api.set(fakeDevice{id: "d1", version: "1.80.0", os: "linux", osVersion: "6.1", routes: []string{"10.0.0.0/24"}})
	if !engine.poll(ctx, client, settings, []string{"devices", "device_details"}, true) {
		t.Fatal("baseline poll failed")
	}
	legacy := `{"deviceInvites":[],"postureAttributes":{"attributes":{"custom:tier":"prod","node:os":"linux","node:osVersion":"6.1","node:tsVersion":"1.80.0"}},"routes":{"advertisedRoutes":["10.0.0.0/24"],"enabledRoutes":["10.0.0.0/24"]}}`
	if _, err := db.ExecContext(ctx, "UPDATE snapshots SET canonical_json=?,content_hash='legacy-hash',content_bytes=? WHERE generation=? AND collector='device_details' AND resource_id='d1'", []byte(legacy), len(legacy), settings.Generation); err != nil {
		t.Fatal(err)
	}
	if !engine.poll(ctx, client, settings, []string{"devices", "device_details"}, true) {
		t.Fatal("upgrade poll failed")
	}
	if got := deviceEventCount(t, st); got != 0 {
		t.Fatalf("upgrade re-normalization reported %d drift events", got)
	}
}

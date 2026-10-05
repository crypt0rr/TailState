package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// countingUsersAPI serves the minimal monitor test inventory and counts the
// users collector requests so scheduler tests can observe when it is polled.
func countingUsersAPI(t *testing.T, users *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			users.Add(1)
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v2/device/device-1/routes", "/api/v2/device/device-1/attributes", "/api/v2/device/device-1/device-invites":
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// baselinedHourlyStore returns a store whose collectors have all been polled
// once with one-hour intervals, so nothing is due for an hour unless a
// persisted per-collector deadline says otherwise.
func baselinedHourlyStore(t *testing.T, api *httptest.Server) (*store.Store, store.Settings) {
	t.Helper()
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	settings.DeviceInterval = time.Hour
	settings.InventoryInterval = time.Hour
	if _, err := st.SaveSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	saved, err := st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	engine.poll(ctx, client, saved, allCollectors(), true)
	return st, saved
}

func waitForCount(counter *atomic.Int32, above int32, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if counter.Load() > above {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return counter.Load() > above
}

func TestSchedulerHonorsPersistedDeadlineAfterRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var users atomic.Int32
	api := countingUsersAPI(t, &users)
	st, settings := baselinedHourlyStore(t, api)
	// A short retry deadline persisted before the restart, far earlier than
	// the one-hour inventory interval.
	if err := st.SetNextPollErr(ctx, settings.Generation, []string{"users"}, time.Now().Add(400*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	before := users.Load()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	if !waitForCount(&users, before, 4*time.Second) {
		t.Fatal("scheduler ignored the persisted users deadline after restart and waited for the full interval")
	}
	cancel()
	<-done
}

func TestSchedulerHonorsPersistedDeadlineAfterSettingsRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var users atomic.Int32
	api := countingUsersAPI(t, &users)
	st, settings := baselinedHourlyStore(t, api)
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	// Let the scheduler arm its timers from the hourly deadlines first.
	time.Sleep(200 * time.Millisecond)
	before := users.Load()
	if err := st.SetNextPollErr(ctx, settings.Generation, []string{"users"}, time.Now().Add(400*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// Rotate the OAuth secret: a non-identity refresh that re-arms the timers.
	rotated := settings
	rotated.OAuthClientSecret = "rotated-secret"
	if generation, err := st.SaveSettings(ctx, rotated); err != nil || generation != settings.Generation {
		t.Fatalf("rotate secret generation=%d err=%v", generation, err)
	}
	engine.Wake()
	if !waitForCount(&users, before, 4*time.Second) {
		t.Fatal("scheduler ignored the persisted users deadline after a credential refresh and waited for the full interval")
	}
	cancel()
	<-done
}

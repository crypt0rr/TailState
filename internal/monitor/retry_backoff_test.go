package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

func TestCollectorRetryDelayBacksOffToInterval(t *testing.T) {
	interval := 5 * time.Minute
	want := []time.Duration{30 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for failures, expected := range want {
		if got := collectorRetryDelay(failures, interval); got != expected {
			t.Fatalf("failures=%d delay=%s, want %s", failures, got, expected)
		}
	}
	if got := collectorRetryDelay(1000, 12*time.Hour); got != 12*time.Hour {
		t.Fatalf("large failure count delay=%s, want interval cap", got)
	}
	if got := collectorRetryDelay(5, 10*time.Second); got != collectorRetryInterval {
		t.Fatalf("short interval delay=%s, want base retry %s", got, collectorRetryInterval)
	}
}

func collectorNextPoll(t *testing.T, st *store.Store, collector string) (time.Time, int) {
	t.Helper()
	status, err := st.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range status.Collectors {
		if state.Name == collector {
			if state.NextPoll == nil {
				t.Fatalf("%s has no next poll", collector)
			}
			return *state.NextPoll, state.FailureCount
		}
	}
	t.Fatalf("%s state missing", collector)
	return time.Time{}, 0
}

func TestPermanentlyFailingDeviceBacksOffDeviceDetailsRetries(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	var broken atomic.Bool
	broken.Store(true)
	var fanouts atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case r.URL.Path == "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"healthy","hostname":"healthy"},{"id":"broken","hostname":"broken"}]}`))
		case r.URL.Path == "/api/v2/device/healthy/routes":
			fanouts.Add(1)
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v2/device/healthy/"):
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v2/device/broken/") && broken.Load():
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v2/device/broken/"):
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	// Each consecutive partial poll doubles the retry delay until it reaches
	// the five-minute inventory interval.
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for attempt, expected := range want {
		before := time.Now()
		if engine.poll(ctx, client, settings, []string{"device_details"}, true) {
			t.Fatal("partial device_details poll reported success")
		}
		next, failures := collectorNextPoll(t, st, "device_details")
		delay := next.Sub(before)
		if delay < expected || delay > expected+5*time.Second {
			t.Fatalf("attempt %d (failures=%d) retry delay=%s, want %s", attempt+1, failures, delay, expected)
		}
	}
	if got := fanouts.Load(); got != int32(len(want)) {
		t.Fatalf("fan-outs=%d, want one per poll (%d)", got, len(want))
	}
	// Only collectors that are due are polled on scheduled wakeups, so a
	// scheduled poll right now does not fan out again.
	engine.poll(ctx, client, settings, []string{"device_details"}, false)
	if got := fanouts.Load(); got != int32(len(want)) {
		t.Fatalf("scheduled poll before the backoff deadline fanned out again: %d", got)
	}

	// A successful poll resets the backoff.
	broken.Store(false)
	if !engine.poll(ctx, client, settings, []string{"device_details"}, true) {
		t.Fatal("recovered device_details poll failed")
	}
	broken.Store(true)
	before := time.Now()
	engine.poll(ctx, client, settings, []string{"device_details"}, true)
	next, _ := collectorNextPoll(t, st, "device_details")
	if delay := next.Sub(before); delay < collectorRetryInterval || delay > collectorRetryInterval+5*time.Second {
		t.Fatalf("retry delay after recovery=%s, want reset to %s", delay, collectorRetryInterval)
	}
}

func TestFailingCoreCollectorBackoffIsCappedAtDeviceInterval(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	status := &atomic.Int32{}
	status.Store(http.StatusInternalServerError)
	api := monitorTestAPI(t, status)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	want := []time.Duration{30 * time.Second, time.Minute, time.Minute}
	for attempt, expected := range want {
		before := time.Now()
		engine.poll(ctx, client, settings, []string{"devices"}, true)
		next, _ := collectorNextPoll(t, st, "devices")
		if delay := next.Sub(before); delay < expected || delay > expected+5*time.Second {
			t.Fatalf("attempt %d devices retry delay=%s, want %s", attempt+1, delay, expected)
		}
	}
}

func TestOverlappingDurableTriggersPollEachCollectorOnce(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	var devices, users atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			devices.Add(1)
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			users.Add(1)
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	scopes := [][]string{{"devices"}, {"devices", "users"}, {"users"}}
	for index, scope := range scopes {
		if _, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat(string(rune('a'+index)), 64), nil, scope); err != nil || !created {
			t.Fatalf("record trigger %v: created=%v err=%v", scope, created, err)
		}
	}
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.processDurableTriggers(ctx, client, settings) {
		t.Fatal("durable triggers were not processed")
	}
	if devices.Load() != 1 || users.Load() != 1 {
		t.Fatalf("overlapping triggers polled devices=%d users=%d times, want once each", devices.Load(), users.Load())
	}
	for index := range scopes {
		state, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat(string(rune('a'+index)), 64), nil, nil)
		if err != nil || state.Status != "processed" {
			t.Fatalf("trigger %d state=%#v err=%v", index, state, err)
		}
	}
}

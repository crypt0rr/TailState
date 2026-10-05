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

// logStreamingAPI serves a configuration log stream while configured is true
// and the documented "not configured" 404 otherwise. The network stream is
// never configured.
func logStreamingAPI(t *testing.T, configured *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/logging/configuration/stream":
			if !configured.Load() {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"destinationType":"splunk","url":"https://splunk.example/services/collector"}`))
		case "/api/v2/tailnet/-/logging/configuration/stream/status":
			if !configured.Load() {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"lastActivity":"2026-10-05T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func pollLogStreaming(t *testing.T, engine *Engine, client *tailscale.Client, settings store.Settings) {
	t.Helper()
	if !engine.poll(context.Background(), client, settings, []string{"log_streaming"}, true) {
		t.Fatal("log streaming poll reported failure")
	}
}

func logStreamingEvents(t *testing.T, st *store.Store) []store.HistoryEvent {
	t.Helper()
	page, err := st.ListHistory(context.Background(), store.HistoryFilter{Collector: "log_streaming", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var events []store.HistoryEvent
	for _, batch := range page.Batches {
		events = append(events, batch.Events...)
	}
	return events
}

// TestDisabledLogStreamIsReportedAsDrift guards the regression where a 404
// after deleting a configured stream was classified as a plan capability and
// the collector was silently marked unsupported.
func TestDisabledLogStreamIsReportedAsDrift(t *testing.T) {
	st, settings := monitorTestStore(t)
	configured := &atomic.Bool{}
	configured.Store(true)
	api := logStreamingAPI(t, configured)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	pollLogStreaming(t, engine, client, settings)
	if events := logStreamingEvents(t, st); len(events) != 0 {
		t.Fatalf("baseline produced events: %#v", events)
	}
	configured.Store(false)
	pollLogStreaming(t, engine, client, settings)
	events := logStreamingEvents(t, st)
	if len(events) != 1 || events[0].EventType != "changed" {
		t.Fatalf("disabling the configuration log stream produced %#v, want one changed event", events)
	}
	status, err := st.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, collector := range status.Collectors {
		if collector.Name == "log_streaming" && !collector.Supported {
			t.Fatalf("log streaming was demoted to unsupported: %#v", collector)
		}
	}
}

func TestFirstConfiguredLogStreamIsReportedAsDrift(t *testing.T) {
	st, settings := monitorTestStore(t)
	configured := &atomic.Bool{}
	api := logStreamingAPI(t, configured)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	pollLogStreaming(t, engine, client, settings)
	if events := logStreamingEvents(t, st); len(events) != 0 {
		t.Fatalf("unconfigured baseline produced events: %#v", events)
	}
	configured.Store(true)
	pollLogStreaming(t, engine, client, settings)
	if events := logStreamingEvents(t, st); len(events) != 1 || events[0].EventType != "changed" {
		t.Fatalf("configuring the first log stream produced %#v, want one changed event", events)
	}
}

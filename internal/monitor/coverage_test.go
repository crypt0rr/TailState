package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

func monitorTestStore(t *testing.T) (*store.Store, store.Settings) {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir()+"/tailstate.db", box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	settings := store.Settings{
		Tailnet:           "-",
		OAuthClientID:     "client",
		OAuthClientSecret: "secret",
		WebhookSecret:     "webhook-secret",
		MattermostURL:     "https://mattermost.example/hooks/token",
		DeviceInterval:    time.Minute,
		InventoryInterval: 5 * time.Minute,
	}
	if _, err := st.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	saved, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st, saved
}

func monitorTestAPI(t *testing.T, status *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		code := http.StatusOK
		if status != nil {
			code = int(status.Load())
		}
		if code == 0 {
			code = http.StatusOK
		}
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestPollPersistsBaselineAndCorrelatesTrigger(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	status := &atomic.Int32{}
	api := monitorTestAPI(t, status)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), []string{"nodeCreated"}, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}

	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.poll(ctx, client, settings, []string{"devices"}, true, trigger.ID) {
		t.Fatal("successful poll returned false")
	}
	if err := st.CompleteWebhookTriggers(ctx, []int64{trigger.ID}); err != nil {
		t.Fatal(err)
	}
	completed, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), nil, nil)
	if err != nil || completed.Status != "processed" {
		t.Fatalf("trigger was not completed after poll: %#v err=%v", completed, err)
	}
	current, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.BaselineAt == nil || len(current.ResourceCounts) != 1 || current.ResourceCounts["devices"] != 1 {
		t.Fatalf("baseline or resource count missing: %#v", current)
	}
	page, err := st.ListHistory(ctx, store.HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 0 {
		t.Fatalf("baseline unexpectedly emitted change history: %#v", page.Batches)
	}
}

func TestPollHandlesUnsupportedFailureAndRecovery(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	status := &atomic.Int32{}
	api := monitorTestAPI(t, status)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	status.Store(http.StatusNotFound)
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("unsupported collector should not fail the poll")
	}
	status.Store(http.StatusInternalServerError)
	for i := 0; i < 3; i++ {
		if engine.poll(ctx, client, settings, []string{"devices"}, true) {
			t.Fatalf("failed collector poll %d unexpectedly succeeded", i+1)
		}
	}
	current, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var devices store.CollectorState
	for _, collector := range current.Collectors {
		if collector.Name == "devices" {
			devices = collector
		}
	}
	if devices.FailureCount != 3 {
		t.Fatalf("failure count=%d, want 3", devices.FailureCount)
	}
	if current.Pending != 1 {
		t.Fatalf("unhealthy notification count=%d, want 1", current.Pending)
	}

	status.Store(http.StatusOK)
	if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
		t.Fatal("recovery poll failed")
	}
	current, err = st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Pending != 2 {
		t.Fatalf("recovery notification was not queued: pending=%d", current.Pending)
	}
	items, err := st.DueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	seenUnhealthy, seenRecovered := false, false
	for _, item := range items {
		seenUnhealthy = seenUnhealthy || strings.Contains(item.Payload, "unhealthy")
		seenRecovered = seenRecovered || strings.Contains(item.Payload, "recovered")
	}
	if !seenUnhealthy || !seenRecovered {
		t.Fatalf("health notifications missing: unhealthy=%v recovered=%v", seenUnhealthy, seenRecovered)
	}
}

func TestProcessDurableTriggersCompletesTargetedWork(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	status := &atomic.Int32{}
	api := monitorTestAPI(t, status)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), nil, []string{"devices", "devices"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.processDurableTriggers(ctx, client, settings) {
		t.Fatal("durable trigger was not processed")
	}
	processed, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), nil, nil)
	if err != nil || processed.Status != "processed" || processed.Attempts != 1 {
		t.Fatalf("durable trigger state=%#v err=%v", processed, err)
	}
}

func TestMonitorRequestHelpersAndWakeAreCoalesced(t *testing.T) {
	engine := New(nil, "", "", "test", &scriptedSender{})
	engine.Wake()
	engine.Wake()
	if len(engine.wake) != 1 {
		t.Fatalf("wake channel length=%d, want 1", len(engine.wake))
	}
	if got := normalizeCollectors([]string{" devices ", "", "devices", "users"}); strings.Join(got, ",") != "devices,users" {
		t.Fatalf("normalized collectors=%v", got)
	}
	if got := requestTriggerIDs(ReconcileRequest{TriggerID: 4, TriggerIDs: []int64{-1, 7, 4, 0, 7}}); strings.Join(int64Strings(got), ",") != "4,7" {
		t.Fatalf("trigger IDs=%v", got)
	}
	collectors := allCollectors()
	if len(collectors) == 0 {
		t.Fatal("allCollectors returned no collectors")
	}
	first := collectors[0]
	collectors[0] = "changed"
	if allCollectors()[0] != first {
		t.Fatal("allCollectors did not return an independent copy")
	}
}

func int64Strings(values []int64) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strconv.FormatInt(value, 10)
	}
	return out
}

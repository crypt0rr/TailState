package monitor

import (
	"context"
	"database/sql"
	"errors"
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
	st, settings, _ := openMonitorTestStore(t)
	return st, settings
}

func openMonitorTestStore(t *testing.T) (*store.Store, store.Settings, string) {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/tailstate.db"
	st, err := store.Open(path, box)
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
	return st, saved, path
}

func monitorTestStoreWithDB(t *testing.T) (*store.Store, store.Settings, *sql.DB) {
	t.Helper()
	st, settings, path := openMonitorTestStore(t)
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return st, settings, db
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
		case "/api/v2/device/device-1/routes", "/api/v2/device/device-1/attributes", "/api/v2/device/device-1/device-invites":
			_, _ = w.Write([]byte(`{}`))
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
	st, settings, db := monitorTestStoreWithDB(t)
	status := &atomic.Int32{}
	api := monitorTestAPI(t, status)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	status.Store(http.StatusNotFound)
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("unsupported collector should not fail the poll")
	}
	var unsupportedNext string
	if err := db.QueryRowContext(ctx, "SELECT next_poll FROM collector_state WHERE generation=? AND collector='users'", settings.Generation).Scan(&unsupportedNext); err != nil {
		t.Fatal(err)
	}
	unsupportedAt, err := time.Parse(time.RFC3339Nano, unsupportedNext)
	if err != nil || time.Until(unsupportedAt) < 5*time.Hour {
		t.Fatalf("unsupported collector retry was scheduled too soon: %q", unsupportedNext)
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

func TestPollSanitizesTailscaleProviderErrors(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		if r.URL.Path == "/api/v2/tailnet/-/devices" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("UPSTREAM-SECRET-RESPONSE"))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if engine.poll(ctx, client, settings, []string{"devices"}, true) {
		t.Fatal("provider failure unexpectedly succeeded")
	}
	var lastError string
	if err := db.QueryRowContext(ctx, "SELECT last_error FROM collector_state WHERE generation=? AND collector='devices'", settings.Generation).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(lastError, "UPSTREAM-SECRET-RESPONSE") || lastError != "Tailscale request to /api/v2/tailnet/-/devices returned HTTP 502" {
		t.Fatalf("collector error was not sanitized: %q", lastError)
	}
}

func TestPollDoesNotBaselineEmptyPartialResponse(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		if r.URL.Path == "/api/v2/tailnet/-/devices" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if engine.poll(ctx, client, settings, []string{"device_details"}, true) {
		t.Fatal("empty partial collector response was reported as successful")
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, collector := range status.Collectors {
		if collector.Name == "device_details" {
			if collector.Baseline || collector.Partial {
				t.Fatalf("empty partial response changed collector state: %#v", collector)
			}
			if collector.FailureCount != 1 || collector.LastError == "" {
				t.Fatalf("empty partial response was not recorded as a failure: %#v", collector)
			}
			if collector.PartialErrorCount != 0 {
				t.Fatalf("empty partial response retained an error count: %#v", collector)
			}
			return
		}
	}
	t.Fatal("device_details collector state was not created")
}

func TestPollPersistsUsablePartialErrorCount(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch {
		case r.URL.Path == "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"healthy","hostname":"healthy"},{"id":"broken","hostname":"broken"}]}`))
		case strings.HasPrefix(r.URL.Path, "/api/v2/device/healthy/"):
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v2/device/broken/"):
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("detail provider failure"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if engine.poll(ctx, client, settings, []string{"device_details"}, true) {
		t.Fatal("usable partial collector response was reported as successful")
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, collector := range status.Collectors {
		if collector.Name == "device_details" {
			if !collector.Partial || collector.PartialErrorCount != 1 || collector.FailureCount != 1 {
				t.Fatalf("partial collector state=%#v", collector)
			}
			if collector.LastError == "" || strings.Contains(collector.LastError, "detail provider failure") {
				t.Fatalf("partial collector error was not sanitized: %q", collector.LastError)
			}
			return
		}
	}
	t.Fatal("device_details collector state was not created")
}

func TestCollectorDueErrorsAreCounted(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	if _, err := db.ExecContext(ctx, "INSERT INTO collector_state(generation,collector,next_poll) VALUES(?,?,?) ON CONFLICT(generation,collector) DO UPDATE SET next_poll=excluded.next_poll", settings.Generation, "devices", "not-a-timestamp"); err != nil {
		t.Fatal(err)
	}
	api := monitorTestAPI(t, nil)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.poll(ctx, client, settings, []string{"devices"}, false) {
		t.Fatal("poll with a malformed schedule should still complete the collector")
	}
	if got := engine.CollectorDueErrors(); got != 1 {
		t.Fatalf("collector due errors=%d, want 1", got)
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

func TestDurableTriggersHaveIndependentCollectorOutcomes(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("user provider unavailable"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	devices, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), nil, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record device trigger: %#v created=%v err=%v", devices, created, err)
	}
	users, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, []string{"users"})
	if err != nil || !created {
		t.Fatalf("record user trigger: %#v created=%v err=%v", users, created, err)
	}
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.processDurableTriggers(ctx, client, settings) {
		t.Fatal("durable trigger groups were not processed")
	}
	deviceState, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), nil, nil)
	if err != nil || deviceState.Status != "processed" {
		t.Fatalf("successful device trigger state=%#v err=%v", deviceState, err)
	}
	userState, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, nil)
	if err != nil || userState.Status != "pending" || userState.Attempts != 1 {
		t.Fatalf("failed user trigger state=%#v err=%v", userState, err)
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

type monitorOutcomeSender struct {
	calls chan struct{}
	err   error
}

func (s *monitorOutcomeSender) Send(context.Context, string, string) error {
	select {
	case s.calls <- struct{}{}:
	default:
	}
	return s.err
}

func (s *monitorOutcomeSender) Test(context.Context, string) error { return nil }

func TestMonitorDeliveryAndCleanupErrorBranches(t *testing.T) {
	ctx := context.Background()
	setDeliveryInterval := func(t *testing.T, interval time.Duration) {
		t.Helper()
		previous := deliveryPollInterval
		deliveryPollInterval = interval
		t.Cleanup(func() { deliveryPollInterval = previous })
	}

	t.Run("delivered update error", func(t *testing.T) {
		st, _, db := monitorTestStoreWithDB(t)
		if err := st.EnqueueSystem(ctx, "delivery complete"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fail_delivered_update BEFORE UPDATE OF status ON outbox WHEN NEW.status='delivered' BEGIN SELECT RAISE(ABORT,'delivered update failed'); END`); err != nil {
			t.Fatal(err)
		}
		setDeliveryInterval(t, time.Millisecond)
		sender := &monitorOutcomeSender{calls: make(chan struct{}, 1)}
		engine := New(st, "", "", "test", sender)
		deliveryCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			engine.delivery(deliveryCtx)
			close(done)
		}()
		select {
		case <-sender.calls:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("delivery did not attempt the successful notification")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("delivery did not stop after cancellation")
		}
	})

	t.Run("dead letter logging", func(t *testing.T) {
		st, _, db := monitorTestStoreWithDB(t)
		if err := st.EnqueueSystem(ctx, "delivery dead letter"); err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
		if _, err := db.ExecContext(ctx, "UPDATE outbox SET first_attempt=?", old); err != nil {
			t.Fatal(err)
		}
		setDeliveryInterval(t, time.Millisecond)
		sender := &monitorOutcomeSender{calls: make(chan struct{}, 1), err: errors.New("permanent failure")}
		engine := New(st, "", "", "test", sender)
		deliveryCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			engine.delivery(deliveryCtx)
			close(done)
		}()
		select {
		case <-sender.calls:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("delivery did not attempt the dead-letter notification")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("delivery did not stop after cancellation")
		}
	})

	t.Run("cleanup error", func(t *testing.T) {
		st, _, db := monitorTestStoreWithDB(t)
		if _, err := db.ExecContext(ctx, "DROP TABLE sessions"); err != nil {
			t.Fatal(err)
		}
		previous := cleanupPollInterval
		cleanupPollInterval = time.Millisecond
		t.Cleanup(func() { cleanupPollInterval = previous })
		engine := New(st, "", "", "test", &scriptedSender{})
		cleanupCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			engine.cleanup(cleanupCtx)
			close(done)
		}()
		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup did not stop after cancellation")
		}
	})

	t.Run("durable completion and retry errors", func(t *testing.T) {
		st, _, db := monitorTestStoreWithDB(t)
		if _, err := db.ExecContext(ctx, "DROP TABLE webhook_triggers"); err != nil {
			t.Fatal(err)
		}
		engine := New(st, "", "", "test", &scriptedSender{})
		engine.finishTriggers(ctx, []int64{1}, true, 1)
		engine.finishTriggers(ctx, []int64{1}, false, 2)
	})
}

func TestMonitorHealthNotificationWriteErrors(t *testing.T) {
	ctx := context.Background()
	status := &atomic.Int32{}
	status.Store(http.StatusInternalServerError)
	api := monitorTestAPI(t, status)
	defer api.Close()
	clientFor := func(t *testing.T) (*store.Store, store.Settings, *tailscale.Client, *Engine, *sql.DB) {
		t.Helper()
		st, settings, db := monitorTestStoreWithDB(t)
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		return st, settings, client, New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{}), db
	}

	t.Run("unhealthy notification enqueue", func(t *testing.T) {
		_, settings, client, engine, db := clientFor(t)
		for i := 0; i < 2; i++ {
			if engine.poll(ctx, client, settings, []string{"devices"}, true) {
				t.Fatal("failed collector poll unexpectedly succeeded")
			}
		}
		if _, err := db.ExecContext(ctx, "DROP TABLE outbox"); err != nil {
			t.Fatal(err)
		}
		if engine.poll(ctx, client, settings, []string{"devices"}, true) {
			t.Fatal("failed collector poll unexpectedly succeeded")
		}
	})

	t.Run("recovery notification enqueue", func(t *testing.T) {
		_, settings, client, engine, db := clientFor(t)
		for i := 0; i < 3; i++ {
			if engine.poll(ctx, client, settings, []string{"devices"}, true) {
				t.Fatal("failed collector poll unexpectedly succeeded")
			}
		}
		if _, err := db.ExecContext(ctx, "DROP TABLE outbox"); err != nil {
			t.Fatal(err)
		}
		status.Store(http.StatusOK)
		if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
			t.Fatal("recovery poll failed")
		}
	})
}

func TestSchedulerTimerBranches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	st, _, db := monitorTestStoreWithDB(t)
	if _, err := db.ExecContext(ctx, "UPDATE settings SET device_interval_seconds=1,inventory_interval_seconds=1"); err != nil {
		t.Fatal(err)
	}
	api := monitorTestAPI(t, nil)
	defer api.Close()
	previous := durableTriggerPollInterval
	durableTriggerPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { durableTriggerPollInterval = previous })
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		cancel()
		t.Fatal("scheduler timer branch test did not stop")
	}
}

func TestMonitorSchedulerWaitTimerAndDurableRetryAttempts(t *testing.T) {
	ctx := context.Background()
	t.Run("configuration wait timer", func(t *testing.T) {
		box, err := secret.NewBox(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(t.TempDir()+"/tailstate.db", box)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		previous := schedulerWaitInterval
		schedulerWaitInterval = time.Millisecond
		t.Cleanup(func() { schedulerWaitInterval = previous })
		engine := New(st, "", "", "test", &scriptedSender{})
		waitCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() {
			engine.scheduler(waitCtx)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("scheduler did not stop while waiting for configuration")
		}
	})

	t.Run("configuration wake", func(t *testing.T) {
		box, err := secret.NewBox(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(t.TempDir()+"/tailstate.db", box)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		engine := New(st, "", "", "test", &scriptedSender{})
		waitCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() {
			engine.scheduler(waitCtx)
			close(done)
		}()
		time.Sleep(5 * time.Millisecond)
		engine.Wake()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("scheduler did not stop after wake")
		}
	})

	t.Run("durable retry attempts", func(t *testing.T) {
		status := &atomic.Int32{}
		status.Store(http.StatusInternalServerError)
		api := monitorTestAPI(t, status)
		defer api.Close()
		st, settings := monitorTestStore(t)
		trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("9", 64), nil, []string{"devices"})
		if err != nil || !created {
			t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
		}
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
		if !engine.processDurableTriggers(ctx, client, settings) {
			t.Fatal("durable retry trigger was not processed")
		}
		if err := st.RetryWebhookTriggers(ctx, []int64{trigger.ID}, time.Now().Add(-time.Minute), "previous failure"); err != nil {
			t.Fatal(err)
		}
		if !engine.processDurableTriggers(ctx, client, settings) {
			t.Fatal("durable retry trigger was not processed a second time")
		}
	})

	t.Run("empty finish ids", func(t *testing.T) {
		engine := New(nil, "", "", "test", &scriptedSender{})
		engine.finishTriggers(ctx, nil, true, 1)
	})
}

func TestMonitorSchedulerRequestAndPollChangeBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("in-memory request", func(t *testing.T) {
		st, _ := monitorTestStore(t)
		api := monitorTestAPI(t, nil)
		defer api.Close()
		previous := durableTriggerPollInterval
		durableTriggerPollInterval = time.Second
		t.Cleanup(func() { durableTriggerPollInterval = previous })
		engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
		schedulerCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			engine.scheduler(schedulerCtx)
			close(done)
		}()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			status, err := st.Status(ctx)
			if err == nil && status.BaselineAt != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		engine.Trigger(ReconcileRequest{Collectors: []string{"users"}})
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("scheduler did not stop after request")
		}
	})

	t.Run("inventory change log", func(t *testing.T) {
		st, settings := monitorTestStore(t)
		var calls atomic.Int32
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
				return
			}
			if r.URL.Path == "/api/v2/tailnet/-/devices" {
				name := "server"
				if calls.Add(1) > 1 {
					name = "server-new"
				}
				_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"` + name + `"}]}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer api.Close()
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
		if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
			t.Fatal("baseline poll failed")
		}
		if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
			t.Fatal("changed poll failed")
		}
	})

	t.Run("collector failure store error", func(t *testing.T) {
		st, settings, db := monitorTestStoreWithDB(t)
		status := &atomic.Int32{}
		status.Store(http.StatusInternalServerError)
		api := monitorTestAPI(t, status)
		defer api.Close()
		if _, err := db.ExecContext(ctx, "DROP TABLE collector_state"); err != nil {
			t.Fatal(err)
		}
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
		if engine.poll(ctx, client, settings, []string{"devices"}, true) {
			t.Fatal("collector failure with store error unexpectedly succeeded")
		}
	})
}

func int64Strings(values []int64) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strconv.FormatInt(value, 10)
	}
	return out
}

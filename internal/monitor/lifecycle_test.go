package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

func TestSchedulerInitialPollAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, _ := monitorTestStore(t)
	api := monitorTestAPI(t, nil)
	defer api.Close()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	clientReady := make(chan struct{})
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, err := st.Status(context.Background())
		if err == nil && status.BaselineAt != nil {
			close(clientReady)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-clientReady:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not complete its initial poll")
	}
	engine.Wake()
	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
}

func TestSchedulerDrainsOverflowRequestsAfterInitialPoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, _ := monitorTestStore(t)
	api := monitorTestAPI(t, nil)
	defer api.Close()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, err := st.Status(context.Background())
		if err == nil && status.BaselineAt != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, err := st.Status(context.Background())
	if err != nil || status.BaselineAt == nil {
		t.Fatalf("scheduler did not complete its initial poll: status=%#v err=%v", status, err)
	}
	engine.triggerOverflowMu.Lock()
	engine.triggerOverflow = append(engine.triggerOverflow, ReconcileRequest{})
	engine.triggerOverflowMu.Unlock()
	engine.Wake()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after overflow request")
	}
}

func TestSchedulerWaitsForConfigurationAndWake(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir()+"/tailstate.db", box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine := New(st, "", "", "test", &scriptedSender{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	engine.Wake()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unconfigured scheduler did not stop")
	}
}

func TestSchedulerSettingsCacheRefreshesNonIdentityChanges(t *testing.T) {
	ctx := context.Background()
	st, initial := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})

	cached, revision, err := engine.schedulerSettings(ctx, nil, store.Settings{}, "")
	if err != nil || cached.OAuthClientSecret != initial.OAuthClientSecret || revision == "" {
		t.Fatalf("initial scheduler settings=%#v revision=%q err=%v", cached, revision, err)
	}
	client := tailscale.New("http://invalid.example", "http://invalid.example/token", "test", tailscale.Credentials{})
	unchanged, unchangedRevision, err := engine.schedulerSettings(ctx, client, cached, revision)
	if err != nil || unchangedRevision != revision || unchanged.OAuthClientSecret != cached.OAuthClientSecret {
		t.Fatalf("unchanged scheduler settings were not reused: %#v revision=%q err=%v", unchanged, unchangedRevision, err)
	}

	rotated := initial
	rotated.OAuthClientSecret = "rotated-secret"
	if generation, err := st.SaveSettings(ctx, rotated); err != nil || generation != initial.Generation {
		t.Fatalf("non-identity settings update generation=%d err=%v", generation, err)
	}
	refreshed, refreshedRevision, err := engine.schedulerSettings(ctx, client, cached, revision)
	if err != nil || refreshedRevision == revision || refreshed.OAuthClientSecret != "rotated-secret" {
		t.Fatalf("changed scheduler settings were not refreshed: %#v revision=%q err=%v", refreshed, refreshedRevision, err)
	}
	emptyStore, err := store.Open(t.TempDir()+"/empty.db", mustTestBox(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := engineWithStore(emptyStore).schedulerSettings(ctx, nil, store.Settings{}, ""); err == nil {
		t.Fatal("unconfigured scheduler settings lookup unexpectedly succeeded")
	}
	_ = emptyStore.Close()

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.schedulerSettings(ctx, client, refreshed, refreshedRevision); err == nil {
		t.Fatal("scheduler settings lookup succeeded after store close")
	}
}

func TestSchedulerIdentityRefreshKeepsNonIdentitySettingsOnSameClient(t *testing.T) {
	client := tailscale.New("http://invalid.example", "http://invalid.example/token", "test", tailscale.Credentials{})
	if schedulerIdentityChanged(client, 7, 7) {
		t.Fatal("credential or interval refresh incorrectly reset the monitor identity")
	}
	if !schedulerIdentityChanged(client, 7, 8) {
		t.Fatal("tailnet or OAuth identity change did not reset the monitor identity")
	}
	if !schedulerIdentityChanged(nil, 0, 0) {
		t.Fatal("initial scheduler configuration did not create a monitor identity")
	}
}

func TestNextPollDelayRetriesWithRetryIntervalAfterFailure(t *testing.T) {
	delay := nextPollDelay(time.Hour, false)
	if delay < collectorRetryInterval || delay >= collectorRetryInterval+collectorRetryInterval/10+time.Second {
		t.Fatalf("failed poll delay=%s is outside retry interval jitter", delay)
	}
	if successful := nextPollDelay(time.Second, true); successful < time.Second || successful >= time.Second+time.Second/10+time.Second {
		t.Fatalf("successful poll delay=%s is outside base interval jitter", successful)
	}
}

func TestPollTimerDelayHonorsEarlierCollectorDeadline(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	deadline := time.Now().UTC().Add(5 * time.Minute)
	if err := st.SetNextPollErr(ctx, settings.Generation, []string{"device_details"}, deadline); err != nil {
		t.Fatal(err)
	}
	engine := New(st, "", "", "test", &scriptedSender{})
	delay := engine.pollTimerDelay(ctx, settings.Generation, []string{"device_details"}, 12*time.Hour, true)
	if delay <= 0 || delay > 5*time.Minute {
		t.Fatalf("scheduler ignored earlier collector deadline: %s", delay)
	}
}

func TestPollTimerDelayHandlesMissingCollectors(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})
	if delay := engine.pollTimerDelay(ctx, settings.Generation, []string{"missing"}, time.Hour, true); delay < time.Hour || delay >= time.Hour+time.Hour/10+time.Second {
		t.Fatalf("missing collector timer delay=%s", delay)
	}
}

func TestPollTimerDelayFallsBackWhenStoreUnavailable(t *testing.T) {
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	delay := engine.pollTimerDelay(context.Background(), settings.Generation, []string{"devices"}, time.Hour, true)
	if delay < time.Hour || delay >= time.Hour+time.Hour/10+time.Second {
		t.Fatalf("unavailable store timer delay=%s", delay)
	}
}

func mustTestBox(t *testing.T) *secret.Box {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func engineWithStore(st *store.Store) *Engine {
	return New(st, "", "", "test", &scriptedSender{})
}

func TestRunAndCleanupCancellation(t *testing.T) {
	st, _ := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})
	ctx, cancel := context.WithCancel(context.Background())
	engine.Run(ctx)
	cancel()
	// Give all three short-lived cancellation paths a scheduling opportunity;
	// none should make a database call after the context is canceled.
	time.Sleep(25 * time.Millisecond)
}

func TestEngineWaitAfterRun(t *testing.T) {
	st, _ := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})
	ctx, cancel := context.WithCancel(context.Background())
	engine.Run(ctx)
	cancel()
	engine.Wait()
}

func TestJitterBounds(t *testing.T) {
	if got := jitter(0); got != time.Minute {
		t.Fatalf("zero jitter=%s", got)
	}
	if got := jitter(-time.Second); got != time.Minute {
		t.Fatalf("negative jitter=%s", got)
	}
	base := 10 * time.Second
	for i := 0; i < 20; i++ {
		got := jitter(base)
		if got < base || got >= base+base/10 {
			t.Fatalf("positive jitter=%s outside [%s,%s)", got, base, base+base/10)
		}
	}
}

func TestPollSkipsCollectorsThatAreNotDue(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})
	if err := st.SetNextPollErr(ctx, settings.Generation, []string{"devices"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	client := tailscale.New("http://invalid.example", "http://invalid.example/token", "test", tailscale.Credentials{})
	if !engine.poll(ctx, client, settings, []string{"devices"}, false) {
		t.Fatal("poll with no due collectors returned false")
	}
}

func TestPollRejectsResultsFromStaleGeneration(t *testing.T) {
	ctx := context.Background()
	st, oldSettings := monitorTestStore(t)
	api := monitorTestAPI(t, nil)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	newSettings := oldSettings
	newSettings.OAuthClientID = "rotated-client"
	if generation, err := st.SaveSettings(ctx, newSettings); err != nil || generation == oldSettings.Generation {
		t.Fatalf("rotate settings generation=%d err=%v", generation, err)
	}
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if engine.poll(ctx, client, oldSettings, []string{"devices"}, true, 42) {
		t.Fatal("stale generation poll unexpectedly succeeded")
	}
}

func TestProcessDurableBroadTriggerAndFailureHelpers(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	api := monitorTestAPI(t, nil)
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), []string{"policyUpdate"}, nil)
	if err != nil || !created {
		t.Fatalf("record broad trigger: %#v created=%v err=%v", trigger, created, err)
	}
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.processDurableTriggers(ctx, client, settings) {
		t.Fatal("broad durable trigger was not processed")
	}
	processed, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), nil, nil)
	if err != nil || processed.Status != "processed" {
		t.Fatalf("broad trigger state=%#v err=%v", processed, err)
	}

	retry, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record retry trigger: %#v created=%v err=%v", retry, created, err)
	}
	claim, claimed, err := st.ClaimWebhookTrigger(ctx, retry.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim retry trigger: claimed=%v err=%v", claimed, err)
	}
	engine.finishClaimedTriggers(ctx, []store.WebhookTrigger{claim, claim}, false, 0)
	requeued, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, nil)
	if err != nil || requeued.Status != "pending" || requeued.LastError == "" {
		t.Fatalf("retry trigger state=%#v err=%v", requeued, err)
	}

	if engine.processDurableTriggers(ctx, nil, settings) {
		t.Fatal("empty durable trigger queue reported work")
	}
}

func TestProcessDurableTriggersReportsStoreFailure(t *testing.T) {
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test", &scriptedSender{})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if engine.processDurableTriggers(context.Background(), nil, settings) {
		t.Fatal("closed store reported durable trigger work")
	}
}

func TestDeliveryHandlesStoreFailure(t *testing.T) {
	st, _ := monitorTestStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	engine := New(st, "", "", "test", &scriptedSender{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		engine.delivery(ctx)
		close(done)
	}()
	select {
	case <-time.After(2100 * time.Millisecond):
	case <-done:
		t.Fatal("delivery stopped before checking the store")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delivery did not stop after cancellation")
	}
}

type retryAfterSender struct{ calls chan struct{} }

func (s *retryAfterSender) Send(context.Context, string, string) error {
	select {
	case s.calls <- struct{}{}:
	default:
	}
	return &notify.DeliveryError{Message: "rate limited", RetryAfter: time.Millisecond}
}

func (s *retryAfterSender) Test(context.Context, string) error { return nil }

func TestDeliveryHonorsRetryAfterHint(t *testing.T) {
	ctx := context.Background()
	st, _ := monitorTestStore(t)
	if err := st.EnqueueSystem(ctx, "delivery retry"); err != nil {
		t.Fatal(err)
	}
	sender := &retryAfterSender{calls: make(chan struct{}, 1)}
	engine := New(st, "", "", "test", sender)
	deliveryCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		engine.delivery(deliveryCtx)
		close(done)
	}()
	select {
	case <-sender.calls:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("delivery did not attempt the retryable notification")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delivery did not stop after cancellation")
	}
}

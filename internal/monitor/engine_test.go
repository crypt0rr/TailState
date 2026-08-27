package monitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

type scriptedSender struct {
	mu    sync.Mutex
	calls []string
}

type leakingSender struct{}

func (leakingSender) Send(_ context.Context, serviceURL, _ string) error {
	return fmt.Errorf("provider rejected %s", serviceURL)
}

func (leakingSender) Test(context.Context, string) error { return nil }

func (s *scriptedSender) Send(_ context.Context, serviceURL, _ string) error {
	s.mu.Lock()
	s.calls = append(s.calls, serviceURL)
	s.mu.Unlock()
	if strings.Contains(serviceURL, "backup") {
		return errors.New("backup destination unavailable")
	}
	return nil
}

func (s *scriptedSender) Test(context.Context, string) error { return nil }

func (s *scriptedSender) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func TestDeliveryKeepsDestinationFailuresIndependent(t *testing.T) {
	ctx := context.Background()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir()+"/tailstate.db", box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	settings := store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}
	generation, err := st.SaveSettings(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Backup", ServiceURL: "generic://backup.example/path", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}}}}}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, baseline, notify.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, changed, notify.Digest); err != nil {
		t.Fatal(err)
	}
	sender := &scriptedSender{}
	engine := New(st, "", "", "test", sender)
	deliveryCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.delivery(deliveryCtx)

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		page, historyErr := st.ListHistory(ctx, store.HistoryFilter{Limit: 10})
		if historyErr != nil {
			t.Fatal(historyErr)
		}
		if len(page.Batches) == 1 && len(page.Batches[0].Deliveries) == 2 {
			statuses := map[string]string{}
			for _, delivery := range page.Batches[0].Deliveries {
				statuses[delivery.Destination] = delivery.Status
			}
			if statuses["Mattermost"] == "delivered" && statuses["Backup"] == "pending" {
				if sender.callCount() < 2 {
					t.Fatal("delivery loop did not attempt both destinations")
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("destinations did not settle independently; sender calls=%d", sender.callCount())
}

type slowCountingSender struct {
	mu      sync.Mutex
	calls   map[string]int
	delay   time.Duration
	started chan struct{}
	once    sync.Once
}

func (s *slowCountingSender) Send(_ context.Context, serviceURL, _ string) error {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[serviceURL]++
	s.mu.Unlock()
	s.once.Do(func() { close(s.started) })
	time.Sleep(s.delay)
	return nil
}

func (s *slowCountingSender) Test(context.Context, string) error { return nil }

func (s *slowCountingSender) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, count := range s.calls {
		total += count
	}
	return total
}

func TestDeliveryRenewsLeasesForSlowBatch(t *testing.T) {
	ctx := context.Background()
	st, _, _ := openMonitorTestStore(t)
	for i := 1; i < deliveryBatchSize; i++ {
		if _, err := st.SaveDestination(ctx, store.NotificationDestination{
			Name:       fmt.Sprintf("Slow %d", i),
			ServiceURL: fmt.Sprintf("generic://slow-%d.example/path", i),
			Enabled:    true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EnqueueSystem(ctx, "slow delivery batch"); err != nil {
		t.Fatal(err)
	}
	previousInterval := deliveryPollInterval
	deliveryPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { deliveryPollInterval = previousInterval })
	sender := &slowCountingSender{delay: 300 * time.Millisecond, started: make(chan struct{})}
	first := New(st, "", "", "test", sender)
	second := New(st, "", "", "test", sender)
	first.deliveryLease = 2 * time.Second
	second.deliveryLease = 2 * time.Second
	deliveryCtx, cancel := context.WithCancel(ctx)
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		first.delivery(deliveryCtx)
		close(firstDone)
	}()
	go func() {
		second.delivery(deliveryCtx)
		close(secondDone)
	}()
	select {
	case <-sender.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("slow delivery did not start")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := st.Status(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if status.Pending == 0 && status.Processing == 0 && status.Dead == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("primary delivery worker did not stop")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("secondary delivery worker did not stop")
	}
	if calls := sender.callCount(); calls != deliveryBatchSize {
		t.Fatalf("slow batch was delivered %d times, want exactly %d", calls, deliveryBatchSize)
	}
	firstMetrics := first.DeliveryMetrics()
	secondMetrics := second.DeliveryMetrics()
	if attempts := firstMetrics.Attempts + secondMetrics.Attempts; attempts != deliveryBatchSize {
		t.Fatalf("delivery metrics attempts=%d (first=%+v second=%+v), want %d", attempts, firstMetrics, secondMetrics, deliveryBatchSize)
	}
	if successes := firstMetrics.Successes + secondMetrics.Successes; successes != deliveryBatchSize {
		t.Fatalf("delivery metrics successes=%d (first=%+v second=%+v), want %d", successes, firstMetrics, secondMetrics, deliveryBatchSize)
	}
	if renewals := firstMetrics.LeaseRenewals + secondMetrics.LeaseRenewals; renewals == 0 {
		t.Fatalf("slow batch did not renew any leases: first=%+v second=%+v", firstMetrics, secondMetrics)
	}
	if losses := firstMetrics.LeaseLosses + secondMetrics.LeaseLosses; losses != 0 {
		t.Fatalf("slow batch lost a lease: first=%+v second=%+v", firstMetrics, secondMetrics)
	}
}

func TestDeliveryMetricsRecordDurationBuckets(t *testing.T) {
	engine := &Engine{}
	for _, elapsed := range []time.Duration{
		-1,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
		15 * time.Second,
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		300 * time.Second,
		301 * time.Second,
	} {
		engine.recordDeliveryDuration(elapsed)
	}

	metrics := engine.DeliveryMetrics()
	if metrics.DurationCount != 12 {
		t.Fatalf("duration count=%d, want 12", metrics.DurationCount)
	}
	if metrics.DurationSeconds <= 0 {
		t.Fatalf("duration sum was not recorded: %+v", metrics)
	}
	wantBuckets := [deliveryDurationBucketCount]uint64{3, 4, 5, 6, 7, 8, 9, 10, 11}
	if metrics.DurationBuckets != wantBuckets {
		t.Fatalf("duration buckets=%v, want %v", metrics.DurationBuckets, wantBuckets)
	}
	bounds := DeliveryDurationBucketBounds()
	if bounds[0] != 0.1 || bounds[len(bounds)-1] != 300 {
		t.Fatalf("unexpected duration bucket bounds: %v", bounds)
	}
}

func TestDeliveryLeaseRenewalRecordsLeaseLoss(t *testing.T) {
	ctx := context.Background()
	st, _, _ := openMonitorTestStore(t)
	if err := st.EnqueueSystem(ctx, "lease loss"); err != nil {
		t.Fatal(err)
	}
	items, err := st.ClaimDueOutbox(ctx, 1, time.Minute)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim outbox item: %#v err=%v", items, err)
	}
	item := items[0]
	if err := st.DeliveredClaimed(ctx, item); err != nil {
		t.Fatal(err)
	}
	leaseUntil := time.Now().UTC().Add(time.Second)
	item.LeaseUntil = &leaseUntil
	engine := New(st, "", "", "test", &scriptedSender{})
	state := &deliveryLeaseState{}
	done := make(chan struct{})
	go engine.renewOutboxLease(ctx, item, state, done)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lease renewer did not stop after losing its claim")
	}
	if !state.lost.Load() {
		t.Fatal("lease loss was not recorded in the claim state")
	}
	if metrics := engine.DeliveryMetrics(); metrics.LeaseLosses != 1 {
		t.Fatalf("lease loss metrics=%+v, want one loss", metrics)
	}
}

func TestDeliveryLeaseRenewalErrorsAreCounted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st, _, _ := openMonitorTestStore(t)
	if err := st.EnqueueSystem(context.Background(), "lease renewal error"); err != nil {
		t.Fatal(err)
	}
	items, err := st.ClaimDueOutbox(context.Background(), 1, time.Minute)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim outbox item: %#v err=%v", items, err)
	}
	item := items[0]
	leaseUntil := time.Now().UTC().Add(time.Second)
	item.LeaseUntil = &leaseUntil
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	engine := New(st, "", "", "test", &scriptedSender{})
	done := make(chan struct{})
	go engine.renewOutboxLease(ctx, item, &deliveryLeaseState{}, done)
	deadline := time.After(2 * time.Second)
	for engine.DeliveryMetrics().LeaseRenewalFailures == 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("lease renewal error was not observed")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lease renewer did not stop after cancellation")
	}
}

func TestDeliveryRedactsInjectedSenderErrors(t *testing.T) {
	ctx := context.Background()
	st, _, db := monitorTestStoreWithDB(t)
	if err := st.EnqueueSystem(ctx, "delivery redaction"); err != nil {
		t.Fatal(err)
	}
	previous := deliveryPollInterval
	deliveryPollInterval = time.Millisecond
	t.Cleanup(func() { deliveryPollInterval = previous })
	engine := New(st, "", "", "test", leakingSender{})
	deliveryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		engine.delivery(deliveryCtx)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	var lastError string
	for time.Now().Before(deadline) {
		if err := db.QueryRowContext(ctx, "SELECT last_error FROM outbox ORDER BY id LIMIT 1").Scan(&lastError); err == nil && lastError != "" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delivery worker did not stop")
	}
	if lastError == "" {
		t.Fatal("delivery error was not persisted")
	}
	if strings.Contains(lastError, "mattermost://TailState@mattermost.example/token") || strings.Contains(lastError, "mattermost.example") || strings.Contains(lastError, "/token") {
		t.Fatalf("injected sender URL reached persisted error: %q", lastError)
	}
}

type cancellationAwareSender struct {
	started chan struct{}
	once    sync.Once
}

func (s *cancellationAwareSender) Send(ctx context.Context, _, _ string) error {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return nil
}

func (s *cancellationAwareSender) Test(context.Context, string) error { return nil }

func TestRestartMidDeliveryRecordsOutcome(t *testing.T) {
	ctx := context.Background()
	st, _, path := openMonitorTestStore(t)
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "delivery before restart"); err != nil {
		t.Fatal(err)
	}
	previous := deliveryPollInterval
	deliveryPollInterval = time.Millisecond
	t.Cleanup(func() { deliveryPollInterval = previous })
	sender := &cancellationAwareSender{started: make(chan struct{})}
	engine := New(st, "", "", "test", sender)
	deliveryCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		engine.delivery(deliveryCtx)
		close(done)
	}()
	select {
	case <-sender.started:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("delivery did not start before restart")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delivery worker did not stop after restart")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path, box)
	if err != nil {
		t.Fatalf("reopen after delivery shutdown: %v", err)
	}
	defer reopened.Close()
	status, err := reopened.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Pending != 0 {
		t.Fatalf("delivered notification remained pending after restart: %#v", status)
	}
	if status.Processing != 0 || status.Dead != 0 {
		t.Fatalf("outbox outcome after restart was not delivered: %#v", status)
	}
}

func TestFinishTriggersOutlivesShutdownCancellation(t *testing.T) {
	ctx := context.Background()
	st, _ := monitorTestStore(t)
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), []string{"nodeCreated"}, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	claim, claimed, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim trigger: claimed=%v err=%v", claimed, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	New(st, "", "", "test", &scriptedSender{}).finishClaimedTriggers(canceled, []store.WebhookTrigger{claim}, true, 1)
	updated, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), nil, nil)
	if err != nil || updated.Status != "processed" {
		t.Fatalf("canceled shutdown left trigger unfinished: %#v err=%v", updated, err)
	}
}

func TestFastTriggerClaimOnlyOwnsPendingDurableRows(t *testing.T) {
	ctx := context.Background()
	st, _ := monitorTestStore(t)
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("e", 64), nil, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	engine := New(st, "", "", "test", &scriptedSender{})
	claims := engine.claimFastTriggerClaims(ctx, []int64{trigger.ID, trigger.ID, 0, -1, 99999})
	if len(claims) != 1 || claims[0].ID != trigger.ID {
		t.Fatalf("claimed fast trigger claims=%v, want trigger %d", claims, trigger.ID)
	}
	if second := engine.claimFastTriggerClaims(ctx, []int64{trigger.ID}); len(second) != 0 {
		t.Fatalf("processing trigger was claimed a second time: %v", second)
	}
	if err := st.CompleteClaimedWebhookTriggers(ctx, claims); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if claims = engine.claimFastTriggerClaims(ctx, []int64{trigger.ID}); len(claims) != 0 {
		t.Fatalf("closed-store fast claim returned claims: %v", claims)
	}
}

func TestRetryDelayIsBounded(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		delay := retryDelay(attempt)
		if delay < 5*time.Second || delay > time.Hour+time.Hour/5 {
			t.Fatalf("retry delay out of bounds at attempt %d: %s", attempt, delay)
		}
	}
}

func TestTriggerQueuesTargetedCollectorsAndRetainsOverflowScopes(t *testing.T) {
	engine := New(nil, "", "", "test", &scriptedSender{})
	engine.Trigger(ReconcileRequest{TriggerID: 7, Collectors: []string{"policy", "devices", "policy"}})
	request := <-engine.trigger
	if request.TriggerID != 7 || len(request.Collectors) != 2 || request.Collectors[0] != "devices" || request.Collectors[1] != "policy" {
		t.Fatalf("unexpected targeted trigger: %#v", request)
	}
	for i := 0; i < cap(engine.trigger)+1; i++ {
		collector := "policy"
		if i%2 == 0 {
			collector = "devices"
		}
		engine.Trigger(ReconcileRequest{TriggerID: int64(i + 1), Collectors: []string{collector}})
	}
	overflow := engine.takeTriggerOverflow()
	if len(overflow) != 1 || overflow[0].TriggerID != int64(cap(engine.trigger)+1) {
		t.Fatalf("overflow requests = %#v, want the final request preserved", overflow)
	}
	if len(overflow[0].Collectors) != 1 || overflow[0].Collectors[0] != "devices" {
		t.Fatalf("overflow collector scope = %#v, want devices", overflow[0].Collectors)
	}
}

func TestFinishTriggersKeepsPendingWorkDurable(t *testing.T) {
	ctx := context.Background()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir()+"/tailstate.db", box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	claim, claimed, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim trigger: claimed=%v err=%v", claimed, err)
	}
	engine := New(st, "", "", "test", &scriptedSender{})
	engine.finishClaimedTriggers(ctx, []store.WebhookTrigger{claim}, false, 1)
	retried, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
	if err != nil || retried.Status != "pending" || retried.LastError == "" {
		t.Fatalf("failed trigger was not retained for retry: %#v err=%v", retried, err)
	}
}

func TestFinishTriggersCannotOverwriteRequeuedTrigger(t *testing.T) {
	ctx := context.Background()
	st, _ := monitorTestStore(t)
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("7", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	firstClaim, claimed, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim trigger: claimed=%v err=%v", claimed, err)
	}
	// Simulate lease recovery returning the row to the durable queue while the
	// original worker is still finishing its poll.
	if err := st.RetryClaimedWebhookTriggers(ctx, []store.WebhookTrigger{firstClaim}, time.Now().Add(-time.Second), "reconciliation retry window expired"); err != nil {
		t.Fatal(err)
	}
	secondClaim, claimed, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("reclaim trigger: claimed=%v err=%v", claimed, err)
	}
	if firstClaim.LeaseToken == "" || firstClaim.LeaseToken == secondClaim.LeaseToken {
		t.Fatalf("lease token was not rotated: first=%q second=%q", firstClaim.LeaseToken, secondClaim.LeaseToken)
	}
	engine := New(st, "", "", "test", &scriptedSender{})
	engine.finishClaimedTriggers(ctx, []store.WebhookTrigger{firstClaim}, true, 1)
	updated, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("7", 64), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "processing" || updated.LeaseToken != secondClaim.LeaseToken || updated.LastError != "reconciliation retry window expired" {
		t.Fatalf("late completion overwrote newer trigger attempt: %#v", updated)
	}

	engine.finishClaimedTriggers(ctx, []store.WebhookTrigger{firstClaim}, false, 1)
	updated, _, err = st.RecordWebhookTrigger(ctx, strings.Repeat("7", 64), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "processing" || updated.LeaseToken != secondClaim.LeaseToken || updated.LastError != "reconciliation retry window expired" {
		t.Fatalf("late retry overwrote newer trigger attempt: %#v", updated)
	}

	engine.finishClaimedTriggers(ctx, []store.WebhookTrigger{secondClaim}, true, 1)
	updated, _, err = st.RecordWebhookTrigger(ctx, strings.Repeat("7", 64), nil, nil)
	if err != nil || updated.Status != "processed" {
		t.Fatalf("current claim could not be completed: %#v err=%v", updated, err)
	}
}

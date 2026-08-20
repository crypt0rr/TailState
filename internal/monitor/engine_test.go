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
	st, _ := monitorTestStore(t)
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
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Pending != 0 {
		t.Fatalf("delivered notification remained pending after restart: %#v", status)
	}
}

func TestFinishTriggersOutlivesShutdownCancellation(t *testing.T) {
	ctx := context.Background()
	st, _ := monitorTestStore(t)
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), []string{"nodeCreated"}, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	New(st, "", "", "test", &scriptedSender{}).finishTriggers(canceled, []int64{trigger.ID}, true, 1)
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
	claimed := engine.claimFastTriggers(ctx, []int64{trigger.ID, trigger.ID, 0, -1, 99999})
	if len(claimed) != 1 || claimed[0] != trigger.ID {
		t.Fatalf("claimed fast trigger IDs=%v, want [%d]", claimed, trigger.ID)
	}
	if claimed = engine.claimFastTriggers(ctx, []int64{trigger.ID}); len(claimed) != 0 {
		t.Fatalf("processing trigger was claimed a second time: %v", claimed)
	}
	if err := st.CompleteWebhookTriggers(ctx, []int64{trigger.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if claimed = engine.claimFastTriggers(ctx, []int64{trigger.ID}); len(claimed) != 0 {
		t.Fatalf("closed-store fast claim returned IDs: %v", claimed)
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
	engine := New(st, "", "", "test", &scriptedSender{})
	engine.finishTriggers(ctx, []int64{trigger.ID}, false, 1)
	retried, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
	if err != nil || retried.Status != "pending" || retried.LastError == "" {
		t.Fatalf("failed trigger was not retained for retry: %#v err=%v", retried, err)
	}
	if err := st.CompleteWebhookTriggers(ctx, []int64{trigger.ID}); err != nil {
		t.Fatal(err)
	}
	completed, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
	if err != nil || completed.Status != "processed" {
		t.Fatalf("pending trigger could not be completed after retry: %#v err=%v", completed, err)
	}
}

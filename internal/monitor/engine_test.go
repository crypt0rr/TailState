package monitor

import (
	"context"
	"errors"
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
	if _, err := st.ApplyBatch(ctx, generation, baseline, notify.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, changed, notify.Digest); err != nil {
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

func TestRetryDelayIsBounded(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		delay := retryDelay(attempt)
		if delay < 5*time.Second || delay > time.Hour+time.Hour/5 {
			t.Fatalf("retry delay out of bounds at attempt %d: %s", attempt, delay)
		}
	}
}

func TestTriggerQueuesTargetedCollectorsAndCoalescesOverflow(t *testing.T) {
	engine := New(nil, "", "", "test", &scriptedSender{})
	engine.Trigger(ReconcileRequest{TriggerID: 7, Collectors: []string{"policy", "devices", "policy"}})
	request := <-engine.trigger
	if request.TriggerID != 7 || len(request.Collectors) != 2 || request.Collectors[0] != "devices" || request.Collectors[1] != "policy" {
		t.Fatalf("unexpected targeted trigger: %#v", request)
	}
	for i := 0; i < cap(engine.trigger)+1; i++ {
		engine.Trigger(ReconcileRequest{TriggerID: int64(i + 1), Collectors: []string{"policy"}})
	}
	seenBroad := false
	for {
		select {
		case request := <-engine.trigger:
			if request.TriggerID == 0 && len(request.Collectors) == 0 && len(request.TriggerIDs) == cap(engine.trigger)+1 {
				seenBroad = true
			}
		default:
			if !seenBroad {
				t.Fatal("overflow did not retain a broad reconciliation")
			}
			return
		}
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

package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

type oversizedSender struct{}

func (oversizedSender) Send(context.Context, string, string) error {
	return &notify.DeliveryError{Message: "telegram: Message exceeds the max length", Permanent: true}
}

func (oversizedSender) Test(context.Context, string) error { return nil }

// TestPermanentDeliveryFailureDeadLettersImmediately guards the regression
// where a payload the provider can never accept was retried for 24 hours.
func TestPermanentDeliveryFailureDeadLettersImmediately(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}}}}}
	for _, batch := range [][]model.Collected{baseline, changed} {
		if _, err := st.ApplyBatchWithBatch(ctx, settings.Generation, batch, notify.Digest); err != nil {
			t.Fatal(err)
		}
	}
	engine := New(st, "", "", "test", oversizedSender{})
	deliveryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go engine.delivery(deliveryCtx)

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		page, err := st.ListHistory(ctx, store.HistoryFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Batches) == 1 && len(page.Batches[0].Deliveries) == 1 {
			delivery := page.Batches[0].Deliveries[0]
			if delivery.Status == "dead" {
				if delivery.Attempts != 1 || delivery.LastError != "notification rejected by provider: message too large for this destination" {
					t.Fatalf("dead letter = %#v", delivery)
				}
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("permanent delivery failure was not dead-lettered after one attempt")
}

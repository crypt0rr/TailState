package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// deliverToProvider points the test store's only destination at a provider
// that answers with respond, queues one inventory change, and runs the
// production sender until the delivery reaches a state accepted by done.
func deliverToProvider(t *testing.T, respond http.HandlerFunc, done func(store.HistoryDelivery) bool) store.HistoryDelivery {
	t.Helper()
	ctx := context.Background()
	server := httptest.NewServer(respond)
	t.Cleanup(server.Close)
	st, settings := monitorTestStore(t)
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations = %v, %v", destinations, err)
	}
	destination := destinations[0]
	destination.ServiceURL = strings.Replace(server.URL, "http://", "generic://", 1) + "/hook?disabletls=true"
	if _, err := st.SaveDestination(ctx, destination); err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}}}}}
	for _, batch := range [][]model.Collected{baseline, changed} {
		if _, err := st.ApplyBatchWithBatch(ctx, settings.Generation, batch, notify.Context{}.Digest); err != nil {
			t.Fatal(err)
		}
	}
	engine := New(st, "", "", "test", notify.New())
	deliveryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go engine.delivery(deliveryCtx)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		page, err := st.ListHistory(ctx, store.HistoryFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Batches) == 1 && len(page.Batches[0].Deliveries) == 1 && done(page.Batches[0].Deliveries[0]) {
			return page.Batches[0].Deliveries[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("delivery did not reach the expected state")
	return store.HistoryDelivery{}
}

// TestProviderRejectionDeadLettersOnFirstAttempt guards the regression where
// a revoked webhook token (HTTP 401) was retried for 24 hours.
func TestProviderRejectionDeadLettersOnFirstAttempt(t *testing.T) {
	delivery := deliverToProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid token secret-value"))
	}, func(d store.HistoryDelivery) bool { return d.Status == "dead" })
	if delivery.Attempts != 1 || delivery.LastError != "notification rejected by provider (HTTP 401)" {
		t.Fatalf("dead letter = %#v", delivery)
	}
}

// TestProviderRetryAfterDelaysNextAttempt verifies that a 429 with
// Retry-After: 120 is not retried sooner than the provider asked.
func TestProviderRetryAfterDelaysNextAttempt(t *testing.T) {
	started := time.Now()
	delivery := deliverToProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}, func(d store.HistoryDelivery) bool {
		return d.Status == "pending" && d.Attempts == 1 && d.NextAttempt != nil
	})
	if delivery.LastError != "notification delivery failed with HTTP 429" {
		t.Fatalf("retry reason = %q", delivery.LastError)
	}
	if earliest := started.Add(120 * time.Second); delivery.NextAttempt.Before(earliest) {
		t.Fatalf("next attempt %s is earlier than Retry-After allows (%s)", delivery.NextAttempt, earliest)
	}
	if latest := time.Now().Add(121 * time.Second); delivery.NextAttempt.After(latest) {
		t.Fatalf("next attempt %s ignored the Retry-After hint", delivery.NextAttempt)
	}
}

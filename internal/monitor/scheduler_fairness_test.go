package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestSchedulerServesInventoryWhileTriggersStayDue keeps the durable trigger
// queue non-empty for the whole test: every device poll queues another full
// batch. Scheduled inventory polls must still run within a bounded time.
func TestSchedulerServesInventoryWhileTriggersStayDue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, _, db := monitorTestStoreWithDB(t)
	if _, err := db.ExecContext(ctx, "UPDATE settings SET device_interval_seconds=1,inventory_interval_seconds=1"); err != nil {
		t.Fatal(err)
	}
	var queued, inventoryPolls atomic.Int64
	enqueue := func() {
		hash := fmt.Sprintf("%064x", queued.Add(1))
		_, _, _ = st.RecordWebhookTrigger(context.Background(), hash, nil, []string{"devices"})
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			// One claim takes at most eight triggers, so queuing eight per device
			// poll keeps the durable backlog due indefinitely.
			for range 8 {
				enqueue()
			}
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			inventoryPolls.Add(1)
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v2/device/device-1/attributes", "/api/v2/device/device-1/device-invites":
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	enqueue()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	done := make(chan struct{})
	go func() {
		engine.scheduler(ctx)
		close(done)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("scheduler did not stop after cancellation")
		}
	}
	baselineDeadline := time.Now().Add(10 * time.Second)
	for {
		status, err := st.Status(ctx)
		if err == nil && status.BaselineAt != nil {
			break
		}
		if time.Now().After(baselineDeadline) {
			stop()
			t.Fatal("scheduler did not complete its initial poll")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The initial poll already fetched every inventory collector, so count only
	// the polls that the scheduled inventory timer makes afterwards.
	before := inventoryPolls.Load()
	deadline := time.Now().Add(8 * time.Second)
	for inventoryPolls.Load() == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	polled := inventoryPolls.Load() > before
	queuedTriggers := queued.Load()
	stop()
	if !polled {
		t.Fatalf("inventory collectors were not polled within 8s while %d durable triggers were queued", queuedTriggers)
	}
}

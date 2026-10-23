package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// Node events that arrive during one poll must share a single devices poll,
// not each run their own forced fan-out.
func TestBurstTriggersShareOneCollectorPoll(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	var devicesPolls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			devicesPolls.Add(1)
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	// Six device events arrive while the scheduler is busy: four fill the bounded
	// channel and the last two spill into the overflow queue.
	hashes := make([]string, 0, 6)
	for i := range 6 {
		hash := fmt.Sprintf("%064x", i+1)
		trigger, created, err := st.RecordWebhookTrigger(ctx, hash, nil, []string{"devices"})
		if err != nil || !created {
			t.Fatalf("record trigger %d: %#v created=%v err=%v", i, trigger, created, err)
		}
		hashes = append(hashes, hash)
		engine.Trigger(ReconcileRequest{TriggerID: trigger.ID, Collectors: []string{"devices"}})
	}
	if len(engine.trigger) != cap(engine.trigger) || len(engine.triggerOverflow) != 2 {
		t.Fatalf("channel=%d overflow=%d, want a full channel and two overflow requests", len(engine.trigger), len(engine.triggerOverflow))
	}

	if !engine.processFastTriggers(ctx, client, settings) {
		t.Fatal("queued trigger requests were not served")
	}
	if got := devicesPolls.Load(); got != 1 {
		t.Fatalf("devices endpoint was hit %d times, want one shared poll", got)
	}
	if len(engine.trigger) != 0 || len(engine.triggerOverflow) != 0 {
		t.Fatalf("queues were not drained: channel=%d overflow=%d", len(engine.trigger), len(engine.triggerOverflow))
	}
	for i, hash := range hashes {
		state, _, err := st.RecordWebhookTrigger(ctx, hash, nil, nil)
		if err != nil || state.Status != "processed" || state.Attempts != 1 {
			t.Fatalf("trigger %d state=%#v err=%v, want processed after one attempt", i, state, err)
		}
	}
}

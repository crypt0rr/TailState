package monitor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

const healthyDestinationURL = "generic://healthy.example/path"

// orderSender records delivered messages per destination. The primary
// destination (any URL other than healthyDestinationURL) can be taken down,
// failing fast with a per-message retry hint, or made to hang.
type orderSender struct {
	mu        sync.Mutex
	down      bool
	hang      time.Duration
	delivered map[string][]string
	attempts  map[string]int
	// retryAfter returns the retry hint for a failed message.
	retryAfter func(message string) time.Duration
}

func (s *orderSender) Send(_ context.Context, serviceURL, message string) error {
	primary := serviceURL != healthyDestinationURL
	s.mu.Lock()
	s.attempts[serviceURL]++
	down, hang := s.down && primary, s.hang
	s.mu.Unlock()
	if primary && hang > 0 {
		time.Sleep(hang)
		return &notify.DeliveryError{Message: "timed out"}
	}
	if down {
		return &notify.DeliveryError{Message: "unavailable", RetryAfter: s.retryAfter(message)}
	}
	s.mu.Lock()
	s.delivered[serviceURL] = append(s.delivered[serviceURL], strings.TrimSpace(message))
	s.mu.Unlock()
	return nil
}

func (s *orderSender) Test(context.Context, string) error { return nil }

func (s *orderSender) snapshot(primary bool) ([]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for url, messages := range s.delivered {
		if (url != healthyDestinationURL) == primary {
			return append([]string(nil), messages...), s.attempts[url]
		}
	}
	for url, attempts := range s.attempts {
		if (url != healthyDestinationURL) == primary {
			return nil, attempts
		}
	}
	return nil, 0
}

func startOrderedDelivery(t *testing.T, st *store.Store, sender notify.Sender) {
	t.Helper()
	previous := deliveryPollInterval
	deliveryPollInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	engine := New(st, "", "", "test", sender)
	go func() {
		engine.delivery(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		deliveryPollInterval = previous
	})
}

func waitForDelivered(t *testing.T, sender *orderSender, primary bool, count int, within time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		got, _ := sender.snapshot(primary)
		if len(got) >= count {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivered %v (primary=%t), want %d messages within %s", got, primary, count, within)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDeliveryAfterOutageKeepsCreationOrderPerDestination reproduces an
// outage in which the oldest notification backs off longer than younger ones.
// After recovery the destination must still receive them in creation order,
// while a healthy destination is served in order throughout.
func TestDeliveryAfterOutageKeepsCreationOrderPerDestination(t *testing.T) {
	ctx := context.Background()
	st, _, _ := openMonitorTestStore(t)
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Healthy", ServiceURL: healthyDestinationURL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sender := &orderSender{down: true, delivered: map[string][]string{}, attempts: map[string]int{}, retryAfter: func(message string) time.Duration {
		// The oldest message has climbed further up the backoff ladder.
		if strings.Contains(message, "msg-0") {
			return 400 * time.Millisecond
		}
		return 10 * time.Millisecond
	}}
	startOrderedDelivery(t, st, sender)
	want := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		message := fmt.Sprintf("msg-%d", index)
		want = append(want, message)
		if err := st.EnqueueSystem(ctx, message); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if got := waitForDelivered(t, sender, false, len(want), 5*time.Second); !slices.Equal(got, want) {
		t.Fatalf("healthy destination order=%v, want %v", got, want)
	}
	sender.mu.Lock()
	sender.down = false
	sender.mu.Unlock()
	if got := waitForDelivered(t, sender, true, len(want), 5*time.Second); !slices.Equal(got, want) {
		t.Fatalf("recovered destination order=%v, want creation order %v", got, want)
	}
}

// TestHangingDestinationDelaysOthersByAtMostOneTimeout checks isolation: a
// destination whose sends hang until the send timeout is tried once per
// tick, and its remaining items in the batch are held back, so another
// destination's batch is delayed by at most that one timeout.
func TestHangingDestinationDelaysOthersByAtMostOneTimeout(t *testing.T) {
	ctx := context.Background()
	st, _, _ := openMonitorTestStore(t)
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Healthy", ServiceURL: healthyDestinationURL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	const timeout = 400 * time.Millisecond
	sender := &orderSender{hang: timeout, delivered: map[string][]string{}, attempts: map[string]int{}}
	want := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		message := fmt.Sprintf("msg-%d", index)
		want = append(want, message)
		if err := st.EnqueueSystem(ctx, message); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	startOrderedDelivery(t, st, sender)
	got := waitForDelivered(t, sender, false, len(want), 10*time.Second)
	elapsed := time.Since(started)
	if !slices.Equal(got, want) {
		t.Fatalf("healthy destination order=%v, want %v", got, want)
	}
	_, hangingAttempts := sender.snapshot(true)
	if hangingAttempts != 1 {
		t.Fatalf("hanging destination was tried %d times before the healthy batch finished, want 1", hangingAttempts)
	}
	// Sequential sends of all five hanging items would take 5×timeout.
	if elapsed >= 2*timeout {
		t.Fatalf("healthy destination waited %s behind a hanging one (timeout %s)", elapsed, timeout)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Pending != len(want) {
		t.Fatalf("pending=%d, want the hanging destination's %d items held for retry", status.Pending, len(want))
	}
}

// TestReleaseItemHandlesFencedAndFailedReleases covers the bookkeeping
// outcomes of returning an unsent item: a stale lease token is fenced and
// counted as a lost lease, and a store error leaves the row to its lease.
func TestReleaseItemHandlesFencedAndFailedReleases(t *testing.T) {
	ctx := context.Background()
	st, _, _ := openMonitorTestStore(t)
	if err := st.EnqueueSystem(ctx, "held"); err != nil {
		t.Fatal(err)
	}
	items, err := st.ClaimDueOutbox(ctx, 1)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim items=%d err=%v", len(items), err)
	}
	engine := New(st, "", "", "test", &orderSender{delivered: map[string][]string{}, attempts: map[string]int{}})
	stale := items[0]
	stale.LeaseToken = "stale"
	engine.releaseItem(ctx, stale, engine.startOutboxLease(ctx, stale))
	if lost := engine.DeliveryMetrics().LeaseLosses; lost != 1 {
		t.Fatalf("fenced release lease losses=%d, want 1", lost)
	}
	engine.releaseItem(ctx, stale, nil)
	engine.releaseItem(ctx, items[0], engine.startOutboxLease(ctx, items[0]))
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Pending != 1 || status.Processing != 0 {
		t.Fatalf("released item status pending=%d processing=%d", status.Pending, status.Processing)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	engine.releaseItem(ctx, items[0], nil)
}

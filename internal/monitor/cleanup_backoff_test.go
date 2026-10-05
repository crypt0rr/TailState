package monitor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCleanupErrorsBackOffAndSuccessResets(t *testing.T) {
	failure := errors.New("database or disk is full")
	var backoff cleanupBackoff
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for attempt, expected := range want {
		if got := backoff.next(true, failure); got != expected {
			t.Fatalf("failure %d delay=%s, want %s", attempt+1, got, expected)
		}
	}
	for i := 0; i < 20; i++ {
		backoff.next(false, failure)
	}
	if got := backoff.next(false, failure); got != cleanupPollInterval {
		t.Fatalf("persistent failure delay=%s, want cap %s", got, cleanupPollInterval)
	}
	if got := backoff.next(false, nil); got != cleanupPollInterval {
		t.Fatalf("successful complete pass delay=%s, want %s", got, cleanupPollInterval)
	}
	if got := backoff.next(true, failure); got != cleanupContinuationInterval {
		t.Fatalf("failure after success delay=%s, want reset to %s", got, cleanupContinuationInterval)
	}
	if got := backoff.next(true, nil); got != cleanupContinuationInterval {
		t.Fatalf("successful pass with remaining work delay=%s, want continuation %s", got, cleanupContinuationInterval)
	}
}

func TestPersistentCleanupErrorDoesNotRetryEverySecond(t *testing.T) {
	ctx := context.Background()
	st, _, db := monitorTestStoreWithDB(t)
	if _, err := db.ExecContext(ctx, "DROP TABLE sessions"); err != nil {
		t.Fatal(err)
	}
	// Scale the schedule down: continuation 2ms, cap 64ms. Without backoff
	// a persistent error would retry roughly 250 times in 500ms.
	previousPoll, previousContinuation := cleanupPollInterval, cleanupContinuationInterval
	cleanupPollInterval, cleanupContinuationInterval = 64*time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { cleanupPollInterval, cleanupContinuationInterval = previousPoll, previousContinuation })
	engine := New(st, "", "", "test", &scriptedSender{})
	cleanupCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		engine.cleanup(cleanupCtx)
		close(done)
	}()
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done
	metrics := engine.CleanupMetrics()
	if metrics.Failures < 3 {
		t.Fatalf("cleanup failures=%d, want repeated retries", metrics.Failures)
	}
	// 2+4+8+16+32 = 62ms of ramp, then one attempt per 64ms: about 13 runs.
	if metrics.Runs > 25 {
		t.Fatalf("persistent cleanup error retried %d times in 500ms; backoff not applied", metrics.Runs)
	}
}

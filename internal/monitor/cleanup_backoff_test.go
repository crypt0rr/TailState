package monitor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
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

// TestCleanupLogsTransactionOverrun runs one pass in which every transaction
// overruns a one-nanosecond budget. The 300-event batch is oversized, so its
// escalated retry removes it. Each overrun must be logged as a warning, the
// pass must not count as a failure, and the next pass must wait on the first
// backoff step instead of the continuation interval.
func TestCleanupLogsTransactionOverrun(t *testing.T) {
	ctx := context.Background()
	st, _, db := monitorTestStoreWithDB(t)
	// The timestamp layout matches the store's own (UTC, nine fractional digits).
	observed := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02T15:04:05.000000000Z")
	if _, err := db.ExecContext(ctx, `INSERT INTO event_batches(id,generation,observed_at,change_count,created_at) VALUES(1,1,?,300,?)`, observed, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<300) INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) SELECT 1,1,?,'devices','changed','r','n','[]' FROM n`, observed); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	engine := New(st, "", "", "test", &scriptedSender{})
	var backoff cleanupBackoff
	delay := engine.cleanupPass(ctx, store.CleanupOptions{Retention: time.Hour, TransactionBudget: time.Nanosecond}, &backoff, false)

	warned := false
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `level=WARN msg="retention cleanup transaction exceeded its budget"`) && strings.Contains(line, "phase=event_batches") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("oversized batch overrun was not logged as a warning:\n%s", logs.String())
	}
	var events int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&events); err != nil || events != 0 {
		t.Fatalf("escalated retry left events=%d err=%v", events, err)
	}
	if metrics := engine.CleanupMetrics(); metrics.Failures != 0 || metrics.Runs != 1 {
		t.Fatalf("overrun counted as a failure: %+v", metrics)
	}
	if delay != cleanupContinuationInterval {
		t.Fatalf("overrun pass delay=%s, want the first backoff step %s", delay, cleanupContinuationInterval)
	}
}

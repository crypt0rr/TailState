package monitor

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

func (e *Engine) recordCleanup(stats store.CleanupStats, err error) {
	e.cleanupStats.runs.Add(1)
	e.cleanupStats.transactions.Add(uint64(stats.Transactions))
	e.cleanupStats.durationNanos.Add(uint64(max(stats.Duration, 0)))
	if stats.Remaining {
		e.cleanupStats.remainingPasses.Add(1)
		e.cleanupStats.remaining.Store(1)
	} else {
		e.cleanupStats.remaining.Store(0)
	}
	if err != nil {
		e.cleanupStats.failures.Add(1)
	}
	e.cleanupStats.sessionsDeleted.Add(uint64(max(stats.SessionsDeleted, 0)))
	e.cleanupStats.authTokensDeleted.Add(uint64(max(stats.AuthTokensDeleted, 0)))
	e.cleanupStats.metaDeleted.Add(uint64(max(stats.MetaDeleted, 0)))
	e.cleanupStats.outboxDeadLettered.Add(uint64(max(stats.OutboxDeadLettered, 0)))
	e.cleanupStats.webhookDeadLettered.Add(uint64(max(stats.WebhookDeadLettered, 0)))
	e.cleanupStats.eventsDeleted.Add(uint64(max(stats.EventsDeleted, 0)))
	e.cleanupStats.eventBatchesDeleted.Add(uint64(max(stats.EventBatchesDeleted, 0)))
	e.cleanupStats.eventBatchTriggersDeleted.Add(uint64(max(stats.EventBatchTriggersDeleted, 0)))
	e.cleanupStats.webhookTriggersDeleted.Add(uint64(max(stats.WebhookTriggersDeleted, 0)))
	e.cleanupStats.deliveredOutboxDeleted.Add(uint64(max(stats.DeliveredOutboxDeleted, 0)))
	e.cleanupStats.deadOutboxDeleted.Add(uint64(max(stats.DeadOutboxDeleted, 0)))
	e.cleanupStats.adminAuditDeleted.Add(uint64(max(stats.AdminAuditDeleted, 0)))
	e.cleanupStats.apiTokensDeleted.Add(uint64(max(stats.APITokensDeleted, 0)))
}

// cleanupBackoff schedules retention passes. Genuine leftover work continues
// after cleanupContinuationInterval; consecutive errors back off
// exponentially from that interval up to cleanupPollInterval so a persistent
// failure (corruption, a full disk, a storage limit) does not open a write
// transaction and log an error every second forever. A successful pass
// resets the backoff.
type cleanupBackoff struct {
	failures int
}

// errCleanupOverrun marks a pass in which a transaction overran its budget.
// It is scheduled like a failure but is not recorded as one.
var errCleanupOverrun = errors.New("retention transaction exceeded its budget")

// overran schedules the next pass after a pass that overran a transaction
// budget. An escalated overrun means a batch needs more than the pass budget,
// so retrying it every continuation interval would hold the writer for the
// whole pass budget each second; the backoff spaces those attempts out.
func (b *cleanupBackoff) overran() time.Duration {
	return b.next(true, errCleanupOverrun)
}

func (b *cleanupBackoff) next(remaining bool, err error) time.Duration {
	if err != nil {
		b.failures++
		delay := cleanupContinuationInterval
		for attempt := 1; attempt < b.failures && delay < cleanupPollInterval; attempt++ {
			delay *= 2
		}
		return min(delay, cleanupPollInterval)
	}
	b.failures = 0
	if remaining && cleanupPollInterval > cleanupContinuationInterval {
		return cleanupContinuationInterval
	}
	return cleanupPollInterval
}

// cleanupPass runs one retention pass, logs what happened, and returns the
// delay before the next pass. Each transaction that overran its budget is
// logged as a warning, even when the pass itself succeeded.
func (e *Engine) cleanupPass(ctx context.Context, options store.CleanupOptions, backoff *cleanupBackoff, initial bool) time.Duration {
	stats, err := e.store.CleanupWithOptions(ctx, options)
	e.recordCleanup(stats, err)
	for _, overrun := range stats.Overruns {
		slog.Warn("retention cleanup transaction exceeded its budget", "phase", overrun.Phase, "budget_ms", overrun.Budget.Milliseconds(), "escalated", overrun.Escalated)
	}
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			if initial {
				slog.Error("initial retention cleanup failed", "phase", stats.FailedPhase, "error", err)
			} else {
				slog.Error("retention cleanup failed", "phase", stats.FailedPhase, "error", err)
			}
		}
		// A transient lock or I/O error is retried soon, with backoff for
		// consecutive failures (see cleanupBackoff).
		return backoff.next(stats.Remaining, err)
	}
	slog.Info("retention cleanup completed", "duration_ms", stats.Duration.Milliseconds(), "transactions", stats.Transactions, "sessions_deleted", stats.SessionsDeleted, "auth_tokens_deleted", stats.AuthTokensDeleted, "meta_deleted", stats.MetaDeleted, "outbox_dead_lettered", stats.OutboxDeadLettered, "webhook_dead_lettered", stats.WebhookDeadLettered, "events_deleted", stats.EventsDeleted, "event_batches_deleted", stats.EventBatchesDeleted, "event_batch_triggers_deleted", stats.EventBatchTriggersDeleted, "webhook_triggers_deleted", stats.WebhookTriggersDeleted, "delivered_outbox_deleted", stats.DeliveredOutboxDeleted, "dead_outbox_deleted", stats.DeadOutboxDeleted, "admin_audit_deleted", stats.AdminAuditDeleted, "api_tokens_deleted", stats.APITokensDeleted, "remaining", stats.Remaining, "pages_released", stats.PagesReleased, "wal_checkpointed", stats.WALCheckpointed)
	if len(stats.Overruns) > 0 {
		return backoff.overran()
	}
	return backoff.next(stats.Remaining, nil)
}

func (e *Engine) cleanup(ctx context.Context) {
	var backoff cleanupBackoff
	options := store.CleanupOptions{Retention: 30 * 24 * time.Hour}
	timer := time.NewTimer(e.cleanupPass(ctx, options, &backoff, true))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(e.cleanupPass(ctx, options, &backoff, false))
		}
	}
}

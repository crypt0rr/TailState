package monitor

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

var (
	// ledgerCheckpointInterval is the least time between two checkpoints. A
	// checkpoint is sent only when the ledger has advanced past the last one,
	// so an idle ledger sends nothing.
	ledgerCheckpointInterval = 6 * time.Hour
	// ledgerCheckpointCheckInterval is how often the worker looks for a due
	// checkpoint. It is shorter than the interval so a newly chosen destination
	// gets its first checkpoint promptly.
	ledgerCheckpointCheckInterval = 15 * time.Minute
)

// CheckLedgerCheckpoint enqueues a signed checkpoint of the ledger head to the
// configured destination when one is due, and reports whether it did.
func (e *Engine) CheckLedgerCheckpoint(ctx context.Context, now time.Time) (bool, error) {
	settings, err := e.store.Settings(ctx)
	if err != nil {
		return false, err
	}
	// The context is built before the store call so the message callback never
	// reads the store inside the checkpoint's write transaction.
	messages := e.notificationContext(settings)
	return e.store.EnqueueLedgerCheckpointIfDue(ctx, now, ledgerCheckpointInterval, func(checkpoint store.LedgerCheckpoint) notify.Message {
		return messages.LedgerCheckpoint(checkpoint.Sequence, checkpoint.Head, checkpoint.KeyID, checkpoint.Signature, checkpoint.RecordedAt)
	})
}

func (e *Engine) checkpointWorker(ctx context.Context) {
	ticker := time.NewTicker(ledgerCheckpointCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sent, err := e.CheckLedgerCheckpoint(ctx, time.Now())
			switch {
			case err == nil:
				if sent {
					slog.Info("evidence ledger checkpoint enqueued")
				}
			case ctx.Err() != nil:
				return
			case errors.Is(err, sql.ErrNoRows):
				// An unconfigured installation has no settings and no ledger yet.
			case errors.Is(err, store.ErrEvidenceCheckpointDestinationUnavailable):
				slog.Warn("evidence checkpoint not sent: its notification destination is disabled or removed; choose another with tailstate evidence checkpoint")
			default:
				slog.Error("evidence checkpoint failed", "error", err)
			}
		}
	}
}

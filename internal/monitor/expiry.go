package monitor

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/crypt0rr/tailstate/internal/expiry"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

var (
	// expiryInitialDelay lets the first poll after a restart refresh the
	// snapshots before the first expiry check reads them.
	expiryInitialDelay = 2 * time.Minute
	// expiryCheckInterval is the cadence of the expiry horizon check. A failed
	// check is retried after expiryRetryInterval.
	expiryCheckInterval = 24 * time.Hour
	expiryRetryInterval = 15 * time.Minute
)

// ExpiryReport is the outcome of one expiry check.
type ExpiryReport struct {
	Warnings int
	Items    int
}

// CheckExpiry runs one expiry horizon check over the current device and key
// snapshots and enqueues one grouped system notification per window that was
// newly crossed. The warning state is committed with the notifications, so
// each resource and window alerts once per expiry value.
func (e *Engine) CheckExpiry(ctx context.Context, now time.Time) (ExpiryReport, error) {
	settings, err := e.store.Settings(ctx)
	if err != nil {
		return ExpiryReport{}, err
	}
	devices, err := e.store.ExpirySnapshots(ctx, settings.Generation, "devices")
	if err != nil {
		return ExpiryReport{}, err
	}
	keys, err := e.store.ExpirySnapshots(ctx, settings.Generation, "keys")
	if err != nil {
		return ExpiryReport{}, err
	}
	items := expiry.Items(expirySnapshots(devices), expirySnapshots(keys), settings.ExpiryTagFilter)
	raw, err := e.store.ExpiryWarningState(ctx)
	if err != nil {
		return ExpiryReport{}, err
	}
	warnings, next := expiry.Plan(expiry.ParseState(raw), settings.Generation, items, settings.ExpiryWarningDays, now)
	// Expiry warnings are system notifications like collector health alerts:
	// they are not inventory changes, so they reach every enabled destination
	// regardless of routing rules and mute rules.
	messages := e.notificationContext(settings)
	payloads := make([]notify.Message, 0, len(warnings))
	report := ExpiryReport{Warnings: len(warnings)}
	for _, warning := range warnings {
		payloads = append(payloads, expiry.Message(messages, warning, now))
		report.Items += len(warning.Items)
	}
	committed, err := e.store.CommitExpiryWarnings(ctx, settings.Generation, payloads, next.Encode())
	if err != nil {
		return ExpiryReport{}, err
	}
	if !committed {
		return ExpiryReport{}, nil
	}
	return report, nil
}

func (e *Engine) expiryWorker(ctx context.Context) {
	timer := time.NewTimer(expiryInitialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			report, err := e.CheckExpiry(ctx, time.Now().UTC())
			switch {
			case err == nil:
				if report.Warnings > 0 {
					slog.Info("expiry warnings enqueued", "warnings", report.Warnings, "resources", report.Items)
				}
				timer.Reset(expiryCheckInterval)
			case errors.Is(err, context.Canceled) || ctx.Err() != nil:
				return
			case errors.Is(err, sql.ErrNoRows):
				// An unconfigured installation has no settings row yet.
				timer.Reset(expiryRetryInterval)
			default:
				slog.Error("expiry check failed", "error", err)
				timer.Reset(expiryRetryInterval)
			}
		}
	}
}

func expirySnapshots(records []store.SnapshotRecord) []expiry.Snapshot {
	out := make([]expiry.Snapshot, 0, len(records))
	for _, record := range records {
		out = append(out, expiry.Snapshot{ID: record.ResourceID, Name: record.Name, Raw: record.Raw})
	}
	return out
}

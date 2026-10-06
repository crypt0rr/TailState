package monitor

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// attributionLookupBudget bounds one configuration audit lookup. It is a
// variable so tests can exercise the budget without waiting ten seconds.
var attributionLookupBudget = store.DefaultAttributionBudget

type attributionStats struct {
	complete, unsupported, failed atomic.Uint64
	matched, unknown              atomic.Uint64
}

// AttributionMetrics is a cumulative snapshot of change attribution
// telemetry: configuration audit lookups by outcome, and attributed changes
// by whether an actor was found.
type AttributionMetrics struct {
	LookupsComplete    uint64
	LookupsUnsupported uint64
	LookupsFailed      uint64
	ChangesMatched     uint64
	ChangesUnknown     uint64
}

// AttributionMetrics reports attribution telemetry without actor names.
func (e *Engine) AttributionMetrics() AttributionMetrics {
	return AttributionMetrics{
		LookupsComplete:    e.attributionStats.complete.Load(),
		LookupsUnsupported: e.attributionStats.unsupported.Load(),
		LookupsFailed:      e.attributionStats.failed.Load(),
		ChangesMatched:     e.attributionStats.matched.Load(),
		ChangesUnknown:     e.attributionStats.unknown.Load(),
	}
}

// batchOptions enables change attribution for one poll. The configuration
// audit log is not a collector: it produces no snapshots and never affects
// collector health or readiness. An audit log already found unsupported for
// the current generation and OAuth scopes is left alone until its recheck
// time, so an unsupported plan costs no request per poll.
func (e *Engine) batchOptions(ctx context.Context, client *tailscale.Client, settings store.Settings, polled []string) store.BatchOptions {
	if client == nil {
		return store.BatchOptions{}
	}
	scopes := strings.Join(settings.OAuthScopes, " ")
	source, err := e.store.AttributionSource(ctx)
	if err != nil {
		slog.Warn("read attribution source state", "error", err)
	} else if source.Checked(settings.Generation, scopes) && source.State == store.AttributionSourceUnsupported && time.Now().Before(source.NextCheck) {
		return store.BatchOptions{}
	}
	lookback := time.Duration(0)
	for _, collector := range polled {
		interval := settings.InventoryInterval
		if collector == "devices" {
			interval = settings.DeviceInterval
		}
		lookback = max(lookback, interval)
	}
	record := func(state, reason string, next time.Time) {
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := e.store.RecordAttributionSource(recordCtx, store.AttributionSource{Generation: settings.Generation, Scopes: scopes, State: state, Reason: reason, CheckedAt: time.Now(), NextCheck: next}); err != nil {
			slog.Warn("record attribution source state", "error", err)
		}
	}
	return store.BatchOptions{
		Budget:          attributionLookupBudget,
		RemovalLookback: lookback,
		Attribute: func(lookupCtx context.Context, window store.AttributionWindow) store.AttributionResult {
			entries, err := client.ConfigurationAuditLogs(lookupCtx, window.Start, window.End)
			switch {
			case err == nil:
				e.attributionStats.complete.Add(1)
				record(store.AttributionSourceSupported, "", time.Time{})
				return store.AttributionResult{Status: store.AttributionComplete, Entries: entries}
			case tailscale.IsUnsupported(err):
				e.attributionStats.unsupported.Add(1)
				reason := tailscale.UnsupportedReason(err)
				record(store.AttributionSourceUnsupported, reason, time.Now().Add(store.AttributionSourceRecheck))
				slog.Info("configuration audit log unsupported; changes are not attributed", "reason", reason)
				return store.AttributionResult{Status: store.AttributionUnsupported}
			default:
				e.attributionStats.failed.Add(1)
				reason := tailscale.FailureCategory(err)
				if lookupCtx.Err() != nil {
					reason = tailscale.FailureTimeout
				}
				record(store.AttributionSourceFailing, reason, time.Time{})
				slog.Warn("configuration audit log lookup failed; changes are recorded as actor unknown", "reason", reason)
				return store.AttributionResult{Status: store.AttributionUnavailable}
			}
		},
	}
}

// recordAttributionOutcome counts attributed and unknown changes of a batch
// whose lookup was shown.
func (e *Engine) recordAttributionOutcome(batch store.ChangeBatchResult) {
	if batch.AttributionStatus != store.AttributionComplete && batch.AttributionStatus != store.AttributionUnavailable {
		return
	}
	e.attributionStats.matched.Add(uint64(max(batch.Attributed, 0)))
	e.attributionStats.unknown.Add(uint64(max(len(batch.Changes)-batch.Attributed, 0)))
}

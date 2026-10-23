package monitor

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// pollOutcome keeps two answers apart. success is the scheduler's aggregate and
// is strict: a partial response is not a complete poll, so timers and backoff
// keep treating it as a failure. collectors records, per polled collector,
// whether its answer reconciles a webhook trigger: a complete or unsupported
// response, or a partial response whose resources were applied.
type pollOutcome struct {
	success    bool
	collectors map[string]bool
}

// succeeds reports whether a trigger that requested collectors is reconciled
// by the poll. An empty scope means every collector, so it is judged over the
// collectors this poll covered.
func (p pollOutcome) succeeds(collectors []string) bool {
	collectors = normalizeCollectors(collectors)
	if len(collectors) == 0 {
		for _, ok := range p.collectors {
			if !ok {
				return false
			}
		}
		return true
	}
	for _, collector := range collectors {
		if ok, found := p.collectors[collector]; !found || !ok {
			return false
		}
	}
	return true
}

// poll preserves the scheduler's aggregate success contract. Trigger
// reconciliation uses pollWithOutcomes so a failure in one collector does not
// retry a durable trigger that only requested collectors which completed or
// applied a partial result.
func (e *Engine) poll(ctx context.Context, client *tailscale.Client, settings store.Settings, collectors []string, force bool, triggerIDs ...int64) bool {
	return e.pollWithOutcomes(ctx, client, settings, collectors, force, triggerIDs...).success
}

func (e *Engine) pollWithOutcomes(ctx context.Context, client *tailscale.Client, settings store.Settings, collectors []string, force bool, triggerIDs ...int64) pollOutcome {
	triggerIDs = uniquePositive(triggerIDs)
	collectors = normalizeCollectors(collectors)
	outcome := pollOutcome{success: true, collectors: make(map[string]bool, len(collectors))}
	if client != nil {
		// Keep the device list shared by devices/device_details only for this
		// reconciliation. A webhook targeting device_details must not reuse a
		// list from an earlier scheduled poll.
		client.BeginPoll()
	}
	success := true
	results := make([]model.Collected, 0, len(collectors))
	polled := make([]string, 0, len(collectors))
	type measurement struct {
		collector string
		duration  time.Duration
		partial   bool
	}
	measurements := make([]measurement, 0, len(collectors))
	var failures []store.CollectorFailure
	var recovered []string
	for _, collector := range collectors {
		if !force {
			due, dueErr := e.store.CollectorDueWithError(ctx, settings.Generation, collector)
			if dueErr != nil {
				e.dueErrors.Add(1)
				slog.Error("check collector schedule", "collector", collector, "error", dueErr)
			}
			if !due {
				continue
			}
		}
		polled = append(polled, collector)
		wasUnhealthy, unhealthyErr := e.store.CollectorWasUnhealthyWithError(ctx, settings.Generation, collector)
		if unhealthyErr != nil {
			slog.Error("read collector health", "collector", collector, "error", unhealthyErr)
		}
		pollCtx := ctx
		cancel := func() {}
		if collectorPollTimeout > 0 {
			pollCtx, cancel = context.WithTimeout(ctx, collectorPollTimeout)
		}
		started := time.Now()
		resources, err := client.Collect(pollCtx, collector)
		duration := time.Since(started)
		cancel()
		result := model.Collected{Collector: collector, Resources: resources, Error: err, ObservedAt: time.Now().UTC()}
		collectorSuccess := true
		var partialErr *tailscale.PartialError
		if err != nil && errors.As(err, &partialErr) {
			if len(resources) > 0 {
				// A partial response with usable resources can update those
				// snapshots while preserving omitted resources. An all-failed
				// response is not a usable baseline and must remain a failure so
				// ApplyBatch cannot mark the collector healthy or initialized.
				result.Error = nil
				result.Partial = true
				result.PartialError = tailscale.SafeError(err)
				result.PartialErrorCount = partialErr.Count
				if result.PartialErrorCount < 1 {
					result.PartialErrorCount = 1
				}
			}
			success = false
			collectorSuccess = false
		}
		if err != nil && tailscale.IsUnsupportedCollector(collector, err) {
			result.Error = nil
			result.Unsupported = true
			result.UnsupportedReason = tailscale.UnsupportedReason(err)
			slog.Info("collector unsupported", "collector", collector, "reason", result.UnsupportedReason)
		} else if err != nil {
			success = false
			collectorSuccess = false
			safeError := tailscale.SafeError(err)
			failures = append(failures, store.CollectorFailure{Collector: collector, Reason: tailscale.FailureCategory(err), Message: safeError})
			slog.Warn("collector failed", "collector", collector, "error", safeError)
		} else if wasUnhealthy {
			recovered = append(recovered, collector)
		}
		// A partial result with resources is applied by ApplyBatch below, so it
		// reconciles the trigger. The aggregate success stays false for it, and
		// collector health and backoff keep tracking it.
		outcome.collectors[collector] = collectorSuccess || result.Partial
		results = append(results, result)
		measurements = append(measurements, measurement{collector: collector, duration: duration, partial: result.Partial})
	}
	// Failures from one poll are grouped into one "unhealthy" message per
	// destination, so a revoked credential produces one alert instead of one per
	// collector. They are stored, and the notice of each collector that crosses
	// the threshold queued, before the batch is applied: the notified flag and
	// its notice commit together, and a shutdown during the batch cannot drop it.
	messages := e.notificationContext(settings)
	if len(failures) > 0 {
		e.recordCollectorFailures(ctx, settings.Generation, failures, messages)
	}
	if len(polled) == 0 {
		outcome.success = success
		return outcome
	}
	batch, err := e.store.ApplyBatchWithOptions(ctx, settings.Generation, results, messages.Digest, e.batchOptions(ctx, client, settings, polled), triggerIDs...)
	// A recovery is announced only once its results are stored. A batch that was
	// not stored, because the settings generation changed, announces nothing.
	if err == nil && batch.Generation != 0 && len(recovered) > 0 {
		e.queueHealthNotice(ctx, "recovered", messages.CollectorsRecovered(recovered, time.Now()))
	}
	// Unhealthy transitions decided while applying the batch (a baselined
	// collector confirmed unsupported, an engaged mass-removal guard) are queued
	// after the batch that committed them, as their own grouped message.
	if len(batch.Unhealthy) > 0 {
		e.queueHealthNotice(ctx, "unhealthy", messages.CollectorsUnhealthy(batch.Unhealthy, time.Now()))
	}
	if err != nil {
		slog.Error("apply collected inventory", "error", err)
		if retryErr := e.store.SetNextPollErr(ctx, settings.Generation, polled, time.Now().Add(collectorRetryInterval)); retryErr != nil {
			slog.Error("schedule collector retry after apply failure", "error", retryErr)
		}
		for _, collector := range polled {
			outcome.collectors[collector] = false
		}
		outcome.success = false
		return outcome
	}
	if len(triggerIDs) > 0 && batch.Generation == 0 {
		// Settings changed while the poll was running. Keep the durable
		// triggers queued so the new generation can reconcile them.
		for _, collector := range polled {
			outcome.collectors[collector] = false
		}
		outcome.success = false
		return outcome
	}
	for _, item := range measurements {
		if telemetryErr := e.store.RecordCollectorPoll(ctx, settings.Generation, item.collector, item.duration, item.partial); telemetryErr != nil {
			slog.Error("record collector poll telemetry", "collector", item.collector, "error", telemetryErr)
		}
	}
	if len(batch.Changes) > 0 {
		e.recordAttributionOutcome(batch)
		slog.Info("inventory changes detected", "batch_id", batch.ID, "count", len(batch.Changes), "attributed", batch.Attributed)
	}
	deviceCollectors := make([]string, 0, 1)
	inventoryCollectors := make([]string, 0, len(polled))
	retryCollectors := make([]string, 0, len(polled))
	for _, result := range results {
		if result.Unsupported {
			// ApplyBatch deliberately schedules unsupported optional collectors
			// far into the future; do not overwrite that state here.
			continue
		}
		if result.Error != nil || result.Partial {
			retryCollectors = append(retryCollectors, result.Collector)
			continue
		}
		if result.Collector == "devices" {
			deviceCollectors = append(deviceCollectors, result.Collector)
		} else {
			inventoryCollectors = append(inventoryCollectors, result.Collector)
		}
	}
	if err := e.store.SetNextPollErr(ctx, settings.Generation, deviceCollectors, time.Now().Add(settings.DeviceInterval)); err != nil {
		slog.Error("schedule device collector", "error", err)
	}
	if err := e.store.SetNextPollErr(ctx, settings.Generation, inventoryCollectors, time.Now().Add(settings.InventoryInterval)); err != nil {
		slog.Error("schedule inventory collectors", "error", err)
	}
	e.scheduleCollectorRetries(ctx, settings, retryCollectors)
	outcome.success = success
	return outcome
}

// healthBookkeepingTimeout bounds the health writes made around a poll. They
// run on a context detached from the poll, so a shutdown that cancels the poll
// cannot drop a notice whose notified flag is already committed.
const healthBookkeepingTimeout = 5 * time.Second

// recordCollectorFailures stores a poll's failed collectors and queues the
// notices of those that cross the failure threshold, in one transaction. A
// failed write is logged and the poll continues, as for its other writes.
func (e *Engine) recordCollectorFailures(ctx context.Context, generation int64, failures []store.CollectorFailure, messages notify.Context) {
	bookkeepingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthBookkeepingTimeout)
	defer cancel()
	if err := e.store.RecordCollectorHealth(bookkeepingCtx, generation, failures, messages); err != nil {
		slog.Error("record collector failures", "collectors", len(failures), "error", err)
	}
}

// queueHealthNotice queues a health notice after the batch that decided it has
// been committed, on a context detached from the poll like recordCollectorFailures.
func (e *Engine) queueHealthNotice(ctx context.Context, kind string, message notify.Message) {
	bookkeepingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthBookkeepingTimeout)
	defer cancel()
	if err := e.store.EnqueueMessage(bookkeepingCtx, message); err != nil {
		slog.Error("enqueue collector health notification", "notice", kind, "error", err)
	}
}

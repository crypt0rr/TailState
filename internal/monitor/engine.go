package monitor

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

type Engine struct {
	store                      *store.Store
	baseURL, tokenURL, version string
	sender                     notify.Sender
	wake                       chan struct{}
	trigger                    chan ReconcileRequest
	triggerOverflowMu          sync.Mutex
	triggerOverflow            []ReconcileRequest
	wg                         sync.WaitGroup
	dueErrors                  atomic.Uint64
}

// ReconcileRequest asks the scheduler to poll a set of collectors immediately.
// A zero TriggerID is used for a broad, coalesced wakeup without history
// correlation; normal webhook requests carry their durable trigger ID.
type ReconcileRequest struct {
	TriggerID  int64
	TriggerIDs []int64
	Collectors []string
}

var (
	durableTriggerPollInterval = 30 * time.Second
	schedulerWaitInterval      = 5 * time.Second
	deliveryPollInterval       = 2 * time.Second
	cleanupPollInterval        = time.Hour
	collectorPollTimeout       = 2 * time.Minute
	collectorRetryInterval     = 30 * time.Second
)

const maxTriggerOverflow = 1024

func New(st *store.Store, baseURL, tokenURL, version string, senders ...notify.Sender) *Engine {
	var sender notify.Sender = notify.New()
	if len(senders) > 0 && senders[0] != nil {
		sender = senders[0]
	}
	return &Engine{store: st, baseURL: baseURL, tokenURL: tokenURL, version: version, sender: sender, wake: make(chan struct{}, 1), trigger: make(chan ReconcileRequest, 4)}
}
func (e *Engine) Wake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Trigger queues a targeted reconciliation. Requests that arrive while the
// bounded fast-path queue is full are retained in an overflow queue so their
// collector scopes and independent durable outcomes are not lost.
func (e *Engine) Trigger(request ReconcileRequest) {
	request.Collectors = normalizeCollectors(request.Collectors)
	select {
	case e.trigger <- request:
		return
	default:
	}
	// Keep overflow requests separate instead of broadening them into one
	// reconciliation. A broad poll has one success value, so coalescing
	// unrelated webhook scopes would retry/dead-letter healthy triggers along
	// with a failed collector. The scheduler drains this queue in order.
	e.triggerOverflowMu.Lock()
	if len(e.triggerOverflow) < maxTriggerOverflow {
		e.triggerOverflow = append(e.triggerOverflow, request)
	}
	e.triggerOverflowMu.Unlock()
	e.Wake()
}

func (e *Engine) takeTriggerOverflow() []ReconcileRequest {
	e.triggerOverflowMu.Lock()
	defer e.triggerOverflowMu.Unlock()
	if len(e.triggerOverflow) == 0 {
		return nil
	}
	out := append([]ReconcileRequest(nil), e.triggerOverflow...)
	e.triggerOverflow = e.triggerOverflow[:0]
	return out
}

// Run starts the scheduler, delivery worker, and retention worker. Wait must
// be called after the context is cancelled when the owning process is shutting
// down so the store is not closed while a worker is still writing to it.
func (e *Engine) Run(ctx context.Context) {
	e.wg.Add(3)
	go func() {
		defer e.wg.Done()
		e.scheduler(ctx)
	}()
	go func() {
		defer e.wg.Done()
		e.delivery(ctx)
	}()
	go func() {
		defer e.wg.Done()
		e.cleanup(ctx)
	}()
}

// Wait blocks until all workers started by Run have stopped.
func (e *Engine) Wait() { e.wg.Wait() }

// CollectorDueErrors reports scheduler/database failures for the metrics
// endpoint without adding collector names or other high-cardinality labels.
func (e *Engine) CollectorDueErrors() uint64 { return e.dueErrors.Load() }

// schedulerSettings avoids decrypting credentials on every idle scheduler
// iteration while still noticing writes that preserve the inventory
// generation, such as OAuth rotation or interval changes.
func (e *Engine) schedulerSettings(ctx context.Context, client *tailscale.Client, cached store.Settings, cachedRevision string) (store.Settings, string, error) {
	if client == nil {
		current, err := e.store.Settings(ctx)
		if err != nil {
			return store.Settings{}, "", err
		}
		return current, current.Revision, nil
	}
	revision, err := e.store.SettingsRevision(ctx)
	if err != nil {
		return store.Settings{}, "", err
	}
	if revision == cachedRevision {
		return cached, revision, nil
	}
	current, err := e.store.Settings(ctx)
	if err != nil {
		return store.Settings{}, "", err
	}
	return current, revision, nil
}

func (e *Engine) scheduler(ctx context.Context) {
	var generation int64
	var settingsRevision string
	var client *tailscale.Client
	var settings store.Settings
	var deviceTimer, inventoryTimer *time.Timer
	triggerTimer := time.NewTicker(durableTriggerPollInterval)
	defer triggerTimer.Stop()
	stop := func(t *time.Timer) {
		if t != nil && !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}
	defer func() { stop(deviceTimer) }()
	defer func() { stop(inventoryTimer) }()
	for {
		current, currentRevision, err := e.schedulerSettings(ctx, client, settings, settingsRevision)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				slog.Debug("monitor waiting for configuration")
			}
			select {
			case <-ctx.Done():
				return
			case <-e.wake:
				continue
			case <-time.After(schedulerWaitInterval):
				continue
			}
		}
		settingsChanged := client == nil || currentRevision != settingsRevision
		if settingsChanged {
			identityChanged := client == nil || generation != current.Generation
			generation = current.Generation
			settingsRevision = currentRevision
			settings = current
			client = tailscale.New(e.baseURL, e.tokenURL, e.version, tailscale.Credentials{Tailnet: settings.Tailnet, ClientID: settings.OAuthClientID, ClientSecret: settings.OAuthClientSecret})
			if identityChanged {
				initialSuccess := e.poll(ctx, client, settings, allCollectors(), false)
				stop(deviceTimer)
				stop(inventoryTimer)
				deviceTimer = time.NewTimer(nextPollDelay(settings.DeviceInterval, initialSuccess))
				inventoryTimer = time.NewTimer(nextPollDelay(settings.InventoryInterval, initialSuccess))
			} else {
				// Refreshing a credential or interval must not reset the baseline,
				// but the old timers must not keep using the previous interval.
				stop(deviceTimer)
				stop(inventoryTimer)
				deviceTimer = time.NewTimer(jitter(settings.DeviceInterval))
				inventoryTimer = time.NewTimer(jitter(settings.InventoryInterval))
			}
		}
		if overflow := e.takeTriggerOverflow(); len(overflow) > 0 {
			for _, request := range overflow {
				collectors := request.Collectors
				if len(collectors) == 0 {
					collectors = allCollectors()
				}
				requestedIDs := requestTriggerIDs(request)
				triggerIDs := e.claimFastTriggers(ctx, requestedIDs)
				if len(requestedIDs) > 0 && len(triggerIDs) == 0 {
					continue
				}
				success := e.poll(ctx, client, settings, collectors, true, triggerIDs...)
				e.finishTriggers(ctx, triggerIDs, success, 1)
			}
			continue
		}
		// Handle the low-latency in-memory request first when one is queued.
		// The durable queue remains the source of truth and is replayed once
		// the fast path has drained.
		// A trigger already accepted into the durable ledger must continue to
		// reconcile even if the webhook secret is later cleared. Disabling new
		// ingress must not strand work that was acknowledged earlier.
		if len(e.trigger) == 0 && e.processDurableTriggers(ctx, client, settings) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
			client = nil
			continue
		case request := <-e.trigger:
			collectors := request.Collectors
			if len(collectors) == 0 {
				collectors = allCollectors()
			}
			requestedIDs := requestTriggerIDs(request)
			triggerIDs := e.claimFastTriggers(ctx, requestedIDs)
			if len(requestedIDs) > 0 && len(triggerIDs) == 0 {
				continue
			}
			success := e.poll(ctx, client, settings, collectors, true, triggerIDs...)
			e.finishTriggers(ctx, triggerIDs, success, 1)
		case <-triggerTimer.C:
			// The durable queue is checked at the top of the loop. This timer
			// also wakes the scheduler when a retry becomes due after a crash.
			continue
		case <-deviceTimer.C:
			pollSuccess := e.poll(ctx, client, settings, tailscale.CoreCollectors, false)
			deviceTimer.Reset(nextPollDelay(settings.DeviceInterval, pollSuccess))
		case <-inventoryTimer.C:
			pollSuccess := e.poll(ctx, client, settings, tailscale.InventoryCollectors, false)
			inventoryTimer.Reset(nextPollDelay(settings.InventoryInterval, pollSuccess))
		}
	}
}

func (e *Engine) poll(ctx context.Context, client *tailscale.Client, settings store.Settings, collectors []string, force bool, triggerIDs ...int64) bool {
	triggerIDs = uniquePositive(triggerIDs)
	success := true
	results := make([]model.Collected, 0, len(collectors))
	polled := make([]string, 0, len(collectors))
	type measurement struct {
		collector string
		duration  time.Duration
		partial   bool
	}
	measurements := make([]measurement, 0, len(collectors))
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
		}
		if err != nil && tailscale.IsUnsupportedCollector(collector, err) {
			result.Error = nil
			result.Unsupported = true
			slog.Info("collector unsupported", "collector", collector)
		} else if err != nil {
			success = false
			safeError := tailscale.SafeError(err)
			shouldNotify, _, storeErr := e.store.RecordCollectorFailure(ctx, settings.Generation, collector, safeError)
			if storeErr != nil {
				slog.Error("record collector failure", "collector", collector, "error", storeErr)
			}
			if shouldNotify {
				if enqueueErr := e.store.EnqueueSystem(ctx, notify.SourceHealth(collector, false)); enqueueErr != nil {
					slog.Error("enqueue collector health notification", "collector", collector, "error", enqueueErr)
				}
			}
			slog.Warn("collector failed", "collector", collector, "error", safeError)
		} else if wasUnhealthy {
			if enqueueErr := e.store.EnqueueSystem(ctx, notify.SourceHealth(collector, true)); enqueueErr != nil {
				slog.Error("enqueue collector recovery notification", "collector", collector, "error", enqueueErr)
			}
		}
		results = append(results, result)
		measurements = append(measurements, measurement{collector: collector, duration: duration, partial: result.Partial})
	}
	if len(polled) == 0 {
		return success
	}
	batch, err := e.store.ApplyBatchWithBatch(ctx, settings.Generation, results, notify.Digest, triggerIDs...)
	if err != nil {
		slog.Error("apply collected inventory", "error", err)
		if retryErr := e.store.SetNextPollErr(ctx, settings.Generation, polled, time.Now().Add(collectorRetryInterval)); retryErr != nil {
			slog.Error("schedule collector retry after apply failure", "error", retryErr)
		}
		return false
	}
	if len(triggerIDs) > 0 && batch.Generation == 0 {
		// Settings changed while the poll was running. Keep the durable
		// triggers queued so the new generation can reconcile them.
		return false
	}
	for _, item := range measurements {
		if telemetryErr := e.store.RecordCollectorPoll(ctx, settings.Generation, item.collector, item.duration, item.partial); telemetryErr != nil {
			slog.Error("record collector poll telemetry", "collector", item.collector, "error", telemetryErr)
		}
	}
	if len(batch.Changes) > 0 {
		slog.Info("inventory changes detected", "batch_id", batch.ID, "count", len(batch.Changes))
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
	if err := e.store.SetNextPollErr(ctx, settings.Generation, retryCollectors, time.Now().Add(collectorRetryInterval)); err != nil {
		slog.Error("schedule collector retry", "error", err)
	}
	return success
}

func (e *Engine) processDurableTriggers(ctx context.Context, client *tailscale.Client, settings store.Settings) bool {
	due, err := e.store.HasDueWebhookTriggers(ctx, time.Now().UTC())
	if err != nil {
		slog.Error("check durable webhook triggers", "error", err)
		return false
	}
	if !due {
		return false
	}
	triggers, err := e.store.ClaimWebhookTriggers(ctx, 0, 0)
	if err != nil {
		slog.Error("claim durable webhook triggers", "error", err)
		return false
	}
	if len(triggers) == 0 {
		return false
	}
	type triggerGroup struct {
		ids         []int64
		collectors  []string
		maxAttempts int
	}
	groups := make(map[string]*triggerGroup, len(triggers))
	for _, trigger := range triggers {
		collectors := normalizeCollectors(trigger.Collectors)
		key := strings.Join(collectors, "\x00")
		if len(collectors) == 0 {
			key = "*"
		}
		group := groups[key]
		if group == nil {
			group = &triggerGroup{collectors: collectors, maxAttempts: 1}
			if key == "*" {
				group.collectors = allCollectors()
			}
			groups[key] = group
		}
		group.ids = append(group.ids, trigger.ID)
		if trigger.Attempts > group.maxAttempts {
			group.maxAttempts = trigger.Attempts
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		success := e.poll(ctx, client, settings, group.collectors, true, group.ids...)
		e.finishTriggers(ctx, group.ids, success, group.maxAttempts)
	}
	return true
}

func (e *Engine) finishTriggers(ctx context.Context, ids []int64, success bool, attempts int) {
	ids = uniquePositive(ids)
	if len(ids) == 0 {
		return
	}
	// A shutdown can cancel the poll context immediately after the upstream
	// request completes. Keep the durable trigger outcome write alive briefly so
	// a successfully reconciled webhook is not left processing until lease
	// expiry, and a failed one is not silently lost.
	bookkeepingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if success {
		if err := e.store.CompleteWebhookTriggers(bookkeepingCtx, ids); err != nil {
			slog.Error("complete durable webhook triggers", "trigger_ids", ids, "error", err)
		}
		return
	}
	if attempts <= 0 {
		attempts = 1
	}
	if err := e.store.RetryWebhookTriggers(bookkeepingCtx, ids, time.Now().Add(retryDelay(attempts)), "collector reconciliation failed"); err != nil {
		slog.Error("retry durable webhook triggers", "trigger_ids", ids, "error", err)
	}
}

func allCollectors() []string {
	collectors := append([]string{}, tailscale.CoreCollectors...)
	collectors = append(collectors, tailscale.InventoryCollectors...)
	return collectors
}

func normalizeCollectors(collectors []string) []string {
	seen := make(map[string]struct{}, len(collectors))
	for _, collector := range collectors {
		collector = strings.TrimSpace(collector)
		if collector != "" {
			seen[collector] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for collector := range seen {
		out = append(out, collector)
	}
	sort.Strings(out)
	return out
}

func requestTriggerIDs(request ReconcileRequest) []int64 {
	ids := append([]int64{}, request.TriggerIDs...)
	if request.TriggerID > 0 {
		ids = append(ids, request.TriggerID)
	}
	return uniquePositive(ids)
}

// claimFastTriggers arbitrates ownership with the durable trigger worker. A
// webhook request may be queued for immediate handling while its durable row
// is already being claimed by the safety-net worker; only one path should
// reconcile and finalize that row.
func (e *Engine) claimFastTriggers(ctx context.Context, ids []int64) []int64 {
	ids = uniquePositive(ids)
	if len(ids) == 0 {
		return nil
	}
	claimed := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, ok, err := e.store.ClaimWebhookTrigger(ctx, id, 0); err != nil {
			slog.Error("claim fast webhook trigger", "trigger_id", id, "error", err)
		} else if ok {
			claimed = append(claimed, id)
		}
	}
	return claimed
}

func uniquePositive(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	for _, value := range values {
		if value > 0 {
			seen[value] = struct{}{}
		}
	}
	out := make([]int64, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (e *Engine) delivery(ctx context.Context) {
	ticker := time.NewTicker(deliveryPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			items, err := e.store.DueOutbox(ctx, 10)
			if err != nil {
				slog.Error("load outbox", "error", err)
				continue
			}
			for _, item := range items {
				err = e.sender.Send(ctx, item.Destination.ServiceURL, item.Payload)
				bookkeepingCtx, cancelBookkeeping := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				if err == nil {
					if deliveredErr := e.store.Delivered(bookkeepingCtx, item.ID); deliveredErr != nil {
						slog.Error("mark notification delivery complete", "outbox_id", item.ID, "destination_id", item.DestinationID, "error", deliveredErr)
					}
					cancelBookkeeping()
					continue
				}
				// Senders are injectable for tests and future transports. Apply the
				// same destination-aware redaction at this boundary so an upstream
				// provider error cannot reach logs or durable outbox history even if
				// the sender did not sanitize it itself.
				safeMessage := notify.SafeDeliveryError(err)
				dead := time.Since(item.FirstAttempt) >= 24*time.Hour
				var delivery *notify.DeliveryError
				delay := retryDelay(item.Attempts)
				if errors.As(err, &delivery) && delivery.RetryAfter > 0 {
					delay = delivery.RetryAfter
				}
				if retryErr := e.store.Retry(bookkeepingCtx, item.ID, time.Now().Add(delay), safeMessage, dead); retryErr != nil {
					slog.Error("record notification delivery failure", "outbox_id", item.ID, "destination_id", item.DestinationID, "error", retryErr)
				}
				cancelBookkeeping()
				if dead {
					slog.Error("notification delivery dead-lettered", "outbox_id", item.ID, "destination_id", item.DestinationID, "error", safeMessage)
				} else {
					slog.Warn("notification delivery failed", "outbox_id", item.ID, "destination_id", item.DestinationID, "error", safeMessage)
				}
			}
		}
	}
}

func (e *Engine) cleanup(ctx context.Context) {
	if err := e.store.Cleanup(ctx, 30*24*time.Hour); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("initial retention cleanup failed", "error", err)
	}
	ticker := time.NewTicker(cleanupPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.store.Cleanup(ctx, 30*24*time.Hour); err != nil {
				slog.Error("retention cleanup failed", "error", err)
			}
		}
	}
}
func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Minute
	}
	return base + time.Duration(rand.Int64N(max(int64(base/10), 1)))
}

func nextPollDelay(base time.Duration, successful bool) time.Duration {
	if successful {
		return jitter(base)
	}
	return jitter(collectorRetryInterval)
}

func retryDelay(attempt int) time.Duration {
	shift := min(attempt, 10)
	delay := 5 * time.Second * time.Duration(1<<shift)
	if delay > time.Hour {
		delay = time.Hour
	}
	return delay + time.Duration(rand.Int64N(max(int64(delay/5), 1)))
}

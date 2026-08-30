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
	deliveryLease              time.Duration
	wake                       chan struct{}
	trigger                    chan ReconcileRequest
	triggerOverflowMu          sync.Mutex
	triggerOverflow            []ReconcileRequest
	wg                         sync.WaitGroup
	dueErrors                  atomic.Uint64
	deliveryStats              deliveryStats
	cleanupStats               cleanupTelemetry
}

const (
	deliveryBatchSize               = 10
	deliveryLeaseRenewalFraction    = 3
	minDeliveryLeaseRenewalInterval = 100 * time.Millisecond
	deliveryDurationBucketCount     = 9
	cleanupContinuationInterval     = time.Second
)

var deliveryDurationBucketBounds = [deliveryDurationBucketCount]float64{0.1, 0.5, 1, 5, 15, 30, 60, 120, 300}

type deliveryStats struct {
	attempts             atomic.Uint64
	successes            atomic.Uint64
	failures             atomic.Uint64
	leaseRenewals        atomic.Uint64
	leaseRenewalFailures atomic.Uint64
	leaseLosses          atomic.Uint64
	durationCount        atomic.Uint64
	durationNanos        atomic.Uint64
	durationBuckets      [deliveryDurationBucketCount]atomic.Uint64
}

// DeliveryMetrics is a point-in-time snapshot of delivery worker telemetry.
// DurationBuckets are cumulative histogram buckets whose bounds are returned
// by DeliveryDurationBucketBounds.
type DeliveryMetrics struct {
	Attempts             uint64
	Successes            uint64
	Failures             uint64
	LeaseRenewals        uint64
	LeaseRenewalFailures uint64
	LeaseLosses          uint64
	DurationCount        uint64
	DurationSeconds      float64
	DurationBuckets      [deliveryDurationBucketCount]uint64
}

// CleanupMetrics is a cumulative snapshot of retention-worker telemetry.
// Row counters use stable table names in the Prometheus endpoint and never
// include payloads, destination URLs, or provider data.
type CleanupMetrics struct {
	Runs                      uint64
	Failures                  uint64
	RemainingPasses           uint64
	Remaining                 bool
	Transactions              uint64
	DurationSeconds           float64
	SessionsDeleted           uint64
	AuthTokensDeleted         uint64
	MetaDeleted               uint64
	OutboxDeadLettered        uint64
	WebhookDeadLettered       uint64
	EventsDeleted             uint64
	EventBatchesDeleted       uint64
	EventBatchTriggersDeleted uint64
	WebhookTriggersDeleted    uint64
	DeliveredOutboxDeleted    uint64
	DeadOutboxDeleted         uint64
}

type cleanupTelemetry struct {
	runs, failures, remainingPasses, transactions, durationNanos, remaining atomic.Uint64
	sessionsDeleted, authTokensDeleted, metaDeleted                         atomic.Uint64
	outboxDeadLettered, webhookDeadLettered                                 atomic.Uint64
	eventsDeleted, eventBatchesDeleted                                      atomic.Uint64
	eventBatchTriggersDeleted, webhookTriggersDeleted                       atomic.Uint64
	deliveredOutboxDeleted, deadOutboxDeleted                               atomic.Uint64
}

type deliveryLeaseState struct {
	lost atomic.Bool
}

type deliveryLease struct {
	cancel  context.CancelFunc
	done    chan struct{}
	state   *deliveryLeaseState
	stopOne sync.Once
}

func (l *deliveryLease) stop() {
	if l == nil {
		return
	}
	l.stopOne.Do(func() {
		l.cancel()
		<-l.done
	})
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

// DeliveryMetrics reports delivery and lease telemetry without exposing
// destination names, URLs, payloads, or provider error text.
func (e *Engine) DeliveryMetrics() DeliveryMetrics {
	metrics := DeliveryMetrics{
		Attempts:             e.deliveryStats.attempts.Load(),
		Successes:            e.deliveryStats.successes.Load(),
		Failures:             e.deliveryStats.failures.Load(),
		LeaseRenewals:        e.deliveryStats.leaseRenewals.Load(),
		LeaseRenewalFailures: e.deliveryStats.leaseRenewalFailures.Load(),
		LeaseLosses:          e.deliveryStats.leaseLosses.Load(),
		DurationCount:        e.deliveryStats.durationCount.Load(),
	}
	metrics.DurationSeconds = float64(e.deliveryStats.durationNanos.Load()) / float64(time.Second)
	for i := range metrics.DurationBuckets {
		metrics.DurationBuckets[i] = e.deliveryStats.durationBuckets[i].Load()
	}
	return metrics
}

// CleanupMetrics reports retention progress without exposing row contents or
// error details. RemainingPasses is a counter of bounded passes that stopped
// with work still queued; the current remaining state is exported separately
// by the metrics handler as a gauge.
func (e *Engine) CleanupMetrics() CleanupMetrics {
	return CleanupMetrics{
		Runs:                      e.cleanupStats.runs.Load(),
		Failures:                  e.cleanupStats.failures.Load(),
		RemainingPasses:           e.cleanupStats.remainingPasses.Load(),
		Remaining:                 e.cleanupStats.remaining.Load() == 1,
		Transactions:              e.cleanupStats.transactions.Load(),
		DurationSeconds:           float64(e.cleanupStats.durationNanos.Load()) / float64(time.Second),
		SessionsDeleted:           e.cleanupStats.sessionsDeleted.Load(),
		AuthTokensDeleted:         e.cleanupStats.authTokensDeleted.Load(),
		MetaDeleted:               e.cleanupStats.metaDeleted.Load(),
		OutboxDeadLettered:        e.cleanupStats.outboxDeadLettered.Load(),
		WebhookDeadLettered:       e.cleanupStats.webhookDeadLettered.Load(),
		EventsDeleted:             e.cleanupStats.eventsDeleted.Load(),
		EventBatchesDeleted:       e.cleanupStats.eventBatchesDeleted.Load(),
		EventBatchTriggersDeleted: e.cleanupStats.eventBatchTriggersDeleted.Load(),
		WebhookTriggersDeleted:    e.cleanupStats.webhookTriggersDeleted.Load(),
		DeliveredOutboxDeleted:    e.cleanupStats.deliveredOutboxDeleted.Load(),
		DeadOutboxDeleted:         e.cleanupStats.deadOutboxDeleted.Load(),
	}
}

// DeliveryDurationBucketBounds returns the cumulative delivery histogram
// bounds in seconds.
func DeliveryDurationBucketBounds() [deliveryDurationBucketCount]float64 {
	return deliveryDurationBucketBounds
}

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
			identityChanged := schedulerIdentityChanged(client, generation, current.Generation)
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
				claims := e.claimFastTriggerClaims(ctx, requestedIDs)
				triggerIDs := webhookTriggerIDs(claims)
				if len(requestedIDs) > 0 && len(triggerIDs) == 0 {
					continue
				}
				outcome := e.pollWithOutcomes(ctx, client, settings, collectors, true, triggerIDs...)
				for _, claim := range claims {
					e.finishClaimedTriggers(ctx, []store.WebhookTrigger{claim}, outcome.succeeds(claim.Collectors), claim.Attempts)
				}
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
			continue
		case request := <-e.trigger:
			collectors := request.Collectors
			if len(collectors) == 0 {
				collectors = allCollectors()
			}
			requestedIDs := requestTriggerIDs(request)
			claims := e.claimFastTriggerClaims(ctx, requestedIDs)
			triggerIDs := webhookTriggerIDs(claims)
			if len(requestedIDs) > 0 && len(triggerIDs) == 0 {
				continue
			}
			outcome := e.pollWithOutcomes(ctx, client, settings, collectors, true, triggerIDs...)
			for _, claim := range claims {
				e.finishClaimedTriggers(ctx, []store.WebhookTrigger{claim}, outcome.succeeds(claim.Collectors), claim.Attempts)
			}
		case <-triggerTimer.C:
			// The durable queue is checked at the top of the loop. This timer
			// also wakes the scheduler when a retry becomes due after a crash.
			continue
		case <-deviceTimer.C:
			pollSuccess := e.poll(ctx, client, settings, tailscale.CoreCollectors, false)
			deviceTimer.Reset(e.pollTimerDelay(ctx, settings.Generation, tailscale.CoreCollectors, settings.DeviceInterval, pollSuccess))
		case <-inventoryTimer.C:
			pollSuccess := e.poll(ctx, client, settings, tailscale.InventoryCollectors, false)
			inventoryTimer.Reset(e.pollTimerDelay(ctx, settings.Generation, tailscale.InventoryCollectors, settings.InventoryInterval, pollSuccess))
		}
	}
}

// pollTimerDelay keeps the configured interval as the normal cadence while
// honoring an earlier per-collector deadline. Unsupported responses use a
// short confirmation retry and transient failures use a bounded retry; either
// must wake the scheduler even when the inventory interval is several hours.
func (e *Engine) pollTimerDelay(ctx context.Context, generation int64, collectors []string, base time.Duration, successful bool) time.Duration {
	delay := nextPollDelay(base, successful)
	deadline, found, err := e.store.EarliestCollectorDue(ctx, generation, collectors)
	if err != nil {
		slog.Error("read collector next poll deadline", "error", err)
		return delay
	}
	if !found {
		return delay
	}
	if deadline.IsZero() {
		// A missing deadline means the row is due now. Keep a small floor so a
		// transient write failure cannot turn the scheduler into a tight loop.
		return min(delay, time.Second)
	}
	if remaining := time.Until(deadline); remaining < delay {
		if remaining <= 0 {
			return min(delay, time.Second)
		}
		return remaining
	}
	return delay
}

// schedulerIdentityChanged distinguishes a first configuration or tailnet/
// OAuth identity change from a settings refresh that only rotates credentials
// or polling intervals. The cached client remains usable for the latter; the
// schedulerSettings revision check reloads the new secret without discarding
// the established inventory identity.
func schedulerIdentityChanged(client *tailscale.Client, previousGeneration, currentGeneration int64) bool {
	return client == nil || previousGeneration != currentGeneration
}

type pollOutcome struct {
	success    bool
	collectors map[string]bool
}

func (p pollOutcome) succeeds(collectors []string) bool {
	collectors = normalizeCollectors(collectors)
	if len(collectors) == 0 {
		return p.success
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
// retry a durable trigger that only requested collectors which completed.
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
			slog.Info("collector unsupported", "collector", collector)
		} else if err != nil {
			success = false
			collectorSuccess = false
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
		outcome.collectors[collector] = collectorSuccess
		results = append(results, result)
		measurements = append(measurements, measurement{collector: collector, duration: duration, partial: result.Partial})
	}
	if len(polled) == 0 {
		outcome.success = success
		return outcome
	}
	batch, err := e.store.ApplyBatchWithBatch(ctx, settings.Generation, results, notify.Digest, triggerIDs...)
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
	outcome.success = success
	return outcome
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
		claims     []store.WebhookTrigger
		collectors []string
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
			group = &triggerGroup{collectors: collectors}
			if key == "*" {
				group.collectors = allCollectors()
			}
			groups[key] = group
		}
		group.claims = append(group.claims, trigger)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		triggerIDs := webhookTriggerIDs(group.claims)
		outcome := e.pollWithOutcomes(ctx, client, settings, group.collectors, true, triggerIDs...)
		for _, claim := range group.claims {
			e.finishClaimedTriggers(ctx, []store.WebhookTrigger{claim}, outcome.succeeds(claim.Collectors), claim.Attempts)
		}
	}
	return true
}

// finishClaimedTriggers persists the result against the exact lease returned
// by the claim operation. This fences a slow worker after its lease expires
// and another worker starts a newer attempt for the same trigger.
func (e *Engine) finishClaimedTriggers(ctx context.Context, claims []store.WebhookTrigger, success bool, attempts int) {
	if len(claims) == 0 {
		return
	}
	ids := webhookTriggerIDs(claims)
	bookkeepingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if success {
		if err := e.store.CompleteClaimedWebhookTriggers(bookkeepingCtx, claims); err != nil {
			slog.Error("complete durable webhook triggers", "trigger_ids", ids, "error", err)
		}
		return
	}
	if attempts <= 0 {
		attempts = 1
	}
	if err := e.store.RetryClaimedWebhookTriggers(bookkeepingCtx, claims, time.Now().Add(retryDelay(attempts)), "collector reconciliation failed"); err != nil {
		slog.Error("retry durable webhook triggers", "trigger_ids", ids, "error", err)
	}
}

func allCollectors() []string {
	collectors := append([]string{}, tailscale.CoreCollectors...)
	collectors = append(collectors, tailscale.InventoryCollectors...)
	return collectors
}

func normalizeCollectors(collectors []string) []string {
	known := make(map[string]struct{}, len(tailscale.CoreCollectors)+len(tailscale.InventoryCollectors))
	for _, collector := range tailscale.CoreCollectors {
		known[collector] = struct{}{}
	}
	for _, collector := range tailscale.InventoryCollectors {
		known[collector] = struct{}{}
	}
	seen := make(map[string]struct{}, len(collectors))
	unknown := false
	for _, collector := range collectors {
		collector = strings.TrimSpace(collector)
		if collector != "" {
			if _, ok := known[collector]; !ok {
				// Unknown provider metadata must trigger a broad reconciliation.
				// Silently targeting an unsupported collector would retry a
				// durable webhook until its dead-letter horizon instead of
				// preserving the safety property of unknown events.
				unknown = true
				continue
			}
			seen[collector] = struct{}{}
		}
	}
	if unknown {
		return nil
	}
	out := make([]string, 0, len(seen))
	for collector := range seen {
		out = append(out, collector)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := collectorPriority(out[i]), collectorPriority(out[j])
		if left != right {
			return left < right
		}
		return out[i] < out[j]
	})
	return out
}

func collectorPriority(collector string) int {
	for index, core := range tailscale.CoreCollectors {
		if collector == core {
			return index
		}
	}
	return len(tailscale.CoreCollectors)
}

func requestTriggerIDs(request ReconcileRequest) []int64 {
	ids := append([]int64{}, request.TriggerIDs...)
	if request.TriggerID > 0 {
		ids = append(ids, request.TriggerID)
	}
	return uniquePositive(ids)
}

func (e *Engine) claimFastTriggerClaims(ctx context.Context, ids []int64) []store.WebhookTrigger {
	ids = uniquePositive(ids)
	if len(ids) == 0 {
		return nil
	}
	claimed := make([]store.WebhookTrigger, 0, len(ids))
	for _, id := range ids {
		trigger, ok, err := e.store.ClaimWebhookTrigger(ctx, id, 0)
		if err != nil {
			slog.Error("claim fast webhook trigger", "trigger_id", id, "error", err)
		} else if ok {
			claimed = append(claimed, trigger)
		}
	}
	return claimed
}

func webhookTriggerIDs(claims []store.WebhookTrigger) []int64 {
	ids := make([]int64, 0, len(claims))
	for _, claim := range claims {
		if claim.ID > 0 {
			ids = append(ids, claim.ID)
		}
	}
	return uniquePositive(ids)
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
			var (
				items []store.OutboxItem
				err   error
			)
			if e.deliveryLease > 0 {
				items, err = e.store.ClaimDueOutbox(ctx, deliveryBatchSize, e.deliveryLease)
			} else {
				items, err = e.store.ClaimDueOutbox(ctx, deliveryBatchSize)
			}
			if err != nil {
				slog.Error("load outbox", "error", err)
				continue
			}
			leases := make(map[int64]*deliveryLease, len(items))
			for _, item := range items {
				leases[item.ID] = e.startOutboxLease(ctx, item)
			}
			for _, item := range items {
				e.deliverItemWithLease(ctx, item, leases[item.ID])
			}
			for _, lease := range leases {
				lease.stop()
			}
		}
	}
}

func (e *Engine) startOutboxLease(ctx context.Context, item store.OutboxItem) *deliveryLease {
	renewCtx, cancelRenew := context.WithCancel(ctx)
	lease := &deliveryLease{cancel: cancelRenew, done: make(chan struct{}), state: &deliveryLeaseState{}}
	go e.renewOutboxLease(renewCtx, item, lease.state, lease.done)
	return lease
}

func (e *Engine) deliverItemWithLease(ctx context.Context, item store.OutboxItem, lease *deliveryLease) {
	e.deliveryStats.attempts.Add(1)
	started := time.Now()
	if lease == nil {
		lease = e.startOutboxLease(ctx, item)
	}
	sendErr := e.sender.Send(ctx, item.Destination.ServiceURL, item.Payload)
	lease.stop()
	elapsed := time.Since(started)
	e.recordDeliveryDuration(elapsed)
	leaseLost := lease.state.lost.Load()

	bookkeepingCtx, cancelBookkeeping := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelBookkeeping()
	if sendErr == nil {
		e.deliveryStats.successes.Add(1)
		completed, deliveredErr := e.store.DeliveredClaimedResult(bookkeepingCtx, item)
		if deliveredErr != nil {
			slog.Error("mark notification delivery complete", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds(), "error", deliveredErr)
		} else if !completed {
			e.noteDeliveryLeaseLost(lease.state)
			leaseLost = true
			slog.Warn("notification delivery completion fenced", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds())
		}
		slog.Debug("notification delivery completed", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds(), "lease_lost", leaseLost)
		return
	}
	e.deliveryStats.failures.Add(1)
	// Senders are injectable for tests and future transports. Apply the same
	// destination-aware redaction at this boundary so an upstream provider
	// error cannot reach logs or durable outbox history even if the sender did
	// not sanitize it itself.
	safeMessage := notify.SafeDeliveryError(sendErr)
	dead := time.Since(item.FirstAttempt) >= 24*time.Hour
	var delivery *notify.DeliveryError
	delay := retryDelay(item.Attempts)
	if errors.As(sendErr, &delivery) && delivery.RetryAfter > 0 {
		delay = delivery.RetryAfter
	}
	requeued, retryErr := e.store.RetryClaimedResult(bookkeepingCtx, item, time.Now().Add(delay), safeMessage, dead)
	if retryErr != nil {
		slog.Error("record notification delivery failure", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds(), "error", retryErr)
	} else if !requeued {
		e.noteDeliveryLeaseLost(lease.state)
		leaseLost = true
		slog.Warn("notification delivery retry fenced", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds())
	}
	if dead {
		slog.Error("notification delivery dead-lettered", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds(), "lease_lost", leaseLost, "error", safeMessage)
	} else {
		slog.Warn("notification delivery failed", "outbox_id", item.ID, "destination_id", item.DestinationID, "attempt", item.Attempts, "elapsed_ms", elapsed.Milliseconds(), "lease_lost", leaseLost, "error", safeMessage)
	}
}

func (e *Engine) renewOutboxLease(ctx context.Context, item store.OutboxItem, state *deliveryLeaseState, done chan<- struct{}) {
	defer close(done)
	lease := time.Minute
	if item.LeaseUntil != nil {
		lease = time.Until(*item.LeaseUntil)
	}
	if lease < time.Second {
		lease = time.Second
	}
	interval := lease / deliveryLeaseRenewalFraction
	if interval < minDeliveryLeaseRenewalInterval {
		interval = minDeliveryLeaseRenewalInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewed, err := e.store.RenewClaimed(ctx, item, lease)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				e.deliveryStats.leaseRenewalFailures.Add(1)
				slog.Warn("notification delivery lease renewal failed", "outbox_id", item.ID, "destination_id", item.DestinationID, "error", err)
				continue
			}
			if !renewed {
				e.noteDeliveryLeaseLost(state)
				slog.Warn("notification delivery lease lost", "outbox_id", item.ID, "destination_id", item.DestinationID)
				return
			}
			e.deliveryStats.leaseRenewals.Add(1)
		}
	}
}

func (e *Engine) noteDeliveryLeaseLost(state *deliveryLeaseState) {
	if state.lost.CompareAndSwap(false, true) {
		e.deliveryStats.leaseLosses.Add(1)
	}
}

func (e *Engine) recordDeliveryDuration(elapsed time.Duration) {
	if elapsed < 0 {
		elapsed = 0
	}
	e.deliveryStats.durationCount.Add(1)
	e.deliveryStats.durationNanos.Add(uint64(elapsed))
	seconds := elapsed.Seconds()
	for i, bound := range deliveryDurationBucketBounds {
		if seconds <= bound {
			e.deliveryStats.durationBuckets[i].Add(1)
		}
	}
}

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
}

func (e *Engine) cleanup(ctx context.Context) {
	run := func(initial bool) bool {
		stats, err := e.store.CleanupWithOptions(ctx, store.CleanupOptions{Retention: 30 * 24 * time.Hour})
		e.recordCleanup(stats, err)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				if initial {
					slog.Error("initial retention cleanup failed", "phase", stats.FailedPhase, "error", err)
				} else {
					slog.Error("retention cleanup failed", "phase", stats.FailedPhase, "error", err)
				}
			}
			// A transient lock or I/O error should be retried on the early
			// continuation schedule instead of waiting a full hour.
			return true
		}
		slog.Info("retention cleanup completed", "duration_ms", stats.Duration.Milliseconds(), "transactions", stats.Transactions, "sessions_deleted", stats.SessionsDeleted, "auth_tokens_deleted", stats.AuthTokensDeleted, "meta_deleted", stats.MetaDeleted, "outbox_dead_lettered", stats.OutboxDeadLettered, "webhook_dead_lettered", stats.WebhookDeadLettered, "events_deleted", stats.EventsDeleted, "event_batches_deleted", stats.EventBatchesDeleted, "event_batch_triggers_deleted", stats.EventBatchTriggersDeleted, "webhook_triggers_deleted", stats.WebhookTriggersDeleted, "delivered_outbox_deleted", stats.DeliveredOutboxDeleted, "dead_outbox_deleted", stats.DeadOutboxDeleted, "remaining", stats.Remaining)
		return stats.Remaining
	}

	remaining := run(true)
	wait := cleanupPollInterval
	if remaining && wait > cleanupContinuationInterval {
		wait = cleanupContinuationInterval
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			remaining = run(false)
			wait := cleanupPollInterval
			if remaining && wait > cleanupContinuationInterval {
				wait = cleanupContinuationInterval
			}
			timer.Reset(wait)
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

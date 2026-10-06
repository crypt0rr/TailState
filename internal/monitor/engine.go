package monitor

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
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
	attributionStats           attributionStats
	instanceLabel, publicURL   string
}

const (
	deliveryBatchSize               = 10
	deliveryLeaseRenewalFraction    = 3
	minDeliveryLeaseRenewalInterval = 100 * time.Millisecond
	deliveryDurationBucketCount     = 9
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
	AdminAuditDeleted         uint64
	APITokensDeleted          uint64
}

type cleanupTelemetry struct {
	runs, failures, remainingPasses, transactions, durationNanos, remaining atomic.Uint64
	sessionsDeleted, authTokensDeleted, metaDeleted                         atomic.Uint64
	outboxDeadLettered, webhookDeadLettered                                 atomic.Uint64
	eventsDeleted, eventBatchesDeleted                                      atomic.Uint64
	eventBatchTriggersDeleted, webhookTriggersDeleted                       atomic.Uint64
	deliveredOutboxDeleted, deadOutboxDeleted                               atomic.Uint64
	adminAuditDeleted, apiTokensDeleted                                     atomic.Uint64
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
	// cleanupContinuationInterval is used only when a successful bounded
	// cleanup pass stopped with work remaining, and as the first retry after
	// a cleanup error.
	cleanupContinuationInterval = time.Second
	collectorPollTimeout        = 2 * time.Minute
	collectorRetryInterval      = 30 * time.Second
)

const maxTriggerOverflow = 1024

func New(st *store.Store, baseURL, tokenURL, version string, senders ...notify.Sender) *Engine {
	var sender notify.Sender = notify.New()
	if len(senders) > 0 && senders[0] != nil {
		sender = senders[0]
	}
	return &Engine{store: st, baseURL: baseURL, tokenURL: tokenURL, version: version, sender: sender, wake: make(chan struct{}, 1), trigger: make(chan ReconcileRequest, 4)}
}

// ConfigureNotifications sets the instance label and public URL added to
// every notification. Call it before Run.
func (e *Engine) ConfigureNotifications(instanceLabel, publicURL string) {
	e.instanceLabel, e.publicURL = instanceLabel, publicURL
}

// notificationContext is the identity shown in notifications for one
// settings generation.
func (e *Engine) notificationContext(settings store.Settings) notify.Context {
	return notify.Context{Label: e.instanceLabel, Tailnet: settings.Tailnet, PublicURL: e.publicURL, Version: e.version}
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

// Run starts the scheduler, delivery worker, expiry worker, and retention worker. Wait must
// be called after the context is cancelled when the owning process is shutting
// down so the store is not closed while a worker is still writing to it.
func (e *Engine) Run(ctx context.Context) {
	e.wg.Add(4)
	go func() {
		defer e.wg.Done()
		e.scheduler(ctx)
	}()
	go func() {
		defer e.wg.Done()
		e.expiryWorker(ctx)
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
		AdminAuditDeleted:         e.cleanupStats.adminAuditDeleted.Load(),
		APITokensDeleted:          e.cleanupStats.apiTokensDeleted.Load(),
	}
}

// DeliveryDurationBucketBounds returns the cumulative delivery histogram
// bounds in seconds.
func DeliveryDurationBucketBounds() [deliveryDurationBucketCount]float64 {
	return deliveryDurationBucketBounds
}

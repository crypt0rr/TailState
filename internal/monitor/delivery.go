package monitor

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

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
			// After a destination's first failed send in this batch, its
			// younger items are returned unsent: the failed item's backoff
			// keeps them in order, and a hanging destination costs the
			// others at most one send timeout per tick.
			failed := make(map[int64]bool)
			for _, item := range items {
				if failed[item.DestinationID] {
					e.releaseItem(ctx, item, leases[item.ID])
					continue
				}
				if e.deliverItemWithLease(ctx, item, leases[item.ID]) {
					failed[item.DestinationID] = true
				}
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

// releaseItem returns a claimed item that was not sent to pending without
// counting an attempt.
func (e *Engine) releaseItem(ctx context.Context, item store.OutboxItem, lease *deliveryLease) {
	lease.stop()
	bookkeepingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	released, err := e.store.ReleaseClaimed(bookkeepingCtx, item)
	if err != nil {
		// The lease expires and the row returns to pending on a later claim.
		slog.Error("release unsent notification", "outbox_id", item.ID, "destination_id", item.DestinationID, "error", err)
		return
	}
	if !released {
		if lease != nil {
			e.noteDeliveryLeaseLost(lease.state)
		}
		slog.Warn("notification release fenced", "outbox_id", item.ID, "destination_id", item.DestinationID)
		return
	}
	slog.Debug("notification held behind a failed delivery", "outbox_id", item.ID, "destination_id", item.DestinationID)
}

// deliverItemWithLease sends one claimed item and records the outcome. It
// reports whether the destination was contacted and the send failed, which
// holds back the destination's younger items in the same batch.
func (e *Engine) deliverItemWithLease(ctx context.Context, item store.OutboxItem, lease *deliveryLease) (sendFailed bool) {
	e.deliveryStats.attempts.Add(1)
	started := time.Now()
	if lease == nil {
		lease = e.startOutboxLease(ctx, item)
	}
	// Render the stored payload for this destination's service (or its
	// override) and fit it to the service budget. Legacy Markdown rows are
	// sent unchanged. A payload that cannot be decoded can never succeed and
	// is dead-lettered without contacting the provider.
	message, prepareErr := notify.PrepareFor(item.PayloadFormat, item.Payload, item.Destination.ServiceURL, item.Destination.Format)
	var sendErr error
	if prepareErr != nil {
		sendErr = &notify.DeliveryError{Message: prepareErr.Error(), Permanent: true}
	} else {
		sendErr = notify.Deliver(ctx, e.sender, item.Destination.ServiceURL, message)
	}
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
		return false
	}
	// A payload that could not be prepared never reached the provider and
	// says nothing about the destination's health.
	sendFailed = prepareErr == nil
	e.deliveryStats.failures.Add(1)
	// Senders are injectable for tests and future transports. Apply the same
	// destination-aware redaction at this boundary so an upstream provider
	// error cannot reach logs or durable outbox history even if the sender did
	// not sanitize it itself.
	safeMessage := notify.SafeDeliveryError(sendErr)
	dead := time.Since(item.FirstAttempt) >= 24*time.Hour || notify.IsPermanent(sendErr)
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
	return sendFailed
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

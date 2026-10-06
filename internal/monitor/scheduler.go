package monitor

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

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
			client = tailscale.New(e.baseURL, e.tokenURL, e.version, tailscale.Credentials{Tailnet: settings.Tailnet, ClientID: settings.OAuthClientID, ClientSecret: settings.OAuthClientSecret, Scopes: settings.OAuthScopes})
			if identityChanged {
				initialSuccess := e.poll(ctx, client, settings, allCollectors(), false)
				stop(deviceTimer)
				stop(inventoryTimer)
				// The initial poll only covers collectors that are already due.
				// Persisted per-collector deadlines (failure retries, unsupported
				// confirmation) must survive a restart instead of being replaced by
				// the full configured interval.
				deviceTimer = time.NewTimer(e.pollTimerDelay(ctx, settings.Generation, tailscale.CoreCollectors, settings.DeviceInterval, initialSuccess))
				inventoryTimer = time.NewTimer(e.pollTimerDelay(ctx, settings.Generation, tailscale.InventoryCollectors, settings.InventoryInterval, initialSuccess))
			} else {
				// Refreshing a credential or interval must not reset the baseline,
				// but the old timers must not keep using the previous interval.
				// Short persisted retry deadlines still apply, so an operator who
				// fixes a broken secret gets the pending retry promptly.
				stop(deviceTimer)
				stop(inventoryTimer)
				deviceTimer = time.NewTimer(e.pollTimerDelay(ctx, settings.Generation, tailscale.CoreCollectors, settings.DeviceInterval, true))
				inventoryTimer = time.NewTimer(e.pollTimerDelay(ctx, settings.Generation, tailscale.InventoryCollectors, settings.InventoryInterval, true))
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

// scheduleCollectorRetries reschedules failed or partial collectors with an
// exponential backoff based on their persisted consecutive failure count. The
// delay starts at collectorRetryInterval and is capped at the collector's
// configured interval, so a permanently broken endpoint (or one device whose
// detail request keeps failing) settles back to the normal cadence instead of
// repeating a full fan-out every 30 seconds.
func (e *Engine) scheduleCollectorRetries(ctx context.Context, settings store.Settings, collectors []string) {
	if len(collectors) == 0 {
		return
	}
	failures, err := e.store.CollectorFailureCounts(ctx, settings.Generation, collectors)
	if err != nil {
		slog.Error("read collector failure counts", "error", err)
	}
	now := time.Now()
	for _, collector := range collectors {
		interval := settings.InventoryInterval
		if collector == "devices" {
			interval = settings.DeviceInterval
		}
		next := now.Add(collectorRetryDelay(failures[collector], interval))
		if err := e.store.SetNextPollErr(ctx, settings.Generation, []string{collector}, next); err != nil {
			slog.Error("schedule collector retry", "collector", collector, "error", err)
		}
	}
}

// collectorRetryDelay doubles collectorRetryInterval for each consecutive
// failure after the first and caps the result at the configured interval. An
// interval shorter than the base retry keeps the base retry.
func collectorRetryDelay(failures int, interval time.Duration) time.Duration {
	limit := max(interval, collectorRetryInterval)
	delay := collectorRetryInterval
	for attempt := 1; attempt < failures && delay < limit; attempt++ {
		delay *= 2
	}
	return min(delay, limit)
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

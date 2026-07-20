package monitor

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/crypt0rr/tailstate/internal/mattermost"
	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

type Engine struct {
	store                      *store.Store
	baseURL, tokenURL, version string
	sender                     *mattermost.Sender
	wake                       chan struct{}
}

func New(st *store.Store, baseURL, tokenURL, version string) *Engine {
	return &Engine{store: st, baseURL: baseURL, tokenURL: tokenURL, version: version, sender: mattermost.New(), wake: make(chan struct{}, 1)}
}
func (e *Engine) Wake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Engine) Run(ctx context.Context) { go e.scheduler(ctx); go e.delivery(ctx); go e.cleanup(ctx) }

func (e *Engine) scheduler(ctx context.Context) {
	var generation int64
	var client *tailscale.Client
	var settings store.Settings
	var deviceTimer, inventoryTimer *time.Timer
	stop := func(t *time.Timer) {
		if t != nil && !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}
	defer stop(deviceTimer)
	defer stop(inventoryTimer)
	for {
		current, err := e.store.Settings(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				slog.Debug("monitor waiting for configuration")
			}
			select {
			case <-ctx.Done():
				return
			case <-e.wake:
				continue
			case <-time.After(5 * time.Second):
				continue
			}
		}
		if client == nil || generation != current.Generation {
			generation = current.Generation
			settings = current
			client = tailscale.New(e.baseURL, e.tokenURL, e.version, tailscale.Credentials{Tailnet: settings.Tailnet, ClientID: settings.OAuthClientID, ClientSecret: settings.OAuthClientSecret})
			e.poll(ctx, client, settings, append(append([]string{}, tailscale.CoreCollectors...), tailscale.InventoryCollectors...))
			stop(deviceTimer)
			stop(inventoryTimer)
			deviceTimer = time.NewTimer(jitter(settings.DeviceInterval))
			inventoryTimer = time.NewTimer(jitter(settings.InventoryInterval))
		}
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
			client = nil
			continue
		case <-deviceTimer.C:
			e.poll(ctx, client, settings, tailscale.CoreCollectors)
			deviceTimer.Reset(jitter(settings.DeviceInterval))
		case <-inventoryTimer.C:
			e.poll(ctx, client, settings, tailscale.InventoryCollectors)
			inventoryTimer.Reset(jitter(settings.InventoryInterval))
		}
	}
}

func (e *Engine) poll(ctx context.Context, client *tailscale.Client, settings store.Settings, collectors []string) {
	results := make([]model.Collected, 0, len(collectors))
	polled := make([]string, 0, len(collectors))
	for _, collector := range collectors {
		if !e.store.CollectorDue(ctx, settings.Generation, collector) {
			continue
		}
		polled = append(polled, collector)
		wasUnhealthy := e.store.CollectorWasUnhealthy(ctx, settings.Generation, collector)
		resources, err := client.Collect(ctx, collector)
		result := model.Collected{Collector: collector, Resources: resources, Error: err, ObservedAt: time.Now().UTC()}
		if err != nil && tailscale.IsUnsupported(err) {
			result.Error = nil
			result.Unsupported = true
			slog.Info("collector unsupported", "collector", collector)
		} else if err != nil {
			notify, _, storeErr := e.store.RecordCollectorFailure(ctx, settings.Generation, collector, err.Error())
			if storeErr != nil {
				slog.Error("record collector failure", "collector", collector, "error", storeErr)
			}
			if notify {
				_ = e.store.EnqueueSystem(ctx, mattermost.SourceHealth(collector, false))
			}
			slog.Warn("collector failed", "collector", collector, "error", err)
		} else if wasUnhealthy {
			_ = e.store.EnqueueSystem(ctx, mattermost.SourceHealth(collector, true))
		}
		results = append(results, result)
	}
	if len(polled) == 0 {
		return
	}
	for _, collector := range polled {
		interval := settings.InventoryInterval
		if collector == "devices" {
			interval = settings.DeviceInterval
		}
		e.store.SetNextPoll(ctx, settings.Generation, []string{collector}, time.Now().Add(interval))
	}
	changes, err := e.store.ApplyBatch(ctx, settings.Generation, results, mattermost.Digest)
	if err != nil {
		slog.Error("apply collected inventory", "error", err)
		return
	}
	if len(changes) > 0 {
		slog.Info("inventory changes detected", "count", len(changes))
	}
}

func (e *Engine) delivery(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			settings, err := e.store.Settings(ctx)
			if err != nil {
				continue
			}
			items, err := e.store.DueOutbox(ctx, 10)
			if err != nil {
				slog.Error("load outbox", "error", err)
				continue
			}
			for _, item := range items {
				err = e.sender.Send(ctx, settings.MattermostURL, item.Payload)
				if err == nil {
					_ = e.store.Delivered(ctx, item.ID)
					continue
				}
				dead := time.Since(item.FirstAttempt) >= 24*time.Hour
				var delivery *mattermost.DeliveryError
				if errors.As(err, &delivery) && delivery.Permanent() {
					dead = true
				}
				delay := retryDelay(item.Attempts)
				if errors.As(err, &delivery) && delivery.RetryAfter > 0 {
					delay = delivery.RetryAfter
				}
				_ = e.store.Retry(ctx, item.ID, time.Now().Add(delay), err.Error(), dead)
				if dead {
					slog.Error("Mattermost delivery dead-lettered", "outbox_id", item.ID, "error", err)
				} else {
					slog.Warn("Mattermost delivery failed", "outbox_id", item.ID, "error", err)
				}
			}
		}
	}
}

func (e *Engine) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
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
func retryDelay(attempt int) time.Duration {
	shift := min(attempt, 10)
	delay := 5 * time.Second * time.Duration(1<<shift)
	if delay > time.Hour {
		delay = time.Hour
	}
	return delay + time.Duration(rand.Int64N(max(int64(delay/5), 1)))
}

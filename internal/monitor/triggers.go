package monitor

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

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
	// Coalesce every trigger claimed in this pass into one poll of the union
	// of their collectors, so overlapping webhook scopes poll each collector at
	// most once. Outcomes stay per collector: each claim is completed or
	// retried only on the collectors it requested.
	var collectors []string
	for _, trigger := range triggers {
		scope := normalizeCollectors(trigger.Collectors)
		if len(scope) == 0 {
			collectors = allCollectors()
			break
		}
		collectors = append(collectors, scope...)
	}
	outcome := e.pollWithOutcomes(ctx, client, settings, normalizeCollectors(collectors), true, webhookTriggerIDs(triggers)...)
	for _, claim := range triggers {
		e.finishClaimedTriggers(ctx, []store.WebhookTrigger{claim}, outcome.succeeds(claim.Collectors), claim.Attempts)
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

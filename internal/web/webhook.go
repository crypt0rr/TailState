package web

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/webhook"
)

// Webhook request outcomes, exported as tailstate_webhook_requests_total.
// Signature failures and content-bounds fallbacks are deliberately distinct.
const (
	webhookOutcomeAccepted         = "accepted"
	webhookOutcomeContentFallback  = "content_fallback"
	webhookOutcomeDuplicate        = "duplicate"
	webhookOutcomeInvalidSignature = "invalid_signature"
	webhookOutcomeMalformed        = "malformed"
	webhookOutcomeTooLarge         = "too_large"
	webhookOutcomeNotConfigured    = "not_configured"
	webhookOutcomeUnavailable      = "unavailable"
)

var webhookOutcomes = []string{
	webhookOutcomeAccepted,
	webhookOutcomeContentFallback,
	webhookOutcomeDuplicate,
	webhookOutcomeInvalidSignature,
	webhookOutcomeMalformed,
	webhookOutcomeTooLarge,
	webhookOutcomeNotConfigured,
	webhookOutcomeUnavailable,
}

func (s *Server) recordWebhookOutcome(outcome string) {
	s.metricsMu.Lock()
	s.webhookOutcomes[outcome]++
	s.metricsMu.Unlock()
}

func (s *Server) webhookOutcomeCount(outcome string) uint64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	return s.webhookOutcomes[outcome]
}

func (s *Server) tailscaleWebhook(w http.ResponseWriter, r *http.Request) {
	if !webhook.Method(r.Method) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secret, err := s.store.WebhookSecret(r.Context())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.recordWebhookOutcome(webhookOutcomeNotConfigured)
			http.Error(w, "webhook not configured", http.StatusNotFound)
			return
		}
		s.recordWebhookOutcome(webhookOutcomeUnavailable)
		http.Error(w, "webhook unavailable", http.StatusServiceUnavailable)
		return
	}
	if secret == "" {
		s.recordWebhookOutcome(webhookOutcomeNotConfigured)
		http.Error(w, "webhook not configured", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.recordWebhookOutcome(webhookOutcomeTooLarge)
			http.Error(w, "webhook body too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.recordWebhookOutcome(webhookOutcomeMalformed)
		http.Error(w, "invalid webhook body", http.StatusBadRequest)
		return
	}
	delivery, err := webhook.Verify(body, r.Header.Get("Tailscale-Webhook-Signature"), secret, time.Now().UTC())
	if err != nil {
		// Keep verification details out of responses and logs. 401 is reserved
		// for signature and timestamp failures; size and shape problems get
		// their own status so operators debug the right thing.
		switch {
		case errors.Is(err, webhook.ErrBodyTooLarge):
			s.recordWebhookOutcome(webhookOutcomeTooLarge)
			http.Error(w, "webhook body too large", http.StatusRequestEntityTooLarge)
		case errors.Is(err, webhook.ErrMalformedBody):
			s.recordWebhookOutcome(webhookOutcomeMalformed)
			http.Error(w, "invalid webhook body", http.StatusBadRequest)
		default:
			s.recordWebhookOutcome(webhookOutcomeInvalidSignature)
			http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		}
		return
	}
	trigger, created, err := s.store.RecordWebhookTrigger(r.Context(), delivery.BodyHash, delivery.EventTypes, delivery.Collectors)
	if err != nil {
		s.recordWebhookOutcome(webhookOutcomeUnavailable)
		http.Error(w, "record webhook", http.StatusInternalServerError)
		return
	}
	if created && s.engine != nil {
		s.engine.Trigger(monitor.ReconcileRequest{TriggerID: trigger.ID, Collectors: delivery.Collectors})
	}
	w.Header().Set("Cache-Control", "no-store")
	status := "accepted"
	outcome := webhookOutcomeAccepted
	if delivery.FallbackReason != "" {
		outcome = webhookOutcomeContentFallback
		// The reason is a fixed vocabulary; no provider content is logged.
		slog.Warn("authentic webhook content exceeded TailState bounds; requesting full reconciliation", "reason", delivery.FallbackReason, "events", len(delivery.Events), "trigger_id", trigger.ID)
	}
	if !created {
		status = "duplicate"
		outcome = webhookOutcomeDuplicate
	}
	s.recordWebhookOutcome(outcome)
	response := map[string]any{"status": status, "trigger_id": trigger.ID}
	if len(delivery.Collectors) == 0 {
		response["reconciliation"] = "full"
	} else {
		response["reconciliation"] = "targeted"
	}
	writeJSON(w, http.StatusAccepted, response)
}

package web

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/store"
)

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsAuthorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tailstate-metrics"`)
		http.Error(w, "metrics authorization required", http.StatusUnauthorized)
		return
	}
	// Collect everything that can fail before writing a single byte, and
	// render into a buffer: a scrape either receives a complete exposition
	// or a clean 500, never a 200 with a truncated or corrupted body.
	status, err := s.store.Status(r.Context())
	if err != nil {
		slog.Error("load status for metrics", "error", err)
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	storage, err := s.store.StorageMetrics(r.Context())
	if err != nil {
		slog.Error("load storage metrics", "error", err)
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	var body bytes.Buffer
	s.writeMetrics(&body, status, storage, s.store.StorageLimits())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	_, _ = w.Write(body.Bytes())
}

// metricFamily writes the HELP and TYPE header that must precede every
// family's samples in the Prometheus text exposition format.
func metricFamily(b *bytes.Buffer, name, kind, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

// metricValue writes a single unlabelled family.
func metricValue(b *bytes.Buffer, name, kind, help string, value any) {
	metricFamily(b, name, kind, help)
	switch v := value.(type) {
	case float64:
		fmt.Fprintf(b, "%s %.6f\n", name, v)
	default:
		fmt.Fprintf(b, "%s %d\n", name, v)
	}
}

func (s *Server) writeMetrics(b *bytes.Buffer, status store.Status, storage store.StorageMetrics, limits store.StorageLimits) {
	metricValue(b, "tailstate_ready", "gauge", "Whether setup and baseline are complete.", boolMetric(status.Configured && status.BaselineReady))
	metricValue(b, "tailstate_baseline_degraded", "gauge", "Whether the baseline is ready but one or more collectors are degraded.", boolMetric(status.BaselineDegraded))
	dueErrors := uint64(0)
	if s.engine != nil {
		dueErrors = s.engine.CollectorDueErrors()
	}
	metricValue(b, "tailstate_collector_due_errors_total", "counter", "Scheduler database errors while selecting due collectors.", dueErrors)
	metricFamily(b, "tailstate_credential_challenge_total", "counter", "Credential form challenge outcomes by action.")
	for _, action := range credentialActions {
		for _, outcome := range credentialChallengeOutcomes {
			fmt.Fprintf(b, "tailstate_credential_challenge_total{action=%q,outcome=%q} %d\n", action, outcome, s.credentialChallengeCount(action, outcome))
		}
	}
	metricFamily(b, "tailstate_credential_rejections_total", "counter", "Credential form submissions rejected after challenge validation.")
	for _, action := range credentialActions {
		fmt.Fprintf(b, "tailstate_credential_rejections_total{action=%q} %d\n", action, s.credentialRejectionCount(action))
	}
	metricValue(b, "tailstate_outbox_pending", "gauge", "Notifications waiting for delivery.", status.Pending)
	metricValue(b, "tailstate_outbox_processing", "gauge", "Notifications currently leased for delivery.", status.Processing)
	metricValue(b, "tailstate_outbox_dead", "gauge", "Notifications that exhausted their delivery window.", status.Dead)
	if s.engine != nil {
		delivery := s.engine.DeliveryMetrics()
		metricValue(b, "tailstate_outbox_delivery_attempts_total", "counter", "Notification delivery attempts.", delivery.Attempts)
		metricValue(b, "tailstate_outbox_delivery_success_total", "counter", "Successful notification deliveries.", delivery.Successes)
		metricValue(b, "tailstate_outbox_delivery_failure_total", "counter", "Failed notification delivery attempts.", delivery.Failures)
		metricValue(b, "tailstate_outbox_lease_renewals_total", "counter", "Delivery lease renewals.", delivery.LeaseRenewals)
		metricValue(b, "tailstate_outbox_lease_renewal_failures_total", "counter", "Delivery lease renewal failures.", delivery.LeaseRenewalFailures)
		metricValue(b, "tailstate_outbox_lease_losses_total", "counter", "Delivery leases lost before completion.", delivery.LeaseLosses)
		metricFamily(b, "tailstate_outbox_delivery_duration_seconds", "histogram", "Notification delivery attempt duration.")
		for i, bound := range monitor.DeliveryDurationBucketBounds() {
			fmt.Fprintf(b, "tailstate_outbox_delivery_duration_seconds_bucket{le=\"%.3g\"} %d\n", bound, delivery.DurationBuckets[i])
		}
		fmt.Fprintf(b, "tailstate_outbox_delivery_duration_seconds_bucket{le=\"+Inf\"} %d\ntailstate_outbox_delivery_duration_seconds_sum %.6f\ntailstate_outbox_delivery_duration_seconds_count %d\n", delivery.DurationCount, delivery.DurationSeconds, delivery.DurationCount)
		cleanup := s.engine.CleanupMetrics()
		metricValue(b, "tailstate_cleanup_runs_total", "counter", "Retention cleanup runs.", cleanup.Runs)
		metricValue(b, "tailstate_cleanup_failures_total", "counter", "Retention cleanup runs that failed.", cleanup.Failures)
		metricValue(b, "tailstate_cleanup_remaining", "gauge", "Whether the last cleanup run left work for a further pass.", boolMetric(cleanup.Remaining))
		metricValue(b, "tailstate_cleanup_remaining_passes_total", "counter", "Cleanup runs that left work for a further pass.", cleanup.RemainingPasses)
		metricValue(b, "tailstate_cleanup_transactions_total", "counter", "Cleanup transactions committed.", cleanup.Transactions)
		metricFamily(b, "tailstate_cleanup_duration_seconds", "summary", "Retention cleanup run duration.")
		fmt.Fprintf(b, "tailstate_cleanup_duration_seconds_sum %.6f\ntailstate_cleanup_duration_seconds_count %d\n", cleanup.DurationSeconds, cleanup.Runs)
		metricFamily(b, "tailstate_cleanup_rows_total", "counter", "Rows removed or dead-lettered by retention cleanup, by table.")
		for _, row := range []struct {
			table string
			count uint64
		}{
			{"sessions", cleanup.SessionsDeleted},
			{"auth_tokens", cleanup.AuthTokensDeleted},
			{"meta", cleanup.MetaDeleted},
			{"outbox_dead_letter", cleanup.OutboxDeadLettered},
			{"webhook_dead_letter", cleanup.WebhookDeadLettered},
			{"events", cleanup.EventsDeleted},
			{"event_batches", cleanup.EventBatchesDeleted},
			{"event_batch_triggers", cleanup.EventBatchTriggersDeleted},
			{"webhook_triggers", cleanup.WebhookTriggersDeleted},
			{"delivered_outbox", cleanup.DeliveredOutboxDeleted},
			{"dead_outbox", cleanup.DeadOutboxDeleted},
			{"admin_audit", cleanup.AdminAuditDeleted},
			{"api_tokens", cleanup.APITokensDeleted},
		} {
			fmt.Fprintf(b, "tailstate_cleanup_rows_total{table=%q} %d\n", row.table, row.count)
		}
		attribution := s.engine.AttributionMetrics()
		metricFamily(b, "tailstate_attribution_lookups_total", "counter", "Configuration audit log lookups for change attribution, by outcome.")
		for _, row := range []struct {
			outcome string
			count   uint64
		}{
			{"complete", attribution.LookupsComplete},
			{"unsupported", attribution.LookupsUnsupported},
			{"failed", attribution.LookupsFailed},
		} {
			fmt.Fprintf(b, "tailstate_attribution_lookups_total{outcome=%q} %d\n", row.outcome, row.count)
		}
		metricFamily(b, "tailstate_attribution_changes_total", "counter", "Changes in attributed batches, by whether the audit log named an actor.")
		fmt.Fprintf(b, "tailstate_attribution_changes_total{result=\"matched\"} %d\ntailstate_attribution_changes_total{result=\"unknown\"} %d\n", attribution.ChangesMatched, attribution.ChangesUnknown)
	}
	metricValue(b, "tailstate_storage_bytes", "gauge", "Logical bytes allocated by the SQLite database, including free pages.", storage.DatabaseBytes)
	metricValue(b, "tailstate_storage_used_bytes", "gauge", "Logical bytes in use by the SQLite database, excluding free pages.", storage.DatabaseUsedBytes)
	metricValue(b, "tailstate_storage_freelist_pages", "gauge", "Free SQLite pages awaiting reuse or compaction.", storage.DatabaseFreelistPages)
	metricValue(b, "tailstate_storage_free_bytes", "gauge", "Bytes held by free SQLite pages.", storage.DatabaseFreeBytes)
	metricValue(b, "tailstate_storage_limit_bytes", "gauge", "Configured database budget.", storage.DatabaseLimitBytes)
	metricValue(b, "tailstate_storage_pressure_ratio", "gauge", "Used database bytes (excluding free pages) divided by the configured budget.", storage.PressureRatio())
	metricValue(b, "tailstate_storage_enforced_limit_bytes", "gauge", "Page ceiling SQLite enforces on the active connection.", storage.DatabaseEnforcedLimitBytes)
	metricValue(b, "tailstate_storage_limit_enforced", "gauge", "Whether the enforced page ceiling is within the configured database budget.", boolMetric(storage.LimitEnforced()))
	metricValue(b, "tailstate_storage_database_file_bytes", "gauge", "Physical bytes used by the main SQLite database file.", storage.DatabaseFileBytes)
	metricValue(b, "tailstate_storage_wal_bytes", "gauge", "Physical bytes used by the SQLite WAL sidecar.", storage.DatabaseWALBytes)
	metricValue(b, "tailstate_storage_shm_bytes", "gauge", "Physical bytes used by the SQLite shared-memory sidecar.", storage.DatabaseSHMBytes)
	metricValue(b, "tailstate_storage_physical_bytes", "gauge", "Total physical bytes used by the SQLite database and sidecars.", storage.DatabasePhysicalBytes)
	metricValue(b, "tailstate_snapshot_truncations_total", "counter", "Snapshots stored as a truncation marker.", storage.SnapshotTruncations)
	metricValue(b, "tailstate_event_value_truncations_total", "counter", "Event values stored as a truncation marker.", storage.EventValueTruncations)
	metricValue(b, "tailstate_history_page_truncations_total", "counter", "History pages truncated at the page byte limit.", storage.HistoryPageTruncations)
	metricValue(b, "tailstate_oversized_writes_rejected_total", "counter", "Oversized raw writes replaced by a metadata marker.", storage.OversizedWritesRejected)
	metricValue(b, "tailstate_snapshot_limit_bytes", "gauge", "Configured per-snapshot byte limit.", limits.SnapshotBytes)
	metricValue(b, "tailstate_event_value_limit_bytes", "gauge", "Configured per-event-value byte limit.", limits.EventValueBytes)
	metricValue(b, "tailstate_history_page_limit_bytes", "gauge", "Configured history page byte limit.", limits.HistoryPageBytes)
	metricValue(b, "tailstate_reject_limit_bytes", "gauge", "Configured raw-write rejection byte limit.", limits.RejectBytes)
	metricValue(b, "tailstate_webhook_triggers_pending", "gauge", "Verified webhook deliveries waiting for reconciliation.", status.WebhookPending)
	metricValue(b, "tailstate_webhook_triggers_processing", "gauge", "Verified webhook deliveries currently being reconciled.", status.WebhookProcessing)
	metricValue(b, "tailstate_webhook_triggers_dead", "gauge", "Verified webhook deliveries that exhausted their retry window.", status.WebhookDead)
	metricFamily(b, "tailstate_webhook_requests_total", "counter", "Tailscale webhook requests by outcome; content_fallback is an authentic delivery outside TailState's bounds that requested a full reconciliation.")
	for _, outcome := range webhookOutcomes {
		fmt.Fprintf(b, "tailstate_webhook_requests_total{outcome=%q} %d\n", outcome, s.webhookOutcomeCount(outcome))
	}
	state := diagnostics.NotificationStateFor(status.Configured, status.Destinations, status.EnabledDestinations)
	metricValue(b, "tailstate_notification_destinations", "gauge", "Notification destinations configured.", status.Destinations)
	metricValue(b, "tailstate_notification_destinations_enabled", "gauge", "Notification destinations enabled.", status.EnabledDestinations)
	metricValue(b, "tailstate_notifications_paused", "gauge", "Whether a configured installation is not delivering notifications (no destination, or every destination disabled).", boolMetric(state.Paused()))
	metricFamily(b, "tailstate_notification_state", "gauge", "Notification delivery state; exactly one state is 1.")
	for _, candidate := range diagnostics.NotificationStates {
		fmt.Fprintf(b, "tailstate_notification_state{state=%q} %d\n", candidate, boolMetric(candidate == state))
	}
	collectorFamilies := []struct{ name, help string }{
		{"tailstate_collector_supported", "Whether the collector is supported by the tailnet and credentials."},
		{"tailstate_collector_baseline", "Whether the collector has a baseline."},
		{"tailstate_collector_partial", "Whether the collector's last result was partial."},
		{"tailstate_collector_partial_errors", "Failed related requests in the collector's last partial result."},
		{"tailstate_collector_failures", "Consecutive collector failures."},
		{"tailstate_collector_poll_duration_seconds", "Duration of the collector's last poll."},
		{"tailstate_collector_last_success_timestamp_seconds", "Unix time of the collector's last successful poll."},
		{"tailstate_collector_next_poll_timestamp_seconds", "Unix time of the collector's next scheduled poll."},
	}
	for index, family := range collectorFamilies {
		metricFamily(b, family.name, "gauge", family.help)
		for _, collector := range status.Collectors {
			switch index {
			case 0:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, boolMetric(collector.Supported))
			case 1:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, boolMetric(collector.Baseline))
			case 2:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, boolMetric(collector.Partial))
			case 3:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.PartialErrorCount)
			case 4:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.FailureCount)
			case 5:
				fmt.Fprintf(b, "%s{collector=%q} %.3f\n", family.name, collector.Name, float64(collector.PollDurationMS)/1000)
			case 6:
				if collector.LastSuccess != nil {
					fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.LastSuccess.Unix())
				}
			case 7:
				if collector.NextPoll != nil {
					fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.NextPoll.Unix())
				}
			}
		}
	}
	metricFamily(b, "tailstate_resources", "gauge", "Resources in the current baseline, by collector.")
	collectors := make([]string, 0, len(status.ResourceCounts))
	for collector := range status.ResourceCounts {
		collectors = append(collectors, collector)
	}
	sort.Strings(collectors)
	for _, collector := range collectors {
		fmt.Fprintf(b, "tailstate_resources{collector=%q} %d\n", collector, status.ResourceCounts[collector])
	}
}

func (s *Server) metricsAuthorized(r *http.Request) bool {
	if s.config.MetricsToken != "" {
		const prefix = "Bearer "
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, prefix) {
			return false
		}
		provided := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
		if provided == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(provided), []byte(s.config.MetricsToken)) == 1
	}
	// A blank token is useful for local development, but is only valid on a
	// direct loopback connection. A reverse proxy is never a safe substitute:
	// forwarded headers can be omitted, malformed, or supplied by an untrusted
	// peer, so tokenless metrics fail closed whenever proxy provenance exists.
	remote := strings.TrimSpace(remoteIP(r))
	addr, err := netip.ParseAddr(remote)
	if err != nil || !addr.IsLoopback() || s.isTrustedProxy(remote) {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-Forwarded-For")) == "" && strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")) == ""
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}

package web

import (
	"net/http"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

type readinessCollector struct {
	Name              string `json:"name"`
	Supported         bool   `json:"supported"`
	Baseline          bool   `json:"baseline"`
	Partial           bool   `json:"partial"`
	PartialErrorCount int    `json:"partial_error_count"`
	PollDuration      int64  `json:"poll_duration_ms"`
	FailureCount      int    `json:"failure_count"`
	Reason            string `json:"reason,omitempty"`
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "configured": false, "baseline": false})
		return
	}
	collectors := make([]readinessCollector, 0, len(status.Collectors))
	for _, collector := range status.Collectors {
		collectors = append(collectors, readinessCollector{
			Name:              collector.Name,
			Supported:         collector.Supported,
			Baseline:          collector.Baseline,
			Partial:           collector.Partial,
			PartialErrorCount: collector.PartialErrorCount,
			PollDuration:      collector.PollDurationMS,
			FailureCount:      collector.FailureCount,
			Reason:            readinessCollectorReason(collector),
		})
	}
	state := "not_ready"
	code := http.StatusServiceUnavailable
	if status.Configured && status.BaselineReady {
		state = "ready"
		code = http.StatusOK
		if status.BaselineDegraded {
			state = "degraded"
		}
	}
	response := map[string]any{
		"status":          state,
		"configured":      status.Configured,
		"baseline":        status.BaselineReady,
		"degraded":        status.BaselineDegraded,
		"collectors":      collectors,
		"baseline_reason": status.BaselineReason,
	}
	if status.BaselineGraceUntil != nil {
		response["baseline_grace_until"] = status.BaselineGraceUntil.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, code, response)
}

// readinessCollectorReason is intentionally a bounded vocabulary. Collector
// errors can contain upstream response text, credentials, or tenant-controlled
// values; /readyz is unauthenticated and must never echo those details.
func readinessCollectorReason(collector store.CollectorState) string {
	switch {
	case !collector.Supported:
		return "unsupported"
	case collector.Partial:
		return "partial"
	case collector.FailureCount >= 1:
		return "retrying"
	case !collector.Baseline:
		return "baseline pending"
	default:
		return "healthy"
	}
}

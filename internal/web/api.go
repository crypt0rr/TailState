package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/store"
)

const (
	// apiRequestsPerWindow requests per apiRateWindow are allowed for each
	// API token; further requests receive 429 with Retry-After.
	apiRequestsPerWindow = 60
	apiRateWindow        = time.Minute
	maxTrackedAPITokens  = 1024
	apiRealm             = `Bearer realm="tailstate-api"`
)

// apiFailureThrottle buckets failed API authentications per client.
const apiFailureThrottle credentialAction = "api"

type apiWindow struct {
	start time.Time
	count int
}

// apiRateLimit reports whether token id has exhausted its request budget,
// and when the window reopens.
func (s *Server) apiRateLimit(id int64, now time.Time) (time.Duration, bool) {
	s.apiMu.Lock()
	defer s.apiMu.Unlock()
	if len(s.apiWindows) >= maxTrackedAPITokens {
		for key, window := range s.apiWindows {
			if now.Sub(window.start) >= apiRateWindow {
				delete(s.apiWindows, key)
			}
		}
	}
	window := s.apiWindows[id]
	if now.Sub(window.start) >= apiRateWindow {
		window = apiWindow{start: now}
	}
	if window.count >= apiRequestsPerWindow {
		s.apiWindows[id] = window
		return window.start.Add(apiRateWindow).Sub(now), true
	}
	window.count++
	s.apiWindows[id] = window
	return 0, false
}

func apiError(w http.ResponseWriter, code int, errorCode, description string) {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		w.Header().Set("WWW-Authenticate", apiRealm+`, error="`+errorCode+`"`)
	}
	writeJSON(w, code, map[string]string{"error": errorCode, "error_description": description})
}

func retryAfter(w http.ResponseWriter, wait time.Duration) {
	seconds := int64((wait + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
// Session cookies never authenticate an API request.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// apiAuthorize authenticates a bearer token and checks scope and rate
// limits. A valid token is never blocked by other clients' failures; failed
// authentications are throttled per client.
func (s *Server) apiAuthorize(w http.ResponseWriter, r *http.Request, scope string) bool {
	presented, ok := bearerToken(r)
	if !ok {
		apiError(w, http.StatusUnauthorized, "invalid_request", "Send the token as Authorization: Bearer <token>.")
		return false
	}
	token, err := s.store.AuthenticateAPIToken(r.Context(), presented)
	if err != nil {
		key := s.throttleKey(apiFailureThrottle, s.clientIP(r))
		if wait, limited := s.throttled(apiFailureThrottle, key); limited {
			retryAfter(w, wait)
			apiError(w, http.StatusTooManyRequests, "too_many_failures", "Too many failed authentications. Try again later.")
			return false
		}
		if !errors.Is(err, store.ErrAPITokenInvalid) {
			slog.Error("authenticate API token", "error", err)
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Authentication is temporarily unavailable.")
			return false
		}
		s.recordFailure(apiFailureThrottle, key)
		apiError(w, http.StatusUnauthorized, "invalid_token", "The token is invalid, revoked, or expired.")
		return false
	}
	if !token.HasScope(scope) {
		apiError(w, http.StatusForbidden, "insufficient_scope", "This endpoint requires the "+scope+" scope.")
		return false
	}
	if wait, limited := s.apiRateLimit(token.ID, time.Now()); limited {
		retryAfter(w, wait)
		apiError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests for this token. Try again later.")
		return false
	}
	return true
}

type apiCollector struct {
	Name              string     `json:"name"`
	Supported         bool       `json:"supported"`
	Baseline          bool       `json:"baseline"`
	Partial           bool       `json:"partial"`
	PartialErrorCount int        `json:"partial_error_count"`
	FailureCount      int        `json:"failure_count"`
	PollDurationMS    int64      `json:"poll_duration_ms"`
	LastSuccess       *time.Time `json:"last_success,omitempty"`
	NextPoll          *time.Time `json:"next_poll,omitempty"`
	Reason            string     `json:"reason"`
}

type apiQueue struct {
	Pending    int `json:"pending"`
	Processing int `json:"processing"`
	Dead       int `json:"dead"`
}

// apiStatusResponse is the machine-readable status. Collector errors are
// reduced to the bounded readiness vocabulary and destinations to counts, so
// no upstream text, URL, or secret can appear.
type apiStatusResponse struct {
	Version             string         `json:"version"`
	Configured          bool           `json:"configured"`
	BaselineReady       bool           `json:"baseline_ready"`
	Degraded            bool           `json:"degraded"`
	BaselineAt          *time.Time     `json:"baseline_at,omitempty"`
	NotificationState   string         `json:"notification_state"`
	Destinations        int            `json:"destinations"`
	EnabledDestinations int            `json:"enabled_destinations"`
	Notifications       apiQueue       `json:"notifications"`
	WebhookTriggers     apiQueue       `json:"webhook_triggers"`
	ResourceCounts      map[string]int `json:"resource_counts"`
	Collectors          []apiCollector `json:"collectors"`
	Attribution         apiAttribution `json:"attribution"`
}

// apiAttribution is the configuration audit log state used for change
// attribution: "supported", "unsupported", "failing", or "unchecked". The
// reason is a bounded label, never provider text.
type apiAttribution struct {
	State     string     `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, store.ScopeStatusRead) {
		return
	}
	status, err := s.store.Status(r.Context())
	if err != nil {
		slog.Error("load status for API", "error", err)
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Status is temporarily unavailable.")
		return
	}
	response := apiStatusResponse{
		Version:             s.config.Version,
		Configured:          status.Configured,
		BaselineReady:       status.BaselineReady,
		Degraded:            status.BaselineDegraded,
		BaselineAt:          status.BaselineAt,
		NotificationState:   string(diagnostics.NotificationStateFor(status.Configured, status.Destinations, status.EnabledDestinations)),
		Destinations:        status.Destinations,
		EnabledDestinations: status.EnabledDestinations,
		Notifications:       apiQueue{Pending: status.Pending, Processing: status.Processing, Dead: status.Dead},
		WebhookTriggers:     apiQueue{Pending: status.WebhookPending, Processing: status.WebhookProcessing, Dead: status.WebhookDead},
		ResourceCounts:      status.ResourceCounts,
		Collectors:          make([]apiCollector, 0, len(status.Collectors)),
	}
	response.Attribution = apiAttribution{State: "unchecked"}
	if source := status.Attribution; source.State != "" {
		checked := source.CheckedAt
		response.Attribution = apiAttribution{State: source.State, Reason: source.Reason, CheckedAt: &checked}
	}
	if response.ResourceCounts == nil {
		response.ResourceCounts = map[string]int{}
	}
	for _, collector := range status.Collectors {
		response.Collectors = append(response.Collectors, apiCollector{
			Name: collector.Name, Supported: collector.Supported, Baseline: collector.Baseline, Partial: collector.Partial,
			PartialErrorCount: collector.PartialErrorCount, FailureCount: collector.FailureCount, PollDurationMS: collector.PollDurationMS,
			LastSuccess: collector.LastSuccess, NextPoll: collector.NextPoll, Reason: readinessCollectorReason(collector),
		})
	}
	writeJSON(w, http.StatusOK, response)
}

type apiField struct {
	Field  string `json:"field"`
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
	HasOld bool   `json:"has_old"`
	HasNew bool   `json:"has_new"`
}

type apiEvent struct {
	ID              int64           `json:"id"`
	Collector       string          `json:"collector"`
	EventType       string          `json:"event_type"`
	ResourceID      string          `json:"resource_id"`
	Name            string          `json:"name"`
	Severity        string          `json:"severity"`
	Muted           bool            `json:"muted"`
	Fields          []apiField      `json:"fields"`
	FieldsTruncated bool            `json:"fields_truncated"`
	TotalFields     int             `json:"total_fields"`
	Before          json.RawMessage `json:"before,omitempty"`
	After           json.RawMessage `json:"after,omitempty"`
	BeforeHash      string          `json:"before_sha256,omitempty"`
	AfterHash       string          `json:"after_sha256,omitempty"`
	BeforeBytes     int64           `json:"before_bytes"`
	AfterBytes      int64           `json:"after_bytes"`
	BeforeTruncated bool            `json:"before_truncated"`
	AfterTruncated  bool            `json:"after_truncated"`
	// ChangedBy is the History "Changed by" text ("actor unknown" when the
	// audit log had no match); Attribution is the matching audit record.
	ChangedBy   string             `json:"changed_by,omitempty"`
	Attribution *model.Attribution `json:"attribution,omitempty"`
}

// apiDelivery reports a delivery by destination ID and display name only;
// the destination URL is never part of an API response.
type apiDelivery struct {
	DestinationID int64      `json:"destination_id"`
	Destination   string     `json:"destination"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	LastError     string     `json:"last_error,omitempty"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

type apiBatch struct {
	Type        string    `json:"type"`
	ID          int64     `json:"id"`
	Generation  int64     `json:"generation"`
	ObservedAt  time.Time `json:"observed_at"`
	ChangeCount int       `json:"change_count"`
	TriggerIDs  []int64   `json:"trigger_ids,omitempty"`
	LedgerSeq   int64     `json:"ledger_sequence,omitempty"`
	LedgerHash  string    `json:"ledger_hash,omitempty"`
	// AttributionStatus is the configuration audit lookup outcome.
	AttributionStatus string        `json:"attribution_status,omitempty"`
	Events            []apiEvent    `json:"events"`
	Deliveries        []apiDelivery `json:"deliveries"`
}

type apiPage struct {
	Type             string `json:"type"`
	Batches          int    `json:"batches"`
	HasNext          bool   `json:"has_next"`
	NextCursor       int64  `json:"next_cursor,omitempty"`
	Next             string `json:"next,omitempty"`
	HasPrev          bool   `json:"has_prev"`
	PrevCursor       int64  `json:"prev_cursor,omitempty"`
	Prev             string `json:"prev,omitempty"`
	Truncated        bool   `json:"truncated"`
	TruncationReason string `json:"truncation_reason,omitempty"`
	BytesRead        int64  `json:"bytes_read"`
	ByteLimit        int64  `json:"byte_limit"`
}

// rawJSON passes a normalized snapshot through when it is valid JSON and
// otherwise encodes it as a JSON string.
func rawJSON(value string) json.RawMessage {
	if value == "" {
		return nil
	}
	if json.Valid([]byte(value)) {
		return json.RawMessage(value)
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

// apiHistory streams one bounded History page as NDJSON: one "batch" line
// per change batch and a final "page" line with links to the adjacent older
// ("next", cursor=) and newer ("prev", after=) pages. Filters (collector,
// event_type, resource, severity, batch, from/to dates), paging, and the byte
// budget are the History page's own.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, store.ScopeHistoryRead) {
		return
	}
	if !historyDatesValid(r) {
		apiError(w, http.StatusBadRequest, "invalid_request", "Dates must use the YYYY-MM-DD format.")
		return
	}
	filter := historyFilter(r)
	if limit, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && limit > 0 {
		filter.Limit = min(limit, 100)
	}
	page, err := s.store.ListHistory(r.Context(), filter)
	if err != nil {
		slog.Error("load history for API", "error", err)
		apiError(w, http.StatusServiceUnavailable, "unavailable", "History is temporarily unavailable.")
		return
	}
	// Encode the whole page before writing, so a failure produces a clean
	// error instead of a truncated stream.
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, batch := range page.Batches {
		line := apiBatch{Type: "batch", ID: batch.ID, Generation: batch.Generation, ObservedAt: batch.ObservedAt, ChangeCount: batch.ChangeCount, TriggerIDs: batch.TriggerIDs, LedgerSeq: batch.LedgerSequence, LedgerHash: batch.LedgerHash, AttributionStatus: batch.AttributionStatus, Events: make([]apiEvent, 0, len(batch.Events)), Deliveries: make([]apiDelivery, 0, len(batch.Deliveries))}
		for _, event := range batch.Events {
			item := apiEvent{ID: event.ID, Collector: event.Collector, EventType: event.EventType, ResourceID: event.ResourceID, Name: event.Name, Severity: event.Severity, Muted: event.Muted, Fields: make([]apiField, 0, len(event.Fields)), FieldsTruncated: event.FieldsTruncated, TotalFields: event.TotalFields, Before: rawJSON(event.BeforeJSON), After: rawJSON(event.AfterJSON), BeforeHash: event.BeforeHash, AfterHash: event.AfterHash, BeforeBytes: event.BeforeBytes, AfterBytes: event.AfterBytes, BeforeTruncated: event.BeforeTruncated, AfterTruncated: event.AfterTruncated, ChangedBy: event.ChangedBy, Attribution: event.Attribution}
			for _, field := range event.Fields {
				item.Fields = append(item.Fields, apiField{Field: field.Field, Old: field.Old, New: field.New, HasOld: field.HasOld, HasNew: field.HasNew})
			}
			line.Events = append(line.Events, item)
		}
		for _, delivery := range batch.Deliveries {
			line.Deliveries = append(line.Deliveries, apiDelivery{DestinationID: delivery.DestinationID, Destination: delivery.Destination, Status: delivery.Status, Attempts: delivery.Attempts, LastError: delivery.LastError, DeliveredAt: delivery.DeliveredAt})
		}
		if err := encoder.Encode(line); err != nil {
			slog.Error("encode history for API", "error", err)
			apiError(w, http.StatusInternalServerError, "encoding_failed", "History could not be encoded.")
			return
		}
	}
	trailer := apiPage{Type: "page", Batches: len(page.Batches), HasNext: page.HasNext, Truncated: page.Truncated, TruncationReason: page.TruncationReason, BytesRead: page.BytesRead, ByteLimit: page.ByteLimit}
	link := func(key string, value int64) string {
		values := historyQuery(filter)
		values.Set(key, strconv.FormatInt(value, 10))
		values.Set("limit", strconv.Itoa(filter.Limit))
		return "/api/v1/history?" + values.Encode()
	}
	if page.HasNext {
		trailer.NextCursor = page.NextCursor
		trailer.Next = link("cursor", page.NextCursor)
	}
	if page.HasPrev {
		trailer.HasPrev = true
		trailer.PrevCursor = page.PrevCursor
		trailer.Prev = link("after", page.PrevCursor)
	}
	_ = encoder.Encode(trailer)
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	_, _ = w.Write(body.Bytes())
}

// apiEvidence returns the signed evidence pack for the History filters,
// exactly as the History page's download does.
func (s *Server) apiEvidence(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, store.ScopeEvidenceRead) {
		return
	}
	if !historyDatesValid(r) {
		apiError(w, http.StatusBadRequest, "invalid_request", "Dates must use the YYYY-MM-DD format.")
		return
	}
	pack, err := s.store.ExportEvidencePack(r.Context(), historyFilter(r))
	if err != nil {
		if errors.Is(err, store.ErrEvidencePackTooLarge) {
			apiError(w, http.StatusRequestEntityTooLarge, "too_large", "The evidence pack is too large; narrow the filters.")
			return
		}
		slog.Error("export evidence for API", "error", err)
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Evidence is temporarily unavailable.")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(pack)
}

// apiTokenLifetimes are the expiry choices offered in Settings, in days.
var apiTokenLifetimes = []int{30, 90, 180, 365}

// apiTokenPost creates or revokes an API token. Every outcome is reported
// with Post/Redirect/Get. A new token's secret is handed to the next
// Settings view through a one-time, in-memory reveal (see tokenReveals), so
// it is never persisted, never placed in a URL or cookie, and a reload does
// not show it again.
func (s *Server) apiTokenPost(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	ctx := r.Context()
	switch r.FormValue("action") {
	case "create":
		days, err := strconv.Atoi(r.FormValue("expires_days"))
		if err != nil {
			days = 0
		}
		before := s.enabledDestinations(ctx)
		token, secretValue, err := s.store.CreateAPIToken(ctx, r.FormValue("name"), r.Form["scopes"], time.Duration(days)*24*time.Hour)
		if err != nil {
			s.redirectWithFlash(w, r, "/settings", flashKindError, "API token was not created: "+apiTokenMessage(err)+".")
			return
		}
		// A new token opens a read path to history and evidence, so it is
		// a high-risk change.
		s.recordAdmin(r, auth.ref, adminChange{event: store.AuditAPITokenCreated, target: "api_token:" + strconv.FormatInt(token.ID, 10), fields: []string{"expires_at", "name", "scopes"}, highRisk: true}, before, 0)
		reveal, err := s.tokenReveals.put(secretValue, auth.ref, time.Now())
		if err != nil {
			slog.Error("hold new API token for display", "error", err)
			s.redirectWithFlash(w, r, "/settings", flashKindError, "API token "+token.Name+" was created but could not be displayed. Revoke it and create another.")
			return
		}
		s.setFlashWith(w, flashMessage{Kind: flashKindSuccess, Message: "API token " + token.Name + " created. Copy it now: it is shown only once.", Reveal: reveal})
		http.Redirect(w, r, "/settings#new-api-token", http.StatusSeeOther)
	case "revoke":
		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err := s.store.RevokeAPIToken(ctx, id); err != nil {
			s.redirectWithFlash(w, r, "/settings", flashKindError, "API token was not revoked: "+apiTokenMessage(err)+".")
			return
		}
		s.recordAdmin(r, auth.ref, adminChange{event: store.AuditAPITokenRevoked, target: "api_token:" + strconv.FormatInt(id, 10)}, nil, 0)
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, "API token revoked. Requests that present it are refused from now on.")
	default:
		http.Error(w, "unknown API token action", http.StatusBadRequest)
	}
}

// apiTokenMessage keeps validation messages and hides storage details.
func apiTokenMessage(err error) string {
	if errors.Is(err, store.ErrAPITokenRequest) {
		return strings.TrimPrefix(err.Error(), store.ErrAPITokenRequest.Error()+": ")
	}
	slog.Error("API token operation", "error", err)
	return "the token could not be stored"
}

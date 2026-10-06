package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/store"
)

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, false)
	if !ok {
		return
	}
	filter := historyFilter(r)
	dateError := historyDateError(r)
	history, err := s.store.ListHistory(r.Context(), filter)
	if err != nil {
		http.Error(w, "load history", http.StatusInternalServerError)
		return
	}
	data := pageData{
		CSRF:              csrf,
		History:           history,
		HistoryFilter:     filter,
		HistoryCollectors: knownCollectors(),
		HistoryEventTypes: []string{"created", "changed", "removed"},
		HistorySeverities: []string{string(model.SeverityHigh), string(model.SeverityMedium), string(model.SeverityLow)},
		Error:             dateError,
	}
	data.HistoryFrom, data.HistoryTo = historyDateValues(filter)
	data.EvidenceSigningKeyID, _ = s.store.EvidenceSigningKeyID(r.Context())
	if history.HasNext {
		data.HistoryNextURL = historyURL(filter, history.NextCursor)
	}
	if history.HasPrev {
		data.HistoryPrevURL = historyNewerURL(filter, history.PrevCursor)
	}
	data.HistoryExportURL = historyExportURL(filter)
	data.HistoryExportFields = historyExportFields(filter)
	s.render(w, "history", data)
}

func (s *Server) historyExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r, false); !ok {
		return
	}
	filter := historyFilter(r)
	// Exports default to the largest pack; a smaller "limit" is honored so a
	// script can request smaller parts.
	filter.Limit = 0
	if limit, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && limit > 0 {
		filter.Limit = limit
	}
	pack, err := s.store.ExportEvidencePack(r.Context(), filter)
	if err != nil {
		if errors.Is(err, store.ErrEvidencePackTooLarge) {
			http.Error(w, "history export is too large: the newest matching batch alone exceeds the evidence pack size limit; narrow the filters and try again", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "export history", http.StatusInternalServerError)
		return
	}
	filename := "tailstate-drift-evidence-" + time.Now().UTC().Format("20060102T150405Z")
	var part struct {
		Truncated  bool  `json:"truncated"`
		NextCursor int64 `json:"next_cursor"`
	}
	if err := json.Unmarshal(pack, &part); err == nil && part.Truncated && part.NextCursor > 0 {
		// A partial pack names its continuation cursor in the file name and
		// in headers, so the operator (or a script following rel="next") can
		// request the next part with the same filters.
		next := strconv.FormatInt(part.NextCursor, 10)
		filename += "-next-" + next
		w.Header().Set("X-TailState-Evidence-Next-Cursor", next)
		w.Header().Set("Link", "<"+historyExportPartURL(filter, part.NextCursor, filter.Limit)+`>; rel="next"`)
	}
	filename += ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pack)
}

// historyDateLayout is the format of the History page's from/to date
// filters (an HTML date input). Dates are whole UTC days; "to" is inclusive.
const historyDateLayout = "2006-01-02"

func historyFilter(r *http.Request) store.HistoryFilter {
	query := r.URL.Query()
	filter := store.HistoryFilter{
		Collector:  strings.TrimSpace(query.Get("collector")),
		EventType:  strings.TrimSpace(query.Get("event_type")),
		ResourceID: strings.TrimSpace(query.Get("resource")),
		Limit:      20,
	}
	if cursor, err := strconv.ParseInt(query.Get("cursor"), 10, 64); err == nil && cursor > 0 {
		filter.Cursor = cursor
	}
	if batch, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("batch")), 10, 64); err == nil && batch > 0 {
		filter.BatchID = batch
	}
	if severity, ok := model.ParseSeverity(r.URL.Query().Get("severity")); ok {
		filter.Severity = string(severity)
	}
	if after, err := strconv.ParseInt(query.Get("after"), 10, 64); err == nil && after > 0 && filter.Cursor == 0 {
		filter.After = after
	}
	if from, err := time.Parse(historyDateLayout, strings.TrimSpace(query.Get("from"))); err == nil {
		filter.From = from
	}
	if to, err := time.Parse(historyDateLayout, strings.TrimSpace(query.Get("to"))); err == nil {
		filter.Until = to.AddDate(0, 0, 1)
	}
	return filter
}

// historyDateError explains a date filter that historyFilter ignored or
// that cannot match anything.
func historyDateError(r *http.Request) string {
	query := r.URL.Query()
	var parsed [2]time.Time
	for index, name := range []string{"from", "to"} {
		value := strings.TrimSpace(query.Get(name))
		if value == "" {
			continue
		}
		date, err := time.Parse(historyDateLayout, value)
		if err != nil {
			return "Dates must use the YYYY-MM-DD format; the invalid date was ignored."
		}
		parsed[index] = date
	}
	if !parsed[0].IsZero() && !parsed[1].IsZero() && parsed[1].Before(parsed[0]) {
		return "The end date is before the start date, so no changes can match."
	}
	return ""
}

// historyDatesValid reports whether every supplied from/to date parses. The
// History page ignores an invalid date and explains why; the API refuses it,
// because a client would otherwise silently receive an unfiltered page.
func historyDatesValid(r *http.Request) bool {
	query := r.URL.Query()
	for _, name := range []string{"from", "to"} {
		if value := strings.TrimSpace(query.Get(name)); value != "" {
			if _, err := time.Parse(historyDateLayout, value); err != nil {
				return false
			}
		}
	}
	return true
}

// historyDateValues returns the from/to form values for a filter.
func historyDateValues(filter store.HistoryFilter) (string, string) {
	var from, to string
	if !filter.From.IsZero() {
		from = filter.From.UTC().Format(historyDateLayout)
	}
	if !filter.Until.IsZero() {
		to = filter.Until.UTC().AddDate(0, 0, -1).Format(historyDateLayout)
	}
	return from, to
}

// historyQuery encodes the filters shared by page links and exports.
func historyQuery(filter store.HistoryFilter) url.Values {
	values := url.Values{}
	if filter.BatchID > 0 {
		values.Set("batch", strconv.FormatInt(filter.BatchID, 10))
	}
	if filter.Collector != "" {
		values.Set("collector", filter.Collector)
	}
	if filter.EventType != "" {
		values.Set("event_type", filter.EventType)
	}
	if filter.ResourceID != "" {
		values.Set("resource", filter.ResourceID)
	}
	if filter.Severity != "" {
		values.Set("severity", filter.Severity)
	}
	from, to := historyDateValues(filter)
	if from != "" {
		values.Set("from", from)
	}
	if to != "" {
		values.Set("to", to)
	}
	return values
}

// historyURL links to the page of batches older than cursor.
func historyURL(filter store.HistoryFilter, cursor int64) string {
	values := historyQuery(filter)
	values.Set("cursor", strconv.FormatInt(cursor, 10))
	return "/history?" + values.Encode()
}

// historyNewerURL links to the page of batches newer than after.
func historyNewerURL(filter store.HistoryFilter, after int64) string {
	values := historyQuery(filter)
	values.Set("after", strconv.FormatInt(after, 10))
	return "/history?" + values.Encode()
}

// historyExportPartURL requests the evidence pack part that follows a
// partial pack whose next_cursor is cursor, keeping the same filters.
func historyExportPartURL(filter store.HistoryFilter, cursor int64, limit int) string {
	values := historyQuery(filter)
	values.Set("cursor", strconv.FormatInt(cursor, 10))
	if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
	return "/history/export?" + values.Encode()
}

// historyExportField is a hidden form field that carries a History filter
// into the "Download next part" form.
type historyExportField struct {
	Name  string
	Value string
}

func historyExportFields(filter store.HistoryFilter) []historyExportField {
	values := historyQuery(filter)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]historyExportField, 0, len(names))
	for _, name := range names {
		fields = append(fields, historyExportField{Name: name, Value: values.Get(name)})
	}
	return fields
}

func historyExportURL(filter store.HistoryFilter) string {
	values := historyQuery(filter)
	if filter.Cursor > 0 {
		values.Set("cursor", strconv.FormatInt(filter.Cursor, 10))
	}
	if encoded := values.Encode(); encoded != "" {
		return "/history/export?" + encoded
	}
	return "/history/export"
}

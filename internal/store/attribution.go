package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

// Attribution lookup outcomes recorded on each change batch.
const (
	// AttributionComplete means the configuration audit log was read for the
	// batch window; a change without a matching entry is "actor unknown".
	AttributionComplete = "complete"
	// AttributionUnavailable means the lookup failed or exceeded its time
	// budget; every change of the batch is "actor unknown".
	AttributionUnavailable = "unavailable"
	// AttributionUnsupported means the audit log answered 403 or 404; the
	// batch carries no attribution and nothing is shown.
	AttributionUnsupported = "unsupported"
)

const (
	// DefaultAttributionBudget bounds one configuration audit lookup. The
	// lookup runs before the batch transaction, so it can delay a batch by at
	// most this long and never fails it.
	DefaultAttributionBudget = 10 * time.Second
	// AttributionClockSkew widens the lookup window on both sides and is the
	// tolerance for audit timestamps after the poll observed the change.
	AttributionClockSkew = 2 * time.Minute
	// MaxAttributionWindow bounds the lookup window after a long outage.
	MaxAttributionWindow = 24 * time.Hour
)

// AttributionWindow is the audit time range searched for one batch.
type AttributionWindow struct {
	Start time.Time
	End   time.Time
}

// AttributionResult is the outcome of one configuration audit lookup.
// Entries are used only to correlate changes in memory; only the bounded
// model.Attribution of a matching entry is stored.
type AttributionResult struct {
	Status  string
	Entries []model.AuditEntry
}

// AttributionLookup reads configuration audit entries for a window. It must
// honor ctx, which carries the lookup budget.
type AttributionLookup func(ctx context.Context, window AttributionWindow) AttributionResult

// BatchOptions configures optional work around ApplyBatchWithOptions.
type BatchOptions struct {
	// Attribute enables change attribution. It is called at most once, only
	// when the poll can produce a change, before the write transaction.
	Attribute AttributionLookup
	// Budget bounds Attribute; zero uses DefaultAttributionBudget.
	Budget time.Duration
	// RemovalLookback widens the window for a removal, which is confirmed
	// one poll after the resource first went missing. Use the polling
	// interval of the affected collectors.
	RemovalLookback time.Duration
}

// attributionShown reports whether a batch status renders "Changed by":
// a complete lookup names the actor or "actor unknown", and a failed lookup
// shows "actor unknown". Unsupported or absent lookups degrade silently.
func attributionShown(status string) bool {
	return status == AttributionComplete || status == AttributionUnavailable
}

// ChangedBy is the "Changed by" text of an event for a batch attribution
// status, or "" when nothing is shown.
func ChangedBy(attribution *model.Attribution, status string) string {
	if attribution != nil && !attribution.IsZero() {
		return attribution.Display()
	}
	if attributionShown(status) {
		return model.ActorUnknown
	}
	return ""
}

type snapshotProbe struct {
	hash    string
	missing int
}

// attributionWindow decides, without opening a write transaction, whether
// the results can produce a change and, if so, the audit window to search:
// from the previous successful poll of the affected collectors (minus the
// clock-skew tolerance, and minus the removal lookback when a resource is
// about to be confirmed removed) to now plus the tolerance, at most
// MaxAttributionWindow long.
func (s *Store) attributionWindow(ctx context.Context, generation int64, results []model.Collected, canonical [][]canonicalResource, removalLookback time.Duration, now time.Time) (AttributionWindow, bool, error) {
	db := s.readDB()
	var start time.Time
	needed := false
	for index, result := range results {
		if result.Error != nil || result.Unsupported {
			continue
		}
		var baseline int
		var lastSuccess string
		err := db.QueryRowContext(ctx, "SELECT baseline,COALESCE(last_success,'') FROM collector_state WHERE generation=? AND collector=?", generation, result.Collector).Scan(&baseline, &lastSuccess)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && baseline != 1) {
			continue
		}
		if err != nil {
			return AttributionWindow{}, false, err
		}
		stored, err := probeSnapshots(ctx, db, generation, result.Collector)
		if err != nil {
			return AttributionWindow{}, false, err
		}
		changed, removal := false, false
		for resourceIndex, resource := range result.Resources {
			previous, ok := stored[resource.ID]
			if !ok || previous.hash != canonical[index][resourceIndex].hash {
				changed = true
			}
			delete(stored, resource.ID)
		}
		if !result.Partial {
			for _, previous := range stored {
				if previous.missing >= 1 {
					removal = true
				}
			}
		}
		if !changed && !removal {
			continue
		}
		needed = true
		since := now.Add(-MaxAttributionWindow)
		if parsed, parseErr := time.Parse(time.RFC3339Nano, lastSuccess); parseErr == nil {
			since = parsed
		}
		if removal {
			// A removal held back by the mass-removal guard is confirmed up
			// to two polls later than usual; search from the last
			// successful poll before the guard engaged.
			guardedSince, guardErr := removalGuardSince(ctx, db, generation, result.Collector)
			if guardErr != nil {
				return AttributionWindow{}, false, guardErr
			}
			if !guardedSince.IsZero() && guardedSince.Before(since) {
				since = guardedSince
			}
		}
		since = since.Add(-AttributionClockSkew)
		if removal {
			since = since.Add(-max(removalLookback, 0))
		}
		if start.IsZero() || since.Before(start) {
			start = since
		}
	}
	if !needed {
		return AttributionWindow{}, false, nil
	}
	end := now.Add(AttributionClockSkew)
	if earliest := end.Add(-MaxAttributionWindow); start.Before(earliest) {
		start = earliest
	}
	return AttributionWindow{Start: start.UTC(), End: end.UTC()}, true, nil
}

// removalGuardSince returns the last successful poll of a collector before
// its mass-removal guard engaged, or the zero time when no guard of this
// generation is awaiting its removals.
func removalGuardSince(ctx context.Context, db *sql.DB, generation int64, collector string) (time.Time, error) {
	var value string
	err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", removalGuardMetaPrefix+collector).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	markedGeneration, since, ok := strings.Cut(value, " ")
	if !ok || markedGeneration != fmt.Sprint(generation) {
		return time.Time{}, nil
	}
	parsed, parseErr := time.Parse(time.RFC3339Nano, since)
	if parseErr != nil {
		return time.Time{}, nil
	}
	return parsed, nil
}

func probeSnapshots(ctx context.Context, db *sql.DB, generation int64, collector string) (map[string]snapshotProbe, error) {
	rows, err := db.QueryContext(ctx, "SELECT resource_id,content_hash,missing_count FROM snapshots WHERE generation=? AND collector=?", generation, collector)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]snapshotProbe{}
	for rows.Next() {
		var id string
		var probe snapshotProbe
		if err := rows.Scan(&id, &probe.hash, &probe.missing); err != nil {
			return nil, err
		}
		out[id] = probe
	}
	return out, rows.Err()
}

// lookupAttribution runs the optional attribution lookup within its budget.
// It never returns an error: a failed probe skips attribution, and a lookup
// that overruns its budget is reported as unavailable.
func (s *Store) lookupAttribution(ctx context.Context, generation int64, results []model.Collected, canonical [][]canonicalResource, options BatchOptions, now time.Time) (AttributionResult, AttributionWindow) {
	if options.Attribute == nil {
		return AttributionResult{}, AttributionWindow{}
	}
	window, needed, err := s.attributionWindow(ctx, generation, results, canonical, options.RemovalLookback, now)
	if err != nil {
		slog.Warn("attribution window could not be determined", "error", err)
		return AttributionResult{}, AttributionWindow{}
	}
	if !needed {
		return AttributionResult{}, AttributionWindow{}
	}
	budget := options.Budget
	if budget <= 0 {
		budget = DefaultAttributionBudget
	}
	lookupCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	result := options.Attribute(lookupCtx, window)
	switch result.Status {
	case AttributionComplete, AttributionUnsupported:
	default:
		result.Status = AttributionUnavailable
	}
	if lookupCtx.Err() != nil && result.Status == AttributionComplete {
		// A lookup that returned after its budget is not trusted to be
		// complete for the window.
		result = AttributionResult{Status: AttributionUnavailable}
	}
	if result.Status != AttributionComplete {
		result.Entries = nil
	}
	return result, window
}

// attributeChange correlates one recorded change with the looked-up entries
// inside the window. observed is when the change's collector was fetched:
// the latest matching entry at or before it explains the change, and an
// entry within the clock-skew tolerance after it is used only when none
// does, so an edit made after the fetch (while later collectors of the poll
// were still being fetched) is not credited with the change.
//
// related are further snapshots of the changed resource that identify it
// (see model.Attribute).
func attributeChange(entry recordedChange, lookup AttributionResult, window AttributionWindow, observed time.Time, related ...[]byte) *model.Attribution {
	if lookup.Status != AttributionComplete || len(lookup.Entries) == 0 {
		return nil
	}
	entries := make([]model.AuditEntry, 0, len(lookup.Entries))
	for _, candidate := range lookup.Entries {
		if candidate.EventTime.Before(window.Start) {
			continue
		}
		entries = append(entries, candidate)
	}
	attribution, ok := model.Attribute(entry.Change, entry.Before.raw, entry.After.raw, entries, observed, related...)
	if !ok {
		attribution, ok = model.Attribute(entry.Change, entry.Before.raw, entry.After.raw, entries, observed.Add(AttributionClockSkew), related...)
	}
	if !ok {
		return nil
	}
	return &attribution
}

// Attribution source states recorded for the status page.
const (
	AttributionSourceSupported   = "supported"
	AttributionSourceUnsupported = "unsupported"
	AttributionSourceFailing     = "failing"
)

// attributionSourceMeta stores the configuration audit log state for the
// status page. It lives in meta: the state is operational, not history.
const attributionSourceMeta = "config_audit_source"

// AttributionSourceRecheck is how long an unsupported audit log is left
// alone before it is tried again (as for unsupported collectors).
const AttributionSourceRecheck = 6 * time.Hour

// AttributionSource is the last known state of the configuration audit log
// used for change attribution.
type AttributionSource struct {
	Generation int64     `json:"generation"`
	Scopes     string    `json:"scopes"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
	NextCheck  time.Time `json:"next_check,omitzero"`
}

// Checked reports whether the source has been tried for this generation and
// OAuth scope set.
func (a AttributionSource) Checked(generation int64, scopes string) bool {
	return a.State != "" && a.Generation == generation && a.Scopes == scopes
}

// RecordAttributionSource stores the latest attribution source state. The
// reason must be a bounded label, never provider text.
func (s *Store) RecordAttributionSource(ctx context.Context, source AttributionSource) error {
	switch source.State {
	case AttributionSourceSupported, AttributionSourceUnsupported, AttributionSourceFailing:
	default:
		return fmt.Errorf("invalid attribution source state %q", source.State)
	}
	source.Reason = truncate(strings.TrimSpace(source.Reason), 160)
	source.CheckedAt = source.CheckedAt.UTC()
	source.NextCheck = source.NextCheck.UTC()
	raw, err := json.Marshal(source)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", attributionSourceMeta, string(raw))
	return err
}

// AttributionSource returns the stored attribution source state, or the
// zero value when none was recorded or it is unreadable.
func (s *Store) AttributionSource(ctx context.Context) (AttributionSource, error) {
	return readAttributionSource(ctx, s.readDB())
}

func readAttributionSource(ctx context.Context, db *sql.DB) (AttributionSource, error) {
	var raw string
	err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", attributionSourceMeta).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return AttributionSource{}, nil
	}
	if err != nil {
		return AttributionSource{}, err
	}
	var source AttributionSource
	if json.Unmarshal([]byte(raw), &source) != nil {
		return AttributionSource{}, nil
	}
	return source, nil
}

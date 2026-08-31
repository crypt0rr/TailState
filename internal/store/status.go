package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/textutil"
)

func (s *Store) Status(ctx context.Context) (Status, error) {
	out := Status{ResourceCounts: map[string]int{}}
	var baseline, configured string
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(baseline_at,''),configured_at FROM settings WHERE id=1").Scan(&baseline, &configured)
	if err == nil {
		out.Configured = true
		if baseline != "" {
			t, parseErr := time.Parse(time.RFC3339Nano, baseline)
			if parseErr != nil {
				return out, fmt.Errorf("parse status baseline timestamp: %w", parseErr)
			}
			out.BaselineAt = &t
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if out.Configured {
		generation, err := s.currentGeneration(ctx)
		if err != nil {
			return out, fmt.Errorf("load settings generation for status: %w", err)
		}
		rows, err := s.db.QueryContext(ctx, "SELECT collector,COUNT(*) FROM snapshots WHERE generation=? GROUP BY collector", generation)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return out, err
			}
			out.ResourceCounts[k] = n
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return out, err
		}
		if err := rows.Close(); err != nil {
			return out, err
		}
		rows, err = s.db.QueryContext(ctx, "SELECT collector,supported,baseline,COALESCE(last_success,''),last_error,failure_count,COALESCE(next_poll,''),poll_duration_ms,partial,partial_error_count FROM collector_state WHERE generation=? ORDER BY collector", generation)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var c CollectorState
			var last, next string
			var supported, baseline, partial int
			if err := rows.Scan(&c.Name, &supported, &baseline, &last, &c.LastError, &c.FailureCount, &next, &c.PollDurationMS, &partial, &c.PartialErrorCount); err != nil {
				rows.Close()
				return out, err
			}
			c.Supported = supported == 1
			c.Baseline = baseline == 1
			c.Partial = partial == 1
			if last != "" {
				t, parseErr := time.Parse(time.RFC3339Nano, last)
				if parseErr != nil {
					rows.Close()
					return out, fmt.Errorf("parse collector success timestamp: %w", parseErr)
				}
				c.LastSuccess = &t
			}
			if next != "" {
				t, parseErr := time.Parse(time.RFC3339Nano, next)
				if parseErr != nil {
					rows.Close()
					return out, fmt.Errorf("parse collector next poll timestamp: %w", parseErr)
				}
				c.NextPoll = &t
			}
			out.Collectors = append(out.Collectors, c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return out, err
		}
		if err := rows.Close(); err != nil {
			return out, err
		}
		pending := make([]string, 0)
		hasBaseline := false
		for _, collector := range out.Collectors {
			if collector.Supported && collector.Baseline {
				hasBaseline = true
				continue
			}
			if collector.Supported && !collector.Baseline {
				pending = append(pending, collector.Name)
			}
		}
		out.BaselineReady = hasBaseline
		configuredAt, parseErr := time.Parse(time.RFC3339Nano, configured)
		if parseErr != nil {
			return out, fmt.Errorf("parse settings configured timestamp: %w", parseErr)
		}
		graceUntil := configuredAt.Add(baselineGracePeriod)
		out.BaselineGraceUntil = &graceUntil
		if !time.Now().UTC().Before(graceUntil) && (!hasBaseline || len(pending) > 0) {
			out.BaselineReady = true
			out.BaselineDegraded = true
			if len(pending) == 0 {
				out.BaselineReason = "baseline grace period expired; no collector has completed a baseline"
			} else {
				out.BaselineReason = "baseline grace period expired; waiting for: " + strings.Join(pending, ", ")
			}
		}
	}
	if out.BaselineAt != nil {
		out.BaselineReady = true
		out.BaselineGraceUntil = nil
		out.BaselineDegraded, out.BaselineReason = postBaselineDegradation(out.Collectors)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='pending'").Scan(&out.Pending); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='processing'").Scan(&out.Processing); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='dead'").Scan(&out.Dead); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE deleted_at IS NULL").Scan(&out.Destinations); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE deleted_at IS NULL AND enabled=1").Scan(&out.EnabledDestinations); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_triggers WHERE status='pending'").Scan(&out.WebhookPending); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_triggers WHERE status='processing'").Scan(&out.WebhookProcessing); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_triggers WHERE status='dead'").Scan(&out.WebhookDead); err != nil {
		return out, err
	}
	return out, nil
}

// postBaselineDegradation keeps a historical baseline usable while making
// current collector health visible. A baseline timestamp is a statement about
// the first complete observation; it must not hide a later supported collector
// failure, partial response, or newly added collector waiting for its first
// observation. Confirmed unsupported collectors are intentionally excluded:
// those are plan-capability states, not transient monitoring failures.
func postBaselineDegradation(collectors []CollectorState) (bool, string) {
	degraded := make([]string, 0)
	for _, collector := range collectors {
		if !collector.Supported || (collector.Baseline && !collector.Partial && collector.FailureCount == 0) {
			continue
		}
		if strings.TrimSpace(collector.Name) == "" {
			degraded = append(degraded, "unknown")
			continue
		}
		degraded = append(degraded, collector.Name)
	}
	if len(degraded) == 0 {
		return false, ""
	}
	reason := "collector health degraded: " + strings.Join(degraded, ", ")
	return true, textutil.Truncate(reason, 200)
}

func (s *Store) currentGeneration(ctx context.Context) (int64, error) {
	var generation int64
	if err := s.db.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&generation); err != nil {
		return 0, err
	}
	return generation, nil
}

// SettingsGeneration reads only the non-secret generation marker. The
// monitor uses it for its idle loop so ordinary timer wakeups do not decrypt
// OAuth and webhook credentials repeatedly.
func (s *Store) SettingsGeneration(ctx context.Context) (int64, error) {
	return s.currentGeneration(ctx)
}

// SettingsRevision reads only the non-secret settings change marker. Unlike
// Generation, this value changes for credential and polling updates that must
// not discard the inventory baseline. The monitor uses it to refresh its
// cached client without decrypting settings on every idle scheduler wake.
func (s *Store) SettingsRevision(ctx context.Context) (string, error) {
	var revision string
	if err := s.db.QueryRowContext(ctx, "SELECT configured_at FROM settings WHERE id=1").Scan(&revision); err != nil {
		return "", err
	}
	return revision, nil
}

// SetNextPollErr schedules collectors without mutating the caller's slice and
// returns persistence failures to the monitor so they can be surfaced.
func (s *Store) SetNextPollErr(ctx context.Context, generation int64, collectors []string, next time.Time) error {
	ordered := sortedUnique(collectors)
	if len(ordered) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&activeGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if activeGeneration != generation {
		return nil
	}
	value := next.UTC().Format(time.RFC3339Nano)
	args := make([]any, 0, len(ordered)*3)
	placeholders := make([]string, 0, len(ordered))
	for _, collector := range ordered {
		placeholders = append(placeholders, "(?,?,?)")
		args = append(args, generation, collector, value)
	}
	query := `INSERT INTO collector_state(generation,collector,next_poll) VALUES ` + strings.Join(placeholders, ",") + `
		ON CONFLICT(generation,collector) DO UPDATE SET next_poll=excluded.next_poll`
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// EarliestCollectorDue returns the soonest persisted poll deadline for the
// supplied collectors. A zero time with found=true means at least one
// collector is due immediately (its next_poll column is empty). The monitor
// uses this to wake for short confirmation/retry windows even when the normal
// inventory interval is much longer.
func (s *Store) EarliestCollectorDue(ctx context.Context, generation int64, collectors []string) (deadline time.Time, found bool, err error) {
	ordered := sortedUnique(collectors)
	if len(ordered) == 0 {
		return time.Time{}, false, nil
	}
	placeholders := make([]string, 0, len(ordered))
	args := make([]any, 0, len(ordered)+1)
	args = append(args, generation)
	for _, collector := range ordered {
		placeholders = append(placeholders, "?")
		args = append(args, collector)
	}
	rows, err := s.db.QueryContext(ctx, "SELECT COALESCE(next_poll,'') FROM collector_state WHERE generation=? AND collector IN ("+strings.Join(placeholders, ",")+")", args...)
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return time.Time{}, false, err
		}
		if raw == "" {
			return time.Time{}, true, nil
		}
		value, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("parse collector next poll timestamp: %w", err)
		}
		if !found || value.Before(deadline) {
			deadline = value
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, false, err
	}
	if err := rows.Close(); err != nil {
		return time.Time{}, false, err
	}
	return deadline, found, nil
}

// CollectorDueWithError reports whether a collector is due and preserves
// database errors for callers that need to surface a degraded scheduler.
func (s *Store) CollectorDueWithError(ctx context.Context, generation int64, collector string) (bool, error) {
	var next string
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(next_poll,'') FROM collector_state WHERE generation=? AND collector=?", generation, collector).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	if next == "" {
		return true, nil
	}
	when, err := time.Parse(time.RFC3339Nano, next)
	if err != nil {
		return true, err
	}
	return !when.After(time.Now()), nil
}

// RecordCollectorPoll stores bounded operational telemetry for the latest
// attempt. It is deliberately separate from ApplyBatch so failed upstream
// requests still expose their duration without changing snapshot state.
func (s *Store) RecordCollectorPoll(ctx context.Context, generation int64, collector string, duration time.Duration, partial bool) error {
	if duration < 0 {
		duration = 0
	}
	_, err := s.db.ExecContext(ctx, "UPDATE collector_state SET poll_duration_ms=?,partial=? WHERE generation=? AND collector=?", duration.Milliseconds(), boolInt(partial), generation, collector)
	return err
}

const (
	// Cleanup batches are deliberately small because SQLite has one writer in
	// the service. Each statement below is one autocommit transaction, so a
	// large backlog cannot hold the writer for longer than one bounded batch.
	defaultCleanupBatchSize         = 128
	defaultCleanupTransactionBudget = 250 * time.Millisecond
	defaultCleanupPassBudget        = 2 * time.Second
)

// CleanupOptions controls one resumable retention pass. Zero values select
// the production budgets; callers may use smaller values in tests or during
// an operator-driven maintenance pass.
type CleanupOptions struct {
	Retention         time.Duration
	BatchSize         int
	TransactionBudget time.Duration
	PassBudget        time.Duration
}

// CleanupStats describes the work completed by one retention pass. Counts
// are rows changed by the pass, not estimates of the remaining backlog.
type CleanupStats struct {
	SessionsDeleted           int64
	AuthTokensDeleted         int64
	MetaDeleted               int64
	OutboxDeadLettered        int64
	WebhookDeadLettered       int64
	EventsDeleted             int64
	EventBatchesDeleted       int64
	EventBatchTriggersDeleted int64
	WebhookTriggersDeleted    int64
	DeliveredOutboxDeleted    int64
	DeadOutboxDeleted         int64
	Transactions              int
	Duration                  time.Duration
	Remaining                 bool
	FailedPhase               string
}

// TotalRowsChanged returns the total number of rows changed by the pass.
func (c CleanupStats) TotalRowsChanged() int64 {
	return c.SessionsDeleted + c.AuthTokensDeleted + c.MetaDeleted + c.OutboxDeadLettered + c.WebhookDeadLettered + c.EventsDeleted + c.EventBatchesDeleted + c.EventBatchTriggersDeleted + c.WebhookTriggersDeleted + c.DeliveredOutboxDeleted + c.DeadOutboxDeleted
}

// Cleanup expires short-lived authentication/session state, bounds pending
// notification retries, and applies the configured retention window. It
// retains the historical error-only API for existing callers.
func (s *Store) Cleanup(ctx context.Context, retention time.Duration) error {
	_, err := s.CleanupWithOptions(ctx, CleanupOptions{Retention: retention})
	return err
}

// CleanupWithOptions runs a bounded, resumable retention pass. Every batch is
// an independent autocommit transaction capped by BatchSize and
// TransactionBudget. If PassBudget is reached, Remaining is true and a later
// pass can continue from the same keyset predicates without skipping rows.
func (s *Store) CleanupWithOptions(ctx context.Context, options CleanupOptions) (stats CleanupStats, err error) {
	started := time.Now()
	defer func() { stats.Duration = time.Since(started) }()
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	if options.BatchSize <= 0 {
		options.BatchSize = defaultCleanupBatchSize
	}
	if options.BatchSize > 1024 {
		options.BatchSize = 1024
	}
	if options.TransactionBudget <= 0 {
		options.TransactionBudget = defaultCleanupTransactionBudget
	}
	if options.PassBudget <= 0 {
		options.PassBudget = defaultCleanupPassBudget
	}
	deadline := time.Now().Add(options.PassBudget)
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	retryCutoff := now.Add(-outboxRetryWindow).Format(time.RFC3339Nano)
	webhookRetryCutoff := now.Add(-webhookTriggerRetryWindow).Format(time.RFC3339Nano)
	cutoff := now.Add(-options.Retention).Format(time.RFC3339Nano)
	budget := cleanupBudget{deadline: deadline, transaction: options.TransactionBudget, batchSize: options.BatchSize}

	phases := []cleanupPhase{
		{name: "sessions", query: `DELETE FROM sessions WHERE rowid IN (SELECT rowid FROM sessions WHERE expires_at<=? ORDER BY expires_at,rowid LIMIT ?)`, args: []any{nowValue}, add: func(n int64) { stats.SessionsDeleted += n }},
		{name: "auth_tokens", query: `DELETE FROM auth_tokens WHERE rowid IN (SELECT rowid FROM auth_tokens WHERE expires_at<=? ORDER BY expires_at,rowid LIMIT ?)`, args: []any{nowValue}, add: func(n int64) { stats.AuthTokensDeleted += n }},
		{name: "meta", query: `DELETE FROM meta WHERE rowid IN (SELECT rowid FROM meta WHERE (key='setup_token_hash' AND NOT EXISTS (SELECT 1 FROM auth_tokens WHERE kind='setup')) OR (key='reset_token_hash' AND NOT EXISTS (SELECT 1 FROM auth_tokens WHERE kind='reset')) ORDER BY rowid LIMIT ?)`, args: nil, add: func(n int64) { stats.MetaDeleted += n }},
		{name: "outbox_dead_letter", query: `UPDATE outbox SET status='dead',next_attempt=?,lease_until=NULL,lease_token='',last_error=CASE WHEN TRIM(last_error)='' THEN 'delivery retry window expired' ELSE last_error END WHERE rowid IN (SELECT rowid FROM outbox WHERE status IN ('pending','processing') AND first_attempt<=? AND (status='pending' OR lease_until IS NULL OR lease_until<=?) ORDER BY first_attempt,rowid LIMIT ?)`, args: []any{nowValue, retryCutoff, nowValue}, add: func(n int64) { stats.OutboxDeadLettered += n }},
		{name: "webhook_dead_letter", query: `UPDATE webhook_triggers SET status='dead',next_attempt_at=?,lease_until=NULL,lease_token='',last_error=CASE WHEN TRIM(last_error)='' THEN 'reconciliation retry window expired' ELSE last_error END WHERE rowid IN (SELECT rowid FROM webhook_triggers WHERE status IN ('pending','processing') AND received_at<=? AND (status='pending' OR lease_until IS NULL OR lease_until<=?) ORDER BY received_at,rowid LIMIT ?)`, args: []any{nowValue, webhookRetryCutoff, nowValue}, add: func(n int64) { stats.WebhookDeadLettered += n }},
		{name: "events", query: `DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE observed_at<? ORDER BY observed_at,rowid LIMIT ?)`, args: []any{cutoff}, add: func(n int64) { stats.EventsDeleted += n }},
		{name: "event_batches", query: `DELETE FROM event_batches WHERE rowid IN (SELECT b.rowid FROM event_batches b WHERE NOT EXISTS (SELECT 1 FROM events WHERE events.batch_id=b.id) ORDER BY b.observed_at,b.rowid LIMIT ?)`, args: nil, add: func(n int64) { stats.EventBatchesDeleted += n }},
		{name: "event_batch_triggers", query: `DELETE FROM event_batch_triggers WHERE rowid IN (SELECT t.rowid FROM event_batch_triggers t WHERE NOT EXISTS (SELECT 1 FROM event_batches WHERE event_batches.id=t.batch_id) ORDER BY t.batch_id,t.trigger_id LIMIT ?)`, args: nil, add: func(n int64) { stats.EventBatchTriggersDeleted += n }},
		// Ledger entries are intentionally absent from this list. They outlive
		// event snapshots so the signed chain remains an audit trail.
		{name: "webhook_triggers", query: `DELETE FROM webhook_triggers WHERE rowid IN (SELECT rowid FROM webhook_triggers WHERE received_at<? AND status IN ('processed','dead') ORDER BY received_at,rowid LIMIT ?)`, args: []any{cutoff}, add: func(n int64) { stats.WebhookTriggersDeleted += n }},
		{name: "delivered_outbox", query: `DELETE FROM outbox WHERE rowid IN (SELECT rowid FROM outbox WHERE status='delivered' AND delivered_at<? ORDER BY delivered_at,rowid LIMIT ?)`, args: []any{cutoff}, add: func(n int64) { stats.DeliveredOutboxDeleted += n }},
		{name: "dead_outbox", query: `DELETE FROM outbox WHERE rowid IN (SELECT rowid FROM outbox WHERE status='dead' AND created_at<? ORDER BY created_at,rowid LIMIT ?)`, args: []any{cutoff}, add: func(n int64) { stats.DeadOutboxDeleted += n }},
	}
	for _, phase := range phases {
		phaseDone, phaseErr := s.runCleanupPhase(ctx, &stats, phase, &budget)
		if phaseErr != nil {
			stats.FailedPhase = phase.name
			return stats, phaseErr
		}
		if !phaseDone {
			stats.Remaining = true
			return stats, nil
		}
	}
	return stats, nil
}

type cleanupPhase struct {
	name  string
	query string
	args  []any
	add   func(int64)
}

type cleanupBudget struct {
	deadline    time.Time
	transaction time.Duration
	batchSize   int
}

func (b cleanupBudget) expired() bool { return !time.Now().Before(b.deadline) }

func (s *Store) runCleanupPhase(ctx context.Context, stats *CleanupStats, phase cleanupPhase, budget *cleanupBudget) (bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if budget.expired() {
			return false, nil
		}
		args := append([]any(nil), phase.args...)
		args = append(args, budget.batchSize)
		transactionBudget := budget.transaction
		if remaining := time.Until(budget.deadline); remaining < transactionBudget {
			transactionBudget = remaining
		}
		if transactionBudget <= 0 {
			return false, nil
		}
		batchCtx, cancel := context.WithTimeout(ctx, transactionBudget)
		result, err := s.db.ExecContext(batchCtx, phase.query, args...)
		cancel()
		stats.Transactions++
		if err != nil {
			return false, fmt.Errorf("cleanup %s: %w", phase.name, err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return false, fmt.Errorf("cleanup %s rows affected: %w", phase.name, err)
		}
		if changed == 0 {
			return true, nil
		}
		phase.add(changed)
	}
}

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

// Cleanup expires short-lived authentication/session state, bounds pending
// notification retries, and applies the configured retention window.
func (s *Store) Cleanup(ctx context.Context, retention time.Duration) error {
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM auth_tokens WHERE expires_at<=?", now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM meta
		WHERE (key='setup_token_hash' AND NOT EXISTS (SELECT 1 FROM auth_tokens WHERE kind='setup'))
		   OR (key='reset_token_hash' AND NOT EXISTS (SELECT 1 FROM auth_tokens WHERE kind='reset'))`); err != nil {
		return err
	}
	retryCutoff := now.Add(-outboxRetryWindow).Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `UPDATE outbox
		SET status='dead',next_attempt=?,lease_until=NULL,lease_token='',last_error=CASE WHEN TRIM(last_error)='' THEN 'delivery retry window expired' ELSE last_error END
		WHERE status IN ('pending','processing') AND first_attempt<=?
		  AND (status='pending' OR lease_until IS NULL OR lease_until<=?)`, now.Format(time.RFC3339Nano), retryCutoff, now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	webhookRetryCutoff := now.Add(-webhookTriggerRetryWindow).Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `UPDATE webhook_triggers
		SET status='dead',next_attempt_at=?,lease_until=NULL,lease_token='',last_error=CASE WHEN TRIM(last_error)='' THEN 'reconciliation retry window expired' ELSE last_error END
		WHERE status IN ('pending','processing') AND received_at<=?
		  AND (status='pending' OR lease_until IS NULL OR lease_until<=?)`, now.Format(time.RFC3339Nano), webhookRetryCutoff, now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	cutoff := now.Add(-retention).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE observed_at<?", cutoff)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM event_batches WHERE NOT EXISTS (SELECT 1 FROM events WHERE events.batch_id=event_batches.id)"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM event_batch_triggers WHERE NOT EXISTS (SELECT 1 FROM event_batches WHERE event_batches.id=event_batch_triggers.batch_id)"); err != nil {
		return err
	}
	// Ledger entries are retained beyond event snapshots so the hash chain
	// remains a durable audit trail after the 30-day history retention sweep.
	if _, err := s.db.ExecContext(ctx, "DELETE FROM webhook_triggers WHERE received_at<? AND status IN ('processed','dead')", cutoff); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM outbox WHERE status='delivered' AND delivered_at<?", cutoff); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM outbox WHERE status='dead' AND created_at<?", cutoff)
	return err
}

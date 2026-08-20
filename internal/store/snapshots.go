package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

type recordedChange struct {
	Change model.Change
	Before []byte
	After  []byte
}

type persistedFields struct {
	Fields          []model.FieldChange `json:"fields"`
	FieldsTruncated bool                `json:"fields_truncated,omitempty"`
	TotalFields     int                 `json:"total_fields,omitempty"`
}

func (s *Store) ApplyBatchWithBatch(ctx context.Context, generation int64, results []model.Collected, digest func([]model.Change) string, triggerIDs ...int64) (ChangeBatchResult, error) {
	triggerIDs = uniquePositiveIDs(triggerIDs)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	defer tx.Rollback()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&activeGeneration); err != nil {
		return ChangeBatchResult{}, err
	}
	if activeGeneration != generation {
		return ChangeBatchResult{}, nil
	}
	now := time.Now().UTC()
	observedAt := now.Format(time.RFC3339Nano)
	var changes []model.Change
	var recorded []recordedChange
	record := func(change model.Change, before, after []byte) {
		changes = append(changes, change)
		recorded = append(recorded, recordedChange{Change: change, Before: append([]byte(nil), before...), After: append([]byte(nil), after...)})
	}
	for _, result := range results {
		if result.Error != nil {
			continue
		}
		if result.Unsupported {
			next := now.Add(6 * time.Hour).Format(time.RFC3339Nano)
			_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,next_poll,partial) VALUES(?,?,0,0,'unsupported',?,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=0,last_error='unsupported',next_poll=excluded.next_poll,partial=0`, generation, result.Collector, next)
			if err != nil {
				return ChangeBatchResult{}, err
			}
			continue
		}
		var baseline int
		stateErr := tx.QueryRowContext(ctx, "SELECT baseline FROM collector_state WHERE generation=? AND collector=?", generation, result.Collector).Scan(&baseline)
		if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
			return ChangeBatchResult{}, stateErr
		}
		seen := make(map[string]struct{}, len(result.Resources))
		for _, resource := range result.Resources {
			seen[resource.ID] = struct{}{}
			raw, hash, err := model.CanonicalFor(result.Collector, resource.Data)
			if err != nil {
				return ChangeBatchResult{}, err
			}
			var oldRaw []byte
			var oldHash, oldType, oldName string
			var missing int
			err = tx.QueryRowContext(ctx, "SELECT canonical_json,content_hash,resource_type,name,missing_count FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, resource.ID).Scan(&oldRaw, &oldHash, &oldType, &oldName, &missing)
			if err == nil && oldHash != hash {
				var oldValue any
				if json.Unmarshal(oldRaw, &oldValue) == nil {
					normalizedOldRaw, normalizedOldHash, normalizeErr := model.CanonicalFor(result.Collector, oldValue)
					if normalizeErr != nil {
						return ChangeBatchResult{}, normalizeErr
					}
					oldRaw = normalizedOldRaw
					oldHash = normalizedOldHash
				}
			}
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if baseline == 1 {
					record(model.Change{Kind: "created", Collector: result.Collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name}, nil, raw)
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,missing_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, generation, result.Collector, resource.ID, resource.Type, resource.Name, raw, hash, 0, now.Format(time.RFC3339Nano))
			case err != nil:
				return ChangeBatchResult{}, err
			case oldHash != hash:
				if baseline == 1 {
					diff := model.DiffDetailed(oldRaw, raw)
					record(model.Change{Kind: "changed", Collector: result.Collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name, Fields: diff.Fields, FieldsTruncated: diff.FieldsTruncated, TotalFields: diff.TotalFields}, oldRaw, raw)
				}
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, raw, hash, now.Format(time.RFC3339Nano), generation, result.Collector, resource.ID)
			default:
				_, err = tx.ExecContext(ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, raw, hash, now.Format(time.RFC3339Nano), generation, result.Collector, resource.ID)
			}
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
		type absent struct {
			id, typ, name string
			raw           []byte
			missing       int
		}
		var missingRows []absent
		massRemovalGuarded := result.Partial
		if !result.Partial {
			rows, queryErr := tx.QueryContext(ctx, "SELECT resource_id,resource_type,name,canonical_json,missing_count FROM snapshots WHERE generation=? AND collector=?", generation, result.Collector)
			if queryErr != nil {
				return ChangeBatchResult{}, queryErr
			}
			for rows.Next() {
				var a absent
				if scanErr := rows.Scan(&a.id, &a.typ, &a.name, &a.raw, &a.missing); scanErr != nil {
					rows.Close()
					return ChangeBatchResult{}, scanErr
				}
				if _, ok := seen[a.id]; !ok {
					missingRows = append(missingRows, a)
				}
			}
			if rowsErr := rows.Err(); rowsErr != nil {
				rows.Close()
				return ChangeBatchResult{}, rowsErr
			}
			if closeErr := rows.Close(); closeErr != nil {
				return ChangeBatchResult{}, closeErr
			}
		}
		if !result.Partial {
			// Treat a sudden large disappearance as degraded data, but do not
			// suppress removals forever if the upstream keeps returning the same
			// shape. Two consecutive guarded responses are enough to establish
			// that the new population is stable; the following poll resumes the
			// normal two-poll removal confirmation path.
			suspicious := len(missingRows) >= 3 && len(missingRows) >= len(seen)
			confirmedMissing := len(missingRows) > 0
			for _, missing := range missingRows {
				if missing.missing == 0 {
					confirmedMissing = false
					break
				}
			}
			if suspicious && !confirmedMissing {
				var previousFailures int
				var previousError string
				stateErr := tx.QueryRowContext(ctx, "SELECT failure_count,last_error FROM collector_state WHERE generation=? AND collector=?", generation, result.Collector).Scan(&previousFailures, &previousError)
				if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
					return ChangeBatchResult{}, stateErr
				}
				if !strings.HasPrefix(previousError, "possible mass removal guarded") || previousFailures < 2 {
					massRemovalGuarded = true
				}
			}
		}
		if !massRemovalGuarded {
			for _, a := range missingRows {
				if a.missing+1 >= 2 {
					if baseline == 1 {
						record(model.Change{Kind: "removed", Collector: result.Collector, ResourceID: a.id, Type: a.typ, Name: a.name}, a.raw, nil)
					}
					_, err = tx.ExecContext(ctx, "DELETE FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, a.id)
				} else {
					_, err = tx.ExecContext(ctx, "UPDATE snapshots SET missing_count=missing_count+1 WHERE generation=? AND collector=? AND resource_id=?", generation, result.Collector, a.id)
				}
				if err != nil {
					return ChangeBatchResult{}, err
				}
			}
		} else if result.Partial {
			partialMessage := strings.TrimSpace(result.PartialError)
			if partialMessage == "" {
				partialMessage = "collector response was partial"
			}
			partialErrorCount := result.PartialErrorCount
			if partialErrorCount < 1 {
				partialErrorCount = 1
			}
			// Partial responses are still a usable baseline for the resources
			// returned. Preserve existing snapshots for omitted resources, but do
			// not let one incomplete optional collector hold the whole installation
			// in an un-baselined state forever.
			_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,1,?,?,1,0,1,?) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,baseline=MAX(collector_state.baseline,1),last_success=excluded.last_success,last_error=excluded.last_error,partial=1,partial_error_count=excluded.partial_error_count`, generation, result.Collector, observedAt, partialMessage, partialErrorCount)
			if err != nil {
				return ChangeBatchResult{}, err
			}
		} else {
			// A successful-looking empty or near-empty response is more likely an
			// upstream degradation than a real mass removal. Keep the snapshots
			// intact and surface the guard in collector health instead of creating
			// a removal storm.
			_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,?,?,?,1,0,0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,last_success=excluded.last_success,last_error=excluded.last_error,failure_count=collector_state.failure_count+1,unhealthy_notified=0,partial=0,partial_error_count=0`, generation, result.Collector, baseline, observedAt, fmt.Sprintf("possible mass removal guarded (%d missing, %d present)", len(missingRows), len(seen)))
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
		if !massRemovalGuarded {
			_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,1,?,'',0,0,0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,baseline=1,last_success=excluded.last_success,last_error='',failure_count=0,unhealthy_notified=0,partial=0,partial_error_count=0`, generation, result.Collector, observedAt)
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
	}
	var triggerID int64
	if len(triggerIDs) > 0 && triggerIDs[0] > 0 {
		triggerID = triggerIDs[0]
	}
	result := ChangeBatchResult{ChangeBatch: ChangeBatch{Generation: generation, ObservedAt: now, TriggerID: triggerID, TriggerIDs: append([]int64(nil), triggerIDs...)}, Changes: changes}
	if len(recorded) > 0 {
		var triggerValue any
		if triggerID > 0 {
			triggerValue = triggerID
		}
		batchResult, err := tx.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at,trigger_id) VALUES(?,?,?,?,?)", generation, observedAt, len(recorded), observedAt, triggerValue)
		if err != nil {
			return ChangeBatchResult{}, err
		}
		batchID, err := batchResult.LastInsertId()
		if err != nil {
			return ChangeBatchResult{}, err
		}
		result.ID, result.ChangeCount = batchID, len(recorded)
		for _, triggerID := range triggerIDs {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO event_batch_triggers(batch_id,trigger_id) VALUES(?,?)", batchID, triggerID); err != nil {
				return ChangeBatchResult{}, err
			}
		}
		for _, entry := range recorded {
			fields, marshalErr := json.Marshal(persistedFields{Fields: entry.Change.Fields, FieldsTruncated: entry.Change.FieldsTruncated, TotalFields: entry.Change.TotalFields})
			if marshalErr != nil {
				return ChangeBatchResult{}, marshalErr
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?,?)", batchID, generation, observedAt, entry.Change.Collector, entry.Change.Kind, entry.Change.ResourceID, entry.Change.Name, fields, nullableJSON(entry.Before), nullableJSON(entry.After))
			if err != nil {
				return ChangeBatchResult{}, err
			}
		}
		payload := digest(changes)
		if err = enqueueOutboxTx(ctx, tx, payload, observedAt, batchID); err != nil {
			return ChangeBatchResult{}, err
		}
		if err = s.appendEvidenceLedgerTx(ctx, tx, batchID); err != nil {
			return ChangeBatchResult{}, err
		}
	}
	var remaining int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1 AND baseline=0", generation).Scan(&remaining)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	var supported int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1", generation).Scan(&supported); err != nil {
		return ChangeBatchResult{}, err
	}
	if supported > 0 && remaining == 0 {
		_, err = tx.ExecContext(ctx, "UPDATE settings SET baseline_at=COALESCE(baseline_at,?) WHERE id=1 AND generation=?", observedAt, generation)
		if err != nil {
			return ChangeBatchResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ChangeBatchResult{}, err
	}
	return result, nil
}

func nullableJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func (s *Store) RecordCollectorFailure(ctx context.Context, generation int64, collector, message string) (notify bool, recovered bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM settings WHERE id=1").Scan(&activeGeneration); err != nil {
		return false, false, err
	}
	if activeGeneration != generation {
		return false, false, nil
	}
	var failures, notified int
	stateErr := tx.QueryRowContext(ctx, "SELECT failure_count,unhealthy_notified FROM collector_state WHERE generation=? AND collector=?", generation, collector).Scan(&failures, &notified)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
		return false, false, stateErr
	}
	failures++
	notify = failures >= 3 && notified == 0
	if notify {
		notified = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,0,?,?,?,0,0) ON CONFLICT(generation,collector) DO UPDATE SET last_error=excluded.last_error,failure_count=excluded.failure_count,unhealthy_notified=excluded.unhealthy_notified,partial=0,partial_error_count=0`, generation, collector, message, failures, notified)
	if err != nil {
		return false, false, err
	}
	err = tx.Commit()
	return
}

// CollectorWasUnhealthyWithError reports the persisted unhealthy notification
// state without hiding database failures from the scheduler.
func (s *Store) CollectorWasUnhealthyWithError(ctx context.Context, generation int64, collector string) (bool, error) {
	var notified int
	err := s.db.QueryRowContext(ctx, "SELECT unhealthy_notified FROM collector_state WHERE generation=? AND collector=?", generation, collector).Scan(&notified)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return notified == 1, nil
}

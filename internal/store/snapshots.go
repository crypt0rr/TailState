package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

type recordedChange struct {
	Change model.Change
	Before storedValue
	After  storedValue
}

type canonicalResource struct {
	raw  []byte
	hash string
}

type truncationLog struct {
	collector string
	resource  string
	valueHash string
	observed  int64
	limit     int64
	reason    string
}

type persistedFields struct {
	Fields          []model.FieldChange `json:"fields"`
	FieldsTruncated bool                `json:"fields_truncated,omitempty"`
	TotalFields     int                 `json:"total_fields,omitempty"`
}

const (
	// A previously baselined collector must not be demoted to a six-hour
	// unsupported window on one transient 403/404. Require a second
	// consecutive response before changing its capability state, while still
	// demoting collectors that have never produced a baseline immediately.
	unsupportedConfirmationMessage = "unsupported response pending confirmation"
	unsupportedRetryInterval       = 5 * time.Minute
	unsupportedDemotionInterval    = 6 * time.Hour
	// usersSharedScopeMeta records the generation whose users snapshot was
	// collected with users?type=all. Older versions requested only members,
	// so the first type=all poll of an existing users baseline would otherwise
	// report every pre-existing shared (external) user as newly created.
	usersSharedScopeMeta = "users_shared_scope_generation"
)

func (s *Store) ApplyBatchWithBatch(ctx context.Context, generation int64, results []model.Collected, digest notify.DigestFunc, triggerIDs ...int64) (ChangeBatchResult, error) {
	return s.ApplyBatchWithOptions(ctx, generation, results, digest, BatchOptions{}, triggerIDs...)
}

// ApplyBatchWithOptions applies collector results like ApplyBatchWithBatch
// and, when options.Attribute is set, attributes the recorded changes to the
// configuration audit log. The lookup runs before the write transaction and
// within options.Budget; its failure never fails the batch.
//
// The work runs in named phases: canonicalisation and attribution outside
// the write transaction, then, inside it, each collector's result
// (unsupported handling, snapshot upserts, missing-resource reconciliation,
// and collector state), the change batch with its events, digest, and
// ledger entry, and the baseline transition.
func (s *Store) ApplyBatchWithOptions(ctx context.Context, generation int64, results []model.Collected, digest notify.DigestFunc, options BatchOptions, triggerIDs ...int64) (batchResult ChangeBatchResult, err error) {
	defer func() { err = storageWriteError(err) }()
	triggerIDs = uniquePositiveIDs(triggerIDs)
	// Canonicalise every resource before opening the write transaction. The
	// store uses a single SQLite connection, so CPU-bound normalisation inside
	// the transaction would delay health checks, metrics, and webhook intake.
	canonical, err := canonicalizeResults(results)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	// Attribution needs the network, so it happens before the single writer
	// is taken and only within its budget.
	lookup, window := s.lookupAttribution(ctx, generation, results, canonical, options, time.Now().UTC())
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
	apply := &batchApply{ctx: ctx, tx: tx, generation: generation, now: now, observedAt: formatTimestamp(now), limits: s.StorageLimits()}
	for resultIndex, result := range results {
		if result.Error != nil {
			continue
		}
		if result.Unsupported {
			if err := apply.unsupportedCollector(result); err != nil {
				return ChangeBatchResult{}, err
			}
			continue
		}
		if err := apply.collector(result, canonical[resultIndex]); err != nil {
			return ChangeBatchResult{}, err
		}
	}
	result, err := s.recordChangeBatch(apply, results, digest, lookup, window, triggerIDs)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	if err := apply.markBaselineReady(); err != nil {
		return ChangeBatchResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ChangeBatchResult{}, err
	}
	s.publishTruncations(apply)
	return result, nil
}

// canonicalizeResults returns the canonical form of every resource of every
// usable result, indexed like results and their resources.
func canonicalizeResults(results []model.Collected) ([][]canonicalResource, error) {
	canonical := make([][]canonicalResource, len(results))
	for i, result := range results {
		if result.Error != nil || result.Unsupported {
			continue
		}
		canonical[i] = make([]canonicalResource, len(result.Resources))
		for j, resource := range result.Resources {
			raw, hash, err := model.CanonicalFor(result.Collector, resource.Data)
			if err != nil {
				return nil, err
			}
			canonical[i][j] = canonicalResource{raw: raw, hash: hash}
		}
	}
	return canonical, nil
}

// batchApply is the state of one ApplyBatch write transaction: the changes
// recorded so far and the storage truncations to report after commit.
type batchApply struct {
	ctx        context.Context
	tx         *sql.Tx
	generation int64
	now        time.Time
	observedAt string
	limits     StorageLimits

	changes     []model.Change
	recorded    []recordedChange
	truncations []truncationLog

	snapshotTruncations, eventTruncations, oversizedWrites uint64
}

func (a *batchApply) record(change model.Change, before, after storedValue) {
	a.changes = append(a.changes, change)
	a.recorded = append(a.recorded, recordedChange{Change: change, Before: before, After: after})
}

func (a *batchApply) noteTruncation(collector, resource string, value storedValue, limit int64, snapshot bool) {
	if !value.truncated {
		return
	}
	if snapshot {
		a.snapshotTruncations++
	} else {
		a.eventTruncations++
	}
	if value.rejected {
		a.oversizedWrites++
	}
	a.truncations = append(a.truncations, truncationLog{collector: collector, resource: resource, valueHash: value.hash, observed: value.bytes, limit: limit, reason: value.reason})
}

// unsupportedCollector records an unsupported response. A baselined
// collector is demoted only on the second consecutive response.
func (a *batchApply) unsupportedCollector(result model.Collected) error {
	ctx, tx := a.ctx, a.tx
	var supported, baseline int
	var lastError string
	stateErr := tx.QueryRowContext(ctx, "SELECT supported,baseline,last_error FROM collector_state WHERE generation=? AND collector=?", a.generation, result.Collector).Scan(&supported, &baseline, &lastError)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
		return stateErr
	}
	if stateErr == nil && supported == 1 && baseline == 1 && lastError != unsupportedConfirmationMessage {
		next := formatTimestamp(a.now.Add(unsupportedRetryInterval))
		_, err := tx.ExecContext(ctx, `UPDATE collector_state
					SET supported=1,last_error=?,failure_count=1,next_poll=?,partial=0,partial_error_count=0
					WHERE generation=? AND collector=?`, unsupportedConfirmationMessage, next, a.generation, result.Collector)
		return err
	}
	next := formatTimestamp(a.now.Add(unsupportedDemotionInterval))
	reason := strings.TrimSpace(result.UnsupportedReason)
	if reason == "" {
		reason = "unsupported"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,next_poll,partial) VALUES(?,?,0,0,?,?,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=0,last_error=excluded.last_error,next_poll=excluded.next_poll,partial=0`, a.generation, result.Collector, reason, next)
	return err
}

// collector applies one supported result: it upserts the returned
// resources, reconciles the stored resources the response omitted, and
// records the collector's state.
func (a *batchApply) collector(result model.Collected, canonical []canonicalResource) error {
	var baseline int
	stateErr := a.tx.QueryRowContext(a.ctx, "SELECT baseline FROM collector_state WHERE generation=? AND collector=?", a.generation, result.Collector).Scan(&baseline)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
		return stateErr
	}
	absorbSharedUsers, err := a.sharedUsersAbsorption(result, baseline)
	if err != nil {
		return err
	}
	// Device details describe a device whose appearance and removal are
	// already reported by the devices collector. Their snapshots are still
	// created and deleted (after the same two-poll confirmation), but only
	// field changes are reported, so one device change is one event.
	silentLifecycle := result.Collector == "device_details"
	seen := make(map[string]struct{}, len(result.Resources))
	for resourceIndex, resource := range result.Resources {
		seen[resource.ID] = struct{}{}
		if err := a.upsertResource(result.Collector, resource, canonical[resourceIndex], baseline == 1, silentLifecycle, absorbSharedUsers); err != nil {
			return err
		}
	}
	guarded, missingCount, err := a.massRemovalGuard(result, seen)
	if err != nil {
		return err
	}
	if !guarded {
		if !result.Partial && missingCount > 0 {
			if err := a.reconcileMissing(result.Collector, seen, baseline == 1, silentLifecycle); err != nil {
				return err
			}
		}
		return a.recordCollectorSuccess(result.Collector)
	}
	if result.Partial {
		return a.recordCollectorPartial(result)
	}
	return a.recordRemovalGuard(result.Collector, baseline, missingCount, len(seen))
}

// sharedUsersAbsorption reports whether newly visible shared users are
// absorbed silently on this poll. When an established users baseline
// predates shared-user collection, they are a baseline extension on this one
// poll. Members keep normal created events, and a shared user that appears
// on any later poll is reported as created.
func (a *batchApply) sharedUsersAbsorption(result model.Collected, baseline int) (bool, error) {
	if result.Collector != "users" {
		return false, nil
	}
	var scopeGeneration string
	scopeErr := a.tx.QueryRowContext(a.ctx, "SELECT value FROM meta WHERE key=?", usersSharedScopeMeta).Scan(&scopeGeneration)
	if scopeErr != nil && !errors.Is(scopeErr, sql.ErrNoRows) {
		return false, scopeErr
	}
	absorb := baseline == 1 && scopeGeneration != fmt.Sprint(a.generation)
	if _, err := a.tx.ExecContext(a.ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", usersSharedScopeMeta, fmt.Sprint(a.generation)); err != nil {
		return false, err
	}
	return absorb, nil
}

// upsertResource stores one returned resource, recording a created or
// changed event when the collector has a baseline. An unchanged resource
// whose stored row is already byte-identical is not rewritten.
func (a *batchApply) upsertResource(collector string, resource model.Resource, canonical canonicalResource, baselined, silentLifecycle, absorbSharedUsers bool) error {
	ctx, tx, generation := a.ctx, a.tx, a.generation
	raw, hash := canonical.raw, canonical.hash
	var oldRaw []byte
	var oldHash, oldType, oldName string
	var missing, oldBytes, oldTruncated int64
	err := tx.QueryRowContext(ctx, "SELECT canonical_json,content_hash,resource_type,name,missing_count,content_bytes,content_truncated FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, collector, resource.ID).Scan(&oldRaw, &oldHash, &oldType, &oldName, &missing, &oldBytes, &oldTruncated)
	// Keep the row exactly as stored: the re-normalisation below
	// replaces oldRaw/oldHash for diffing, but deciding whether the row
	// needs a rewrite must compare against what is on disk.
	storedRaw, storedHash := oldRaw, oldHash
	oldValue := existingStoredValue(oldRaw, oldHash, oldBytes, oldTruncated == 1)
	if err == nil && oldHash != hash {
		var previous any
		if !oldValue.truncated && json.Unmarshal(oldRaw, &previous) == nil {
			normalizedOldRaw, normalizedOldHash, normalizeErr := model.CanonicalFor(collector, previous)
			if normalizeErr != nil {
				return normalizeErr
			}
			oldRaw = normalizedOldRaw
			oldHash = normalizedOldHash
			oldValue = existingStoredValue(oldRaw, oldHash, int64(len(oldRaw)), false)
		}
	}
	storedSnapshot := boundedValue(raw, hash, a.limits.SnapshotBytes, a.limits.RejectBytes)
	a.noteTruncation(collector, resource.ID, storedSnapshot, a.limits.SnapshotBytes, true)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if baselined && !silentLifecycle && !(absorbSharedUsers && isSharedUser(resource)) {
			a.record(model.Change{Kind: "created", Collector: collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name}, storedValue{}, existingStoredValue(raw, hash, int64(len(raw)), false))
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,content_bytes,content_truncated,missing_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, generation, collector, resource.ID, resource.Type, resource.Name, storedSnapshot.raw, hash, storedSnapshot.bytes, boolInt(storedSnapshot.truncated), 0, formatTimestamp(a.now))
	case err != nil:
		return err
	case oldHash != hash:
		// A snapshot stored in a different upstream shape (for example
		// legacy DNS endpoints versus dns/configuration) is compared only
		// on the fields both shapes express: a shape change alone is
		// absorbed silently, a real change is still reported.
		var oldComparable, newComparable []byte
		transition := false
		if !oldValue.truncated {
			oldComparable, newComparable, transition = model.ShapeTransition(collector, oldRaw, raw)
		}
		if baselined && !(transition && bytes.Equal(oldComparable, newComparable)) {
			diff := model.DiffResult{}
			if transition {
				diff = model.DiffDetailed(oldComparable, newComparable)
			} else if !oldValue.truncated {
				diff = model.DiffDetailed(oldRaw, raw)
			}
			a.record(model.Change{Kind: "changed", Collector: collector, ResourceID: resource.ID, Type: resource.Type, Name: resource.Name, Fields: diff.Fields, FieldsTruncated: diff.FieldsTruncated, TotalFields: diff.TotalFields}, oldValue, existingStoredValue(raw, hash, int64(len(raw)), false))
		}
		err = a.rewriteSnapshot(collector, resource, storedSnapshot, hash)
	case storedHash == hash && oldType == resource.Type && oldName == resource.Name && missing == 0 &&
		(oldTruncated == 1) == storedSnapshot.truncated && oldBytes == storedSnapshot.bytes && bytes.Equal(storedRaw, storedSnapshot.raw):
		// Unchanged resource: the stored row is already byte-identical to
		// what would be written, so skip the UPDATE. Rewriting every
		// snapshot on every poll produced megabytes of WAL traffic per
		// poll with no drift.
	default:
		err = a.rewriteSnapshot(collector, resource, storedSnapshot, hash)
	}
	return err
}

// rewriteSnapshot replaces a stored snapshot and clears its missing count.
func (a *batchApply) rewriteSnapshot(collector string, resource model.Resource, stored storedValue, hash string) error {
	_, err := a.tx.ExecContext(a.ctx, "UPDATE snapshots SET resource_type=?,name=?,canonical_json=?,content_hash=?,content_bytes=?,content_truncated=?,missing_count=0,updated_at=? WHERE generation=? AND collector=? AND resource_id=?", resource.Type, resource.Name, stored.raw, hash, stored.bytes, boolInt(stored.truncated), formatTimestamp(a.now), a.generation, collector, resource.ID)
	return err
}

// massRemovalGuard counts the stored resources a complete response omitted
// and decides whether to hold back their removal. A partial response is
// always guarded: omitted resources may simply not have been returned.
func (a *batchApply) massRemovalGuard(result model.Collected, seen map[string]struct{}) (guarded bool, missingCount int, err error) {
	if result.Partial {
		return true, 0, nil
	}
	// First inspect only identifiers and missing counters. Keeping raw
	// snapshot values out of this pass is important because a guarded
	// response must not retain one potentially large blob per omitted
	// resource just to decide whether removals are safe.
	confirmedMissing := true
	rows, err := a.tx.QueryContext(a.ctx, "SELECT resource_id,missing_count FROM snapshots WHERE generation=? AND collector=?", a.generation, result.Collector)
	if err != nil {
		return false, 0, err
	}
	for rows.Next() {
		var id string
		var missing int
		if scanErr := rows.Scan(&id, &missing); scanErr != nil {
			rows.Close()
			return false, 0, scanErr
		}
		if _, ok := seen[id]; !ok {
			missingCount++
			if missing == 0 {
				confirmedMissing = false
			}
		}
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		rows.Close()
		return false, 0, rowsErr
	}
	if closeErr := rows.Close(); closeErr != nil {
		return false, 0, closeErr
	}
	// Treat a sudden majority disappearance as degraded data, but do not
	// suppress removals forever if the upstream keeps returning the same
	// shape. Two consecutive guarded responses are enough to establish
	// that the new population is stable; the following poll resumes the
	// normal two-poll removal confirmation path.
	if missingCount == 0 {
		confirmedMissing = false
	}
	suspicious := missingCount >= 3 && missingCount > len(seen)
	if !suspicious || confirmedMissing {
		return false, missingCount, nil
	}
	var previousFailures int
	var previousError string
	stateErr := a.tx.QueryRowContext(a.ctx, "SELECT failure_count,last_error FROM collector_state WHERE generation=? AND collector=?", a.generation, result.Collector).Scan(&previousFailures, &previousError)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
		return false, 0, stateErr
	}
	guarded = !strings.HasPrefix(previousError, "possible mass removal guarded") || previousFailures < 2
	return guarded, missingCount, nil
}

// absentResource is a stored resource that a complete response omitted.
type absentResource struct {
	id, typ, name string
	raw           []byte
	hash          string
	bytes         int64
	truncated     bool
	missing       int
}

// reconcileMissing advances the missing count of every stored resource the
// response omitted and removes those missing on two consecutive polls,
// recording a removed event when the collector has a baseline. The full
// rows are loaded only after the guard decision, so a guarded response
// never retains raw values.
func (a *batchApply) reconcileMissing(collector string, seen map[string]struct{}, baselined, silentLifecycle bool) error {
	ctx, tx, generation := a.ctx, a.tx, a.generation
	rows, err := tx.QueryContext(ctx, "SELECT resource_id,resource_type,name,canonical_json,content_hash,content_bytes,content_truncated,missing_count FROM snapshots WHERE generation=? AND collector=?", generation, collector)
	if err != nil {
		return err
	}
	var missingRows []absentResource
	for rows.Next() {
		var absent absentResource
		var truncated int
		if scanErr := rows.Scan(&absent.id, &absent.typ, &absent.name, &absent.raw, &absent.hash, &absent.bytes, &truncated, &absent.missing); scanErr != nil {
			rows.Close()
			return scanErr
		}
		absent.truncated = truncated == 1
		if _, ok := seen[absent.id]; !ok {
			missingRows = append(missingRows, absent)
		}
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		rows.Close()
		return rowsErr
	}
	if closeErr := rows.Close(); closeErr != nil {
		return closeErr
	}
	for _, absent := range missingRows {
		if absent.missing+1 >= 2 {
			if baselined && !silentLifecycle {
				a.record(model.Change{Kind: "removed", Collector: collector, ResourceID: absent.id, Type: absent.typ, Name: absent.name}, existingStoredValue(absent.raw, absent.hash, absent.bytes, absent.truncated), storedValue{})
			}
			_, err = tx.ExecContext(ctx, "DELETE FROM snapshots WHERE generation=? AND collector=? AND resource_id=?", generation, collector, absent.id)
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE snapshots SET missing_count=missing_count+1 WHERE generation=? AND collector=? AND resource_id=?", generation, collector, absent.id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// recordCollectorPartial keeps a partial response as a usable baseline for
// the resources returned. Existing snapshots of omitted resources are
// preserved, but one incomplete optional collector must not hold the whole
// installation in an un-baselined state forever.
func (a *batchApply) recordCollectorPartial(result model.Collected) error {
	partialMessage := strings.TrimSpace(result.PartialError)
	if partialMessage == "" {
		partialMessage = "collector response was partial"
	}
	partialErrorCount := result.PartialErrorCount
	if partialErrorCount < 1 {
		partialErrorCount = 1
	}
	_, err := a.tx.ExecContext(a.ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,1,?,?,1,0,1,?) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,baseline=MAX(collector_state.baseline,1),last_success=excluded.last_success,last_error=excluded.last_error,partial=1,partial_error_count=excluded.partial_error_count`, a.generation, result.Collector, a.observedAt, partialMessage, partialErrorCount)
	return err
}

// recordRemovalGuard surfaces a guarded mass removal in collector health. A
// successful-looking empty or near-empty response is more likely an
// upstream degradation than a real mass removal, so the snapshots stay
// intact instead of producing a removal storm.
func (a *batchApply) recordRemovalGuard(collector string, baseline, missingCount, present int) error {
	_, err := a.tx.ExecContext(a.ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,?,?,?,1,0,0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,last_success=excluded.last_success,last_error=excluded.last_error,failure_count=collector_state.failure_count+1,unhealthy_notified=0,partial=0,partial_error_count=0`, a.generation, collector, baseline, a.observedAt, fmt.Sprintf("possible mass removal guarded (%d missing, %d present)", missingCount, present))
	return err
}

// recordCollectorSuccess marks a fully applied collector healthy and
// baselined.
func (a *batchApply) recordCollectorSuccess(collector string) error {
	_, err := a.tx.ExecContext(a.ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_success,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,1,?,'',0,0,0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,baseline=1,last_success=excluded.last_success,last_error='',failure_count=0,unhealthy_notified=0,partial=0,partial_error_count=0`, a.generation, collector, a.observedAt)
	return err
}

// recordChangeBatch stores the recorded changes as one event batch with its
// trigger links and events, queues the digest, and appends the evidence
// ledger entry. A poll without changes stores nothing and returns the batch
// metadata only.
func (s *Store) recordChangeBatch(a *batchApply, results []model.Collected, digest notify.DigestFunc, lookup AttributionResult, window AttributionWindow, triggerIDs []int64) (ChangeBatchResult, error) {
	ctx, tx, generation := a.ctx, a.tx, a.generation
	// Schema-change detection compares a field transition with the number of
	// resources each collector returned in this poll.
	resourceCounts := make(map[string]int, len(results))
	for _, result := range results {
		if result.Error == nil && !result.Unsupported {
			resourceCounts[result.Collector] = len(result.Resources)
		}
	}
	var triggerID int64
	if len(triggerIDs) > 0 && triggerIDs[0] > 0 {
		triggerID = triggerIDs[0]
	}
	result := ChangeBatchResult{ChangeBatch: ChangeBatch{Generation: generation, ObservedAt: a.now, TriggerID: triggerID, TriggerIDs: append([]int64(nil), triggerIDs...)}, Changes: a.changes}
	if len(a.recorded) == 0 {
		return result, nil
	}
	var triggerValue any
	if triggerID > 0 {
		triggerValue = triggerID
	}
	result.AttributionStatus = lookup.Status
	inserted, err := tx.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at,trigger_id,attribution_status) VALUES(?,?,?,?,?,?)", generation, a.observedAt, len(a.recorded), a.observedAt, triggerValue, lookup.Status)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	batchID, err := inserted.LastInsertId()
	if err != nil {
		return ChangeBatchResult{}, err
	}
	result.ID, result.ChangeCount = batchID, len(a.recorded)
	for _, triggerID := range triggerIDs {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO event_batch_triggers(batch_id,trigger_id) VALUES(?,?)", batchID, triggerID); err != nil {
			return ChangeBatchResult{}, err
		}
	}
	muteRules, err := listMuteRules(ctx, tx)
	if err != nil {
		return ChangeBatchResult{}, err
	}
	mutes := newMuteSet(muteRules)
	// The digest receives only unmuted changes, with muted fields removed
	// and severities computed on what is actually shown; History and the
	// ledger keep every change and field, flagged when muted.
	notifiable := make([]model.Change, 0, len(a.recorded))
	severities := make([]model.Severity, 0, len(a.recorded))
	mutedCount := 0
	for index, entry := range a.recorded {
		attribution := attributeChange(entry, lookup, window, a.now)
		if attribution != nil {
			result.Attributed++
			result.Changes[index].Attribution = attribution
		}
		muted, shown := mutes.evaluate(entry.Change, entry.Before.raw, entry.After.raw)
		if muted {
			mutedCount++
		} else {
			shown.Attribution = attribution
			notifiable = append(notifiable, shown)
			severities = append(severities, model.Classify(shown))
		}
		if err := a.insertEvent(batchID, entry, attribution, muted); err != nil {
			return ChangeBatchResult{}, err
		}
	}
	input := notify.DigestInput{BatchID: batchID, ObservedAt: a.now, Changes: notifiable, MutedCount: mutedCount, ResourceCounts: resourceCounts, Attributed: attributionShown(lookup.Status), AttributionUnavailable: lookup.Status == AttributionUnavailable}
	if err := enqueueDigestTx(ctx, tx, digest, input, severities, a.observedAt); err != nil {
		return ChangeBatchResult{}, err
	}
	if err := s.appendEvidenceLedgerTx(ctx, tx, batchID); err != nil {
		return ChangeBatchResult{}, err
	}
	return result, nil
}

// insertEvent stores one recorded change of batchID with its bounded
// before and after values, built-in severity, mute flag, and attribution.
func (a *batchApply) insertEvent(batchID int64, entry recordedChange, attribution *model.Attribution, muted bool) error {
	severity := model.Classify(entry.Change)
	var storedAttribution string
	if attribution != nil {
		storedAttribution = model.MarshalAttribution(*attribution)
	}
	fields, err := json.Marshal(persistedFields{Fields: entry.Change.Fields, FieldsTruncated: entry.Change.FieldsTruncated, TotalFields: entry.Change.TotalFields})
	if err != nil {
		return err
	}
	before := boundedValue(entry.Before.raw, entry.Before.hash, a.limits.EventValueBytes, a.limits.RejectBytes)
	after := boundedValue(entry.After.raw, entry.After.hash, a.limits.EventValueBytes, a.limits.RejectBytes)
	a.noteTruncation(entry.Change.Collector, entry.Change.ResourceID, before, a.limits.EventValueBytes, false)
	a.noteTruncation(entry.Change.Collector, entry.Change.ResourceID, after, a.limits.EventValueBytes, false)
	_, err = a.tx.ExecContext(a.ctx, `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json,before_hash,after_hash,before_bytes,after_bytes,before_truncated,after_truncated,severity,muted,attribution) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, batchID, a.generation, a.observedAt, entry.Change.Collector, entry.Change.Kind, entry.Change.ResourceID, entry.Change.Name, fields, nullableJSON(before.raw), nullableJSON(after.raw), before.hash, after.hash, before.bytes, after.bytes, boolInt(before.truncated), boolInt(after.truncated), string(severity), boolInt(muted), storedAttribution)
	return err
}

// markBaselineReady records the baseline time once every supported
// collector of the generation has a baseline.
func (a *batchApply) markBaselineReady() error {
	var remaining int
	if err := a.tx.QueryRowContext(a.ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1 AND baseline=0", a.generation).Scan(&remaining); err != nil {
		return err
	}
	var supported int
	if err := a.tx.QueryRowContext(a.ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=? AND supported=1", a.generation).Scan(&supported); err != nil {
		return err
	}
	if supported > 0 && remaining == 0 {
		if _, err := a.tx.ExecContext(a.ctx, "UPDATE settings SET baseline_at=COALESCE(baseline_at,?) WHERE id=1 AND generation=?", a.observedAt, a.generation); err != nil {
			return err
		}
	}
	return nil
}

// publishTruncations adds a committed batch's truncations to the storage
// counters and logs each one.
func (s *Store) publishTruncations(a *batchApply) {
	if a.snapshotTruncations > 0 {
		s.counters.snapshotTruncations.Add(a.snapshotTruncations)
	}
	if a.eventTruncations > 0 {
		s.counters.eventTruncations.Add(a.eventTruncations)
	}
	if a.oversizedWrites > 0 {
		s.counters.oversizedWriteRejects.Add(a.oversizedWrites)
	}
	for _, item := range a.truncations {
		logStorageTruncation(item.collector, item.resource, item.valueHash, item.observed, item.limit, item.reason)
	}
}

func isSharedUser(resource model.Resource) bool {
	data, ok := resource.Data.(map[string]any)
	if !ok {
		return false
	}
	kind, _ := data["type"].(string)
	return strings.EqualFold(kind, "shared")
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
	// A non-unsupported error proves that the endpoint is reachable enough to
	// classify the collector as supported, even if it is currently unhealthy.
	// This also lets the UI distinguish a transient failure after an explicit
	// unsupported response from a still-unsupported collector. Preserve the
	// existing baseline: failures must not reset drift comparison state.
	_, err = tx.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,failure_count,unhealthy_notified,partial,partial_error_count) VALUES(?,?,1,0,?,?,?,0,0) ON CONFLICT(generation,collector) DO UPDATE SET supported=1,last_error=excluded.last_error,failure_count=excluded.failure_count,unhealthy_notified=excluded.unhealthy_notified,partial=0,partial_error_count=0`, generation, collector, message, failures, notified)
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

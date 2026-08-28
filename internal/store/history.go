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
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/textutil"
)

// ListHistory returns explainable event batches in descending order. History
// query orchestration lives in this file so the persistence and reconciliation
// code can evolve independently from the audit presentation path.
func (s *Store) ListHistory(ctx context.Context, filter HistoryFilter) (HistoryPage, error) {
	return s.listHistory(ctx, filter, s.StorageLimits().HistoryPageBytes, false)
}

func (s *Store) listHistory(ctx context.Context, filter HistoryFilter, byteLimit int64, includeLedgerPayload bool) (HistoryPage, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	where := []string{"1=1"}
	args := make([]any, 0, 5)
	if filter.Cursor > 0 {
		where = append(where, "b.id < ?")
		args = append(args, filter.Cursor)
	}
	if filter.Collector != "" {
		where = append(where, "EXISTS (SELECT 1 FROM events e WHERE e.batch_id=b.id AND e.collector=?)")
		args = append(args, filter.Collector)
	}
	if filter.EventType != "" {
		where = append(where, "EXISTS (SELECT 1 FROM events e WHERE e.batch_id=b.id AND e.event_type=?)")
		args = append(args, filter.EventType)
	}
	if filter.ResourceID != "" {
		where = append(where, "EXISTS (SELECT 1 FROM events e WHERE e.batch_id=b.id AND (e.resource_id LIKE ? ESCAPE '\\' OR e.name LIKE ? ESCAPE '\\'))")
		term := "%" + escapeLike(filter.ResourceID) + "%"
		args = append(args, term, term)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT b.id,b.generation,b.observed_at,b.change_count,COALESCE(b.trigger_id,0)
		FROM event_batches b WHERE `+strings.Join(where, " AND ")+` ORDER BY b.id DESC LIMIT ?`, args...)
	if err != nil {
		return HistoryPage{}, err
	}
	defer rows.Close()
	page := HistoryPage{Batches: make([]HistoryBatch, 0, limit), ByteLimit: byteLimit}
	candidates := make([]HistoryBatch, 0, limit+1)
	for rows.Next() {
		var batch HistoryBatch
		var observed string
		if err := rows.Scan(&batch.ID, &batch.Generation, &observed, &batch.ChangeCount, &batch.TriggerID); err != nil {
			return HistoryPage{}, err
		}
		batch.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
		if err != nil {
			return HistoryPage{}, fmt.Errorf("parse history batch timestamp: %w", err)
		}
		candidates = append(candidates, batch)
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, err
	}
	if err := rows.Close(); err != nil {
		return HistoryPage{}, err
	}
	hasMoreByCount := len(candidates) > limit
	if hasMoreByCount {
		candidates = candidates[:limit]
	}
	loadedBatches := make([]HistoryBatch, 0, len(candidates))
	for _, batch := range candidates {
		estimate, estimateErr := s.historyBatchByteEstimate(ctx, batch.ID, filter, includeLedgerPayload)
		if estimateErr != nil {
			return HistoryPage{}, estimateErr
		}
		if byteLimit > 0 && estimate > byteLimit-page.BytesRead {
			page.Truncated = true
			page.TruncationReason = "history page byte budget reached"
			break
		}
		loaded, err := s.loadHistoryBatch(ctx, batch, filter, includeLedgerPayload)
		if err != nil {
			return HistoryPage{}, err
		}
		if len(loaded.Events) > 0 {
			if filter.Collector != "" || filter.EventType != "" || filter.ResourceID != "" {
				loaded.ChangeCount = len(loaded.Events)
			}
			loadedBatches = append(loadedBatches, loaded)
			page.BytesRead += estimate
		}
	}
	page.Batches = loadedBatches
	page.HasNext = hasMoreByCount || page.Truncated
	if page.HasNext && len(page.Batches) > 0 {
		page.NextCursor = page.Batches[len(page.Batches)-1].ID
	} else if page.Truncated && len(candidates) > 0 {
		// The first batch can be larger than the entire page budget. Leave a
		// cursor just above it so the caller can retry after narrowing the
		// filter or increasing the configured budget; the explicit reason makes
		// that remediation visible instead of silently dropping the batch.
		page.NextCursor = candidates[0].ID + 1
	}
	if page.Truncated {
		s.counters.historyTruncations.Add(1)
	}
	return page, nil
}

// historyBatchByteEstimate reads only SQLite length metadata before loading a
// batch. Stored snapshots and event values are already bounded at write time,
// so this keeps normal history reads within a predictable aggregate budget
// without pulling an unbounded provider body into memory first.
func (s *Store) historyBatchByteEstimate(ctx context.Context, batchID int64, filter HistoryFilter, includeLedgerPayload bool) (int64, error) {
	eventWhere := []string{"batch_id=?"}
	eventArgs := []any{batchID}
	if filter.Collector != "" {
		eventWhere = append(eventWhere, "collector=?")
		eventArgs = append(eventArgs, filter.Collector)
	}
	if filter.EventType != "" {
		eventWhere = append(eventWhere, "event_type=?")
		eventArgs = append(eventArgs, filter.EventType)
	}
	if filter.ResourceID != "" {
		eventWhere = append(eventWhere, "(resource_id LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')")
		term := "%" + escapeLike(filter.ResourceID) + "%"
		eventArgs = append(eventArgs, term, term)
	}
	var eventBytes int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(
		length(COALESCE(changes_json,'')) + length(COALESCE(before_json,'')) + length(COALESCE(after_json,'')) +
		length(collector) + length(event_type) + length(resource_id) + length(name) + 128),0)
		FROM events WHERE `+strings.Join(eventWhere, " AND "), eventArgs...).Scan(&eventBytes); err != nil {
		return 0, err
	}
	var deliveryBytes int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(length(COALESCE(o.last_error,'')) + length(COALESCE(o.status,'')) + length(COALESCE(d.name,'')) + 128),0)
		FROM outbox o LEFT JOIN notification_destinations d ON d.id=o.destination_id WHERE o.batch_id=?`, batchID).Scan(&deliveryBytes); err != nil {
		return 0, err
	}
	var ledgerBytes int64
	if includeLedgerPayload {
		// The signed payload contains every event in the batch, not only the
		// events selected by the display filter. Include conservative framing
		// and base64/marshal overhead before loading it so the export budget
		// cannot be bypassed by a narrow filter.
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(
			length(COALESCE(changes_json,'')) + length(COALESCE(before_json,'')) + length(COALESCE(after_json,'')) +
			length(collector) + length(event_type) + length(resource_id) + length(name) + 256),0)
			FROM events WHERE batch_id=?`, batchID).Scan(&ledgerBytes); err != nil {
			return 0, err
		}
		// LedgerPayload is base64 encoded in evidence exports. Add a
		// conservative factor for that encoding and the surrounding JSON.
		ledgerBytes = ledgerBytes*2 + 2048
	}
	// Include fixed batch/ledger metadata and a small allowance for JSON
	// indentation used by the authenticated history renderer.
	estimate := eventBytes + deliveryBytes + ledgerBytes + 1024
	return estimate, nil
}

func (s *Store) loadHistoryBatch(ctx context.Context, batch HistoryBatch, filter HistoryFilter, includeLedgerPayload bool) (HistoryBatch, error) {
	triggerRows, err := s.db.QueryContext(ctx, "SELECT trigger_id FROM event_batch_triggers WHERE batch_id=? ORDER BY trigger_id", batch.ID)
	if err != nil {
		return HistoryBatch{}, err
	}
	for triggerRows.Next() {
		var triggerID int64
		if err := triggerRows.Scan(&triggerID); err != nil {
			triggerRows.Close()
			return HistoryBatch{}, err
		}
		if triggerID > 0 {
			batch.TriggerIDs = append(batch.TriggerIDs, triggerID)
		}
	}
	if err := triggerRows.Err(); err != nil {
		triggerRows.Close()
		return HistoryBatch{}, err
	}
	if err := triggerRows.Close(); err != nil {
		return HistoryBatch{}, err
	}
	if len(batch.TriggerIDs) == 0 && batch.TriggerID > 0 {
		batch.TriggerIDs = []int64{batch.TriggerID}
	}
	if err := s.db.QueryRowContext(ctx, "SELECT sequence,prev_hash,entry_hash,signature,key_id FROM evidence_ledger WHERE batch_id=?", batch.ID).Scan(&batch.LedgerSequence, &batch.LedgerPrevHash, &batch.LedgerHash, &batch.LedgerSignature, &batch.LedgerKeyID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return HistoryBatch{}, err
	}
	if includeLedgerPayload && batch.LedgerSequence > 0 {
		payload, _, payloadErr := evidenceLedgerPayload(ctx, s.db, batch.ID)
		if payloadErr != nil {
			return HistoryBatch{}, fmt.Errorf("load evidence ledger payload: %w", payloadErr)
		}
		batch.ledgerPayload = payload
	}
	eventWhere := []string{"batch_id=?"}
	eventArgs := []any{batch.ID}
	if filter.Collector != "" {
		eventWhere = append(eventWhere, "collector=?")
		eventArgs = append(eventArgs, filter.Collector)
	}
	if filter.EventType != "" {
		eventWhere = append(eventWhere, "event_type=?")
		eventArgs = append(eventArgs, filter.EventType)
	}
	if filter.ResourceID != "" {
		eventWhere = append(eventWhere, "(resource_id LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')")
		term := "%" + escapeLike(filter.ResourceID) + "%"
		eventArgs = append(eventArgs, term, term)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json,before_hash,after_hash,before_bytes,after_bytes,before_truncated,after_truncated
		FROM events WHERE `+strings.Join(eventWhere, " AND ")+` ORDER BY id`, eventArgs...)
	if err != nil {
		return HistoryBatch{}, err
	}
	defer rows.Close()
	batch.Events = make([]HistoryEvent, 0, batch.ChangeCount)
	for rows.Next() {
		var event HistoryEvent
		var observed string
		var fieldsRaw, beforeRaw, afterRaw []byte
		var beforeTruncated, afterTruncated int
		if err := rows.Scan(&event.ID, &event.BatchID, &event.Generation, &observed, &event.Collector, &event.EventType, &event.ResourceID, &event.Name, &fieldsRaw, &beforeRaw, &afterRaw, &event.BeforeHash, &event.AfterHash, &event.BeforeBytes, &event.AfterBytes, &beforeTruncated, &afterTruncated); err != nil {
			return HistoryBatch{}, err
		}
		event.BeforeTruncated = beforeTruncated == 1
		event.AfterTruncated = afterTruncated == 1
		if marker, ok := parseTruncationMarker(beforeRaw); ok {
			event.BeforeTruncated = true
			if event.BeforeHash == "" {
				event.BeforeHash = marker.TailState.SHA256
			}
			if event.BeforeBytes == 0 {
				event.BeforeBytes = marker.TailState.Bytes
			}
		}
		if marker, ok := parseTruncationMarker(afterRaw); ok {
			event.AfterTruncated = true
			if event.AfterHash == "" {
				event.AfterHash = marker.TailState.SHA256
			}
			if event.AfterBytes == 0 {
				event.AfterBytes = marker.TailState.Bytes
			}
		}
		if event.BeforeBytes == 0 && len(beforeRaw) > 0 {
			event.BeforeBytes = int64(len(beforeRaw))
		}
		if event.AfterBytes == 0 && len(afterRaw) > 0 {
			event.AfterBytes = int64(len(afterRaw))
		}
		if event.BeforeHash == "" && len(beforeRaw) > 0 && !event.BeforeTruncated {
			event.BeforeHash = valueHash(beforeRaw)
		}
		if event.AfterHash == "" && len(afterRaw) > 0 && !event.AfterTruncated {
			event.AfterHash = valueHash(afterRaw)
		}
		event.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
		if err != nil {
			return HistoryBatch{}, fmt.Errorf("parse history event timestamp: %w", err)
		}
		var fields []model.FieldChange
		if err := json.Unmarshal(fieldsRaw, &fields); err != nil && len(fieldsRaw) > 0 {
			var persisted persistedFields
			if envelopeErr := json.Unmarshal(fieldsRaw, &persisted); envelopeErr != nil {
				return HistoryBatch{}, fmt.Errorf("decode history fields: %w", err)
			}
			fields = persisted.Fields
			event.FieldsTruncated = persisted.FieldsTruncated
			event.TotalFields = persisted.TotalFields
		}
		if event.TotalFields == 0 {
			event.TotalFields = len(fields)
		}
		event.Fields = formatHistoryFields(fields)
		event.BeforeJSON = prettyJSON(beforeRaw)
		event.AfterJSON = prettyJSON(afterRaw)
		batch.Events = append(batch.Events, event)
	}
	if err := rows.Err(); err != nil {
		return HistoryBatch{}, err
	}
	if err := rows.Close(); err != nil {
		return HistoryBatch{}, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT o.id,o.destination_id,COALESCE(d.name,'Removed destination'),o.status,o.attempts,o.last_error,o.next_attempt,COALESCE(o.delivered_at,'')
		FROM outbox o LEFT JOIN notification_destinations d ON d.id=o.destination_id
		WHERE o.batch_id=? ORDER BY o.id`, batch.ID)
	if err != nil {
		return HistoryBatch{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var delivery HistoryDelivery
		var nextAttempt, deliveredAt string
		if err := rows.Scan(&delivery.ID, &delivery.DestinationID, &delivery.Destination, &delivery.Status, &delivery.Attempts, &delivery.LastError, &nextAttempt, &deliveredAt); err != nil {
			return HistoryBatch{}, err
		}
		if strings.TrimSpace(delivery.LastError) != "" {
			delivery.LastError = notify.SafeDeliveryMessage(delivery.LastError)
		}
		delivery.NextAttempt, err = parseOptionalTimeStrict(nextAttempt)
		if err != nil {
			return HistoryBatch{}, fmt.Errorf("parse notification next attempt: %w", err)
		}
		delivery.DeliveredAt, err = parseOptionalTimeStrict(deliveredAt)
		if err != nil {
			return HistoryBatch{}, fmt.Errorf("parse notification delivered timestamp: %w", err)
		}
		batch.Deliveries = append(batch.Deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return HistoryBatch{}, err
	}
	if err := rows.Close(); err != nil {
		return HistoryBatch{}, err
	}
	return batch, nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func formatHistoryFields(fields []model.FieldChange) []HistoryFieldChange {
	out := make([]HistoryFieldChange, 0, len(fields))
	for _, field := range fields {
		formatted := HistoryFieldChange{
			Field:  field.Field,
			HasOld: field.OldPresent || field.Old != nil,
			HasNew: field.NewPresent || field.New != nil,
		}
		if formatted.HasOld {
			if field.OldPresent && field.Old == nil {
				formatted.Old = "null"
			} else {
				formatted.Old = prettyValue(field.Old)
			}
		}
		if formatted.HasNew {
			if field.NewPresent && field.New == nil {
				formatted.New = "null"
			} else {
				formatted.New = prettyValue(field.New)
			}
		}
		out = append(out, formatted)
	}
	return out
}

func prettyJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return string(raw)
	}
	return prettyValue(value)
}

func prettyValue(value any) string {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}

func parseOptionalTimeStrict(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func truncate(value string, n int) string {
	return textutil.Truncate(value, n)
}

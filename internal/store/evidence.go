package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	evidencePackFormat  = "tailstate-drift-evidence"
	evidencePackVersion = 1
	maxEvidenceBatches  = 100
	maxEvidenceEvents   = 2000
	maxEvidenceBytes    = 5 << 20
)

// ErrEvidencePackTooLarge indicates that the selected history cannot be
// exported within the bounded response size.
var ErrEvidencePackTooLarge = errors.New("history evidence pack exceeds the size limit")

// EvidencePack is a redacted, portable representation of explainable drift
// history. ContentSHA256 covers the stable content and excludes GeneratedAt,
// allowing consumers to verify the event data without requiring a signature
// key from the TailState instance.
type EvidencePack struct {
	Format        string          `json:"format"`
	Version       int             `json:"version"`
	GeneratedAt   string          `json:"generated_at"`
	Filter        EvidenceFilter  `json:"filter"`
	Batches       []EvidenceBatch `json:"batches"`
	Truncated     bool            `json:"truncated"`
	NextCursor    int64           `json:"next_cursor,omitempty"`
	ContentSHA256 string          `json:"content_sha256"`
}

// EvidenceFilter records the filters used to create an evidence pack.
type EvidenceFilter struct {
	Collector  string `json:"collector,omitempty"`
	EventType  string `json:"event_type,omitempty"`
	ResourceID string `json:"resource,omitempty"`
	Cursor     int64  `json:"cursor,omitempty"`
	Limit      int    `json:"limit"`
}

// EvidenceBatch contains one atomic polling result and its related events and
// notification outcomes.
type EvidenceBatch struct {
	ID          int64              `json:"id"`
	Generation  int64              `json:"generation"`
	ObservedAt  time.Time          `json:"observed_at"`
	ChangeCount int                `json:"change_count"`
	TriggerID   int64              `json:"trigger_id,omitempty"`
	TriggerIDs  []int64            `json:"trigger_ids,omitempty"`
	Events      []EvidenceEvent    `json:"events"`
	Deliveries  []EvidenceDelivery `json:"deliveries"`
}

// EvidenceEvent contains normalized snapshots and field-level changes. URL
// and secret-like values have already been removed or fingerprinted by the
// model normalization and history persistence paths.
type EvidenceEvent struct {
	ID         int64           `json:"id"`
	BatchID    int64           `json:"batch_id"`
	Generation int64           `json:"generation"`
	ObservedAt time.Time       `json:"observed_at"`
	Collector  string          `json:"collector"`
	EventType  string          `json:"event_type"`
	ResourceID string          `json:"resource_id"`
	Name       string          `json:"name"`
	Fields     []EvidenceField `json:"fields,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
}

// EvidenceField is a machine-readable field-level diff. Missing old or new
// values are omitted, while an explicit JSON null remains distinguishable.
type EvidenceField struct {
	Field string          `json:"field"`
	Old   json.RawMessage `json:"old,omitempty"`
	New   json.RawMessage `json:"new,omitempty"`
}

// EvidenceDelivery records destination-specific delivery state without
// including service URLs or credentials.
type EvidenceDelivery struct {
	ID            int64      `json:"id"`
	DestinationID int64      `json:"destination_id"`
	Destination   string     `json:"destination"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	LastError     string     `json:"last_error,omitempty"`
	NextAttempt   *time.Time `json:"next_attempt,omitempty"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

type evidenceContent struct {
	Format     string          `json:"format"`
	Version    int             `json:"version"`
	Filter     EvidenceFilter  `json:"filter"`
	Batches    []EvidenceBatch `json:"batches"`
	Truncated  bool            `json:"truncated"`
	NextCursor int64           `json:"next_cursor,omitempty"`
}

// ExportEvidencePack returns a bounded JSON export of the matching history.
// It includes at most 100 batches and 2,000 events, and refuses responses
// larger than 5 MiB so an unusually large drift cannot exhaust the web
// process while being downloaded.
func (s *Store) ExportEvidencePack(ctx context.Context, filter HistoryFilter) ([]byte, error) {
	filter.Limit = maxEvidenceBatches
	page, err := s.ListHistory(ctx, filter)
	if err != nil {
		return nil, err
	}
	pack := EvidencePack{
		Format:      evidencePackFormat,
		Version:     evidencePackVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Filter:      EvidenceFilter(filter),
		Batches:     make([]EvidenceBatch, 0, len(page.Batches)),
		Truncated:   page.HasNext,
		NextCursor:  page.NextCursor,
	}

	eventCount := 0
	for _, batch := range page.Batches {
		converted := evidenceBatch(batch)
		eventCount += len(converted.Events)
		if eventCount > maxEvidenceEvents {
			return nil, ErrEvidencePackTooLarge
		}
		pack.Batches = append(pack.Batches, converted)
	}
	content, err := evidencePayload(pack)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(content)
	pack.ContentSHA256 = hex.EncodeToString(hash[:])
	encoded, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxEvidenceBytes {
		return nil, ErrEvidencePackTooLarge
	}
	return encoded, nil
}

// VerifyEvidencePack verifies the content hash in an exported pack. It does
// not establish who produced the pack; use a separately managed signature if
// authenticity beyond tamper evidence is required.
func VerifyEvidencePack(data []byte) error {
	var pack EvidencePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return fmt.Errorf("decode evidence pack: %w", err)
	}
	if pack.Format != evidencePackFormat || pack.Version != evidencePackVersion {
		return fmt.Errorf("unsupported evidence pack format %q version %d", pack.Format, pack.Version)
	}
	content, err := evidencePayload(pack)
	if err != nil {
		return fmt.Errorf("encode evidence pack content: %w", err)
	}
	hash := sha256.Sum256(content)
	if pack.ContentSHA256 != hex.EncodeToString(hash[:]) {
		return errors.New("evidence pack content hash mismatch")
	}
	return nil
}

func evidencePayload(pack EvidencePack) ([]byte, error) {
	return json.Marshal(evidenceContent{
		Format:     pack.Format,
		Version:    pack.Version,
		Filter:     pack.Filter,
		Batches:    pack.Batches,
		Truncated:  pack.Truncated,
		NextCursor: pack.NextCursor,
	})
}

func evidenceBatch(batch HistoryBatch) EvidenceBatch {
	out := EvidenceBatch{
		ID:          batch.ID,
		Generation:  batch.Generation,
		ObservedAt:  batch.ObservedAt,
		ChangeCount: batch.ChangeCount,
		TriggerID:   batch.TriggerID,
		TriggerIDs:  append([]int64(nil), batch.TriggerIDs...),
		Events:      make([]EvidenceEvent, 0, len(batch.Events)),
		Deliveries:  make([]EvidenceDelivery, 0, len(batch.Deliveries)),
	}
	for _, event := range batch.Events {
		converted := EvidenceEvent{
			ID:         event.ID,
			BatchID:    event.BatchID,
			Generation: event.Generation,
			ObservedAt: event.ObservedAt,
			Collector:  event.Collector,
			EventType:  event.EventType,
			ResourceID: event.ResourceID,
			Name:       event.Name,
			Before:     evidenceJSON(event.BeforeJSON),
			After:      evidenceJSON(event.AfterJSON),
			Fields:     make([]EvidenceField, 0, len(event.Fields)),
		}
		for _, field := range event.Fields {
			converted.Fields = append(converted.Fields, EvidenceField{
				Field: field.Field,
				Old:   evidenceJSON(field.Old),
				New:   evidenceJSON(field.New),
			})
		}
		out.Events = append(out.Events, converted)
	}
	for _, delivery := range batch.Deliveries {
		out.Deliveries = append(out.Deliveries, EvidenceDelivery(delivery))
	}
	return out
}

func evidenceJSON(value string) json.RawMessage {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if json.Valid([]byte(value)) {
		return json.RawMessage(value)
	}
	encoded, _ := json.Marshal(value)
	return json.RawMessage(encoded)
}

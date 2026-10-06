package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

const (
	evidencePackFormat  = "tailstate-drift-evidence"
	evidencePackVersion = 5
	// evidencePackVersionV4 packs predate change attribution, and
	// evidencePackVersionV3 packs also per-event severity and mute flags.
	// Both are still verified with their original signature domain.
	evidencePackVersionV4     = 4
	evidencePackVersionV3     = 3
	maxEvidenceBatches        = 100
	maxEvidenceEvents         = 2000
	maxEvidenceBytes          = 5 << 20
	maxEvidenceLedgerLinks    = 10000
	maxEvidencePublicKeyBytes = 4 << 10
)

// evidenceLedgerLinkLimit bounds the ledger links carried by one pack. It is
// a variable so tests can exercise the link budget without 10,000 batches.
var evidenceLedgerLinkLimit = maxEvidenceLedgerLinks

// EvidencePackLimitBytes is the maximum serialized evidence pack accepted by
// both exporters and verifiers.
const EvidencePackLimitBytes = maxEvidenceBytes

// EvidencePublicKeyLimitBytes bounds textual key material before decoding.
const EvidencePublicKeyLimitBytes = maxEvidencePublicKeyBytes

// ErrEvidencePackTooLarge indicates that not even the newest selected batch
// can be exported within the bounded pack size.
var ErrEvidencePackTooLarge = errors.New("history evidence pack exceeds the size limit")

// EvidencePack is a redacted, portable representation of explainable drift
// history. Packs include an Ed25519 signature over the content hash, ledger
// head, generation timestamp, and signing-key fingerprint. Version 4 adds the
// per-event severity and muted flag and version 5 the change attribution;
// version 3 and 4 packs remain verifiable.
type EvidencePack struct {
	Format           string               `json:"format"`
	Version          int                  `json:"version"`
	GeneratedAt      string               `json:"generated_at"`
	Filter           EvidenceFilter       `json:"filter"`
	Batches          []EvidenceBatch      `json:"batches"`
	LedgerLinks      []EvidenceLedgerLink `json:"ledger_links,omitempty"`
	Truncated        bool                 `json:"truncated"`
	NextCursor       int64                `json:"next_cursor,omitempty"`
	ContentSHA256    string               `json:"content_sha256"`
	SigningKeyID     string               `json:"signing_key_id,omitempty"`
	SigningPublicKey string               `json:"signing_public_key,omitempty"`
	LedgerHead       string               `json:"ledger_head,omitempty"`
	Signature        string               `json:"signature,omitempty"`
}

// EvidenceFilter records the filters used to create an evidence pack.
type EvidenceFilter struct {
	Collector  string `json:"collector,omitempty"`
	EventType  string `json:"event_type,omitempty"`
	ResourceID string `json:"resource,omitempty"`
	// From and Until are the RFC 3339 UTC bounds of a date-range filter
	// (inclusive and exclusive). They are omitted when no range was used, so
	// packs without a range keep their original signed shape.
	From     string `json:"from,omitempty"`
	Until    string `json:"until,omitempty"`
	Cursor   int64  `json:"cursor,omitempty"`
	Limit    int    `json:"limit"`
	BatchID  int64  `json:"batch,omitempty"`
	Severity string `json:"severity,omitempty"`
}

func evidenceFilter(filter HistoryFilter) EvidenceFilter {
	out := EvidenceFilter{Collector: filter.Collector, EventType: filter.EventType, ResourceID: filter.ResourceID, Cursor: filter.Cursor, Limit: filter.Limit, BatchID: filter.BatchID, Severity: filter.Severity}
	if !filter.From.IsZero() {
		out.From = filter.From.UTC().Format(time.RFC3339)
	}
	if !filter.Until.IsZero() {
		out.Until = filter.Until.UTC().Format(time.RFC3339)
	}
	return out
}

// EvidenceBatch contains one atomic polling result and its related events and
// notification outcomes.
type EvidenceBatch struct {
	ID          int64     `json:"id"`
	Generation  int64     `json:"generation"`
	ObservedAt  time.Time `json:"observed_at"`
	ChangeCount int       `json:"change_count"`
	// LedgerChangeCount preserves the unfiltered event count used by the
	// signed ledger payload. A history filter may include only some events from
	// a batch, while the ledger must still verify the original batch metadata.
	LedgerChangeCount int     `json:"ledger_change_count,omitempty"`
	TriggerID         int64   `json:"trigger_id,omitempty"`
	TriggerIDs        []int64 `json:"trigger_ids,omitempty"`
	LedgerSequence    int64   `json:"ledger_sequence,omitempty"`
	LedgerPrevHash    string  `json:"ledger_prev_hash,omitempty"`
	LedgerHash        string  `json:"ledger_hash,omitempty"`
	LedgerSignature   string  `json:"ledger_signature,omitempty"`
	LedgerKeyID       string  `json:"ledger_key_id,omitempty"`
	LedgerPayload     string  `json:"ledger_payload,omitempty"`
	// AttributionStatus is the configuration audit lookup outcome for the
	// batch (version 5): "complete", "unavailable", or "unsupported".
	AttributionStatus string             `json:"attribution_status,omitempty"`
	Events            []EvidenceEvent    `json:"events"`
	Deliveries        []EvidenceDelivery `json:"deliveries"`
}

// EvidenceLedgerLink carries the signed chain links between exported batches.
// Links for omitted, filtered batches let offline verification prove chain
// continuity without exposing their event payloads.
type EvidenceLedgerLink struct {
	Sequence  int64  `json:"sequence"`
	BatchID   int64  `json:"batch_id"`
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

// EvidenceEvent contains normalized snapshots and field-level changes. URL
// and secret-like values have already been removed or fingerprinted by the
// model normalization and history persistence paths.
type EvidenceEvent struct {
	ID              int64           `json:"id"`
	BatchID         int64           `json:"batch_id"`
	Generation      int64           `json:"generation"`
	ObservedAt      time.Time       `json:"observed_at"`
	Collector       string          `json:"collector"`
	EventType       string          `json:"event_type"`
	ResourceID      string          `json:"resource_id"`
	Name            string          `json:"name"`
	Fields          []EvidenceField `json:"fields,omitempty"`
	FieldsTruncated bool            `json:"fields_truncated,omitempty"`
	TotalFields     int             `json:"total_fields,omitempty"`
	Before          json.RawMessage `json:"before,omitempty"`
	After           json.RawMessage `json:"after,omitempty"`
	BeforeHash      string          `json:"before_sha256,omitempty"`
	AfterHash       string          `json:"after_sha256,omitempty"`
	BeforeBytes     int64           `json:"before_bytes,omitempty"`
	AfterBytes      int64           `json:"after_bytes,omitempty"`
	BeforeTruncated bool            `json:"before_truncated,omitempty"`
	AfterTruncated  bool            `json:"after_truncated,omitempty"`
	// Severity is the built-in classification recorded with the event
	// (version 4). It is covered by the pack signature; the ledger payload
	// does not carry it because it is derived from the signed change.
	Severity string `json:"severity,omitempty"`
	// Muted marks a change left out of notifications by a mute rule
	// (version 4). It is bound to the signed ledger payload.
	Muted bool `json:"muted,omitempty"`
	// Attribution names who made the change according to the configuration
	// audit log (version 5). It is bound to the signed ledger payload.
	Attribution *model.Attribution `json:"attribution,omitempty"`
}

// EvidenceField is a machine-readable field-level diff. Missing old or new
// values are omitted, while an explicit JSON null remains distinguishable.
type EvidenceField struct {
	Field      string          `json:"field"`
	Old        json.RawMessage `json:"old,omitempty"`
	New        json.RawMessage `json:"new,omitempty"`
	OldPresent bool            `json:"old_present,omitempty"`
	NewPresent bool            `json:"new_present,omitempty"`
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
	Format      string               `json:"format"`
	Version     int                  `json:"version"`
	Filter      EvidenceFilter       `json:"filter"`
	Batches     []EvidenceBatch      `json:"batches"`
	LedgerLinks []EvidenceLedgerLink `json:"ledger_links,omitempty"`
	Truncated   bool                 `json:"truncated"`
	NextCursor  int64                `json:"next_cursor,omitempty"`
	LedgerHead  string               `json:"ledger_head,omitempty"`
}

// ExportEvidencePack returns a bounded JSON export of the matching history,
// newest batch first. A pack holds at most filter.Limit (capped at 100)
// batches, 2,000 events, and 5 MiB so an unusually large drift cannot exhaust
// the web process while being downloaded.
//
// When a budget is reached the pack is a part of a paginated chain rather
// than an error: it carries the newest batches that fit, Truncated=true, and
// NextCursor set to its oldest batch ID. Exporting again with
// filter.Cursor=NextCursor returns the next part, so the chain covers every
// matching batch exactly once and each part verifies on its own.
// ErrEvidencePackTooLarge is returned only when not even one batch fits.
func (s *Store) ExportEvidencePack(ctx context.Context, filter HistoryFilter) ([]byte, error) {
	if filter.Limit <= 0 || filter.Limit > maxEvidenceBatches {
		filter.Limit = maxEvidenceBatches
	}
	// Exports always page towards older batches from Cursor.
	filter.After = 0
	page, err := s.listHistory(ctx, filter, maxEvidenceBytes, true)
	if err != nil {
		return nil, err
	}
	if len(page.Batches) == 0 && page.Truncated {
		// The newest matching batch alone exceeds the read budget.
		return nil, ErrEvidencePackTooLarge
	}
	ledgerHead, err := s.evidenceLedgerHead(ctx)
	if err != nil {
		return nil, err
	}
	links, err := s.evidenceLedgerLinks(ctx, page.Batches)
	if err != nil {
		return nil, err
	}
	batches := make([]EvidenceBatch, 0, len(page.Batches))
	for _, batch := range page.Batches {
		batches = append(batches, evidenceBatch(batch))
	}
	if err := validateLedgerBatchState(batches); err != nil {
		return nil, err
	}
	fit := evidenceBatchesWithinCaps(batches, links)
	if fit == 0 && len(batches) > 0 {
		return nil, ErrEvidencePackTooLarge
	}
	generatedAt := time.Now().UTC().Format(time.RFC3339Nano)
	build := func(count int) ([]byte, error) {
		pack := EvidencePack{
			Format:      evidencePackFormat,
			Version:     evidencePackVersion,
			GeneratedAt: generatedAt,
			Filter:      evidenceFilter(filter),
			Batches:     batches[:count],
			LedgerLinks: evidenceLinksFor(batches[:count], links),
			Truncated:   page.HasNext,
			NextCursor:  page.NextCursor,
			LedgerHead:  ledgerHead,
		}
		if count < len(batches) {
			pack.Truncated = true
			pack.NextCursor = batches[count-1].ID
		}
		return s.signEvidencePack(pack)
	}
	encoded, err := build(fit)
	if err != nil || len(encoded) <= maxEvidenceBytes {
		return encoded, err
	}
	// Encoded size grows with every batch, so the largest prefix that fits
	// is found with a binary search over [1, fit).
	good, bad := 0, fit
	var goodEncoded []byte
	for good+1 < bad {
		middle := (good + bad) / 2
		candidate, err := build(middle)
		if err != nil {
			return nil, err
		}
		if len(candidate) <= maxEvidenceBytes {
			good, goodEncoded = middle, candidate
		} else {
			bad = middle
		}
	}
	if good == 0 {
		return nil, ErrEvidencePackTooLarge
	}
	return goodEncoded, nil
}

// evidenceBatchesWithinCaps returns how many leading batches fit both the
// per-pack event cap and the fetched ledger-link segment.
func evidenceBatchesWithinCaps(batches []EvidenceBatch, links []EvidenceLedgerLink) int {
	firstLink := int64(0)
	if len(links) > 0 {
		firstLink = links[0].Sequence
	}
	events := 0
	for index, batch := range batches {
		events += len(batch.Events)
		if events > maxEvidenceEvents {
			return index
		}
		if batch.LedgerSequence > 0 && ledgerCheckpointSequence(batch.LedgerSequence) < firstLink {
			return index
		}
	}
	return len(batches)
}

// evidenceLinksFor narrows the fetched ledger segment to the one spanning
// the given batches and their checkpoint predecessor.
func evidenceLinksFor(batches []EvidenceBatch, links []EvidenceLedgerLink) []EvidenceLedgerLink {
	var minSequence, maxSequence int64
	for _, batch := range batches {
		if batch.LedgerSequence == 0 {
			continue
		}
		if minSequence == 0 || batch.LedgerSequence < minSequence {
			minSequence = batch.LedgerSequence
		}
		maxSequence = max(maxSequence, batch.LedgerSequence)
	}
	out := make([]EvidenceLedgerLink, 0)
	if minSequence == 0 {
		return out
	}
	start := ledgerCheckpointSequence(minSequence)
	for _, link := range links {
		if link.Sequence >= start && link.Sequence <= maxSequence {
			out = append(out, link)
		}
	}
	return out
}

// signEvidencePack hashes, signs, and encodes a pack.
func (s *Store) signEvidencePack(pack EvidencePack) ([]byte, error) {
	content, err := evidencePayload(pack)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(content)
	pack.ContentSHA256 = hex.EncodeToString(hash[:])
	pack.SigningKeyID = s.evidenceKey.keyID
	pack.SigningPublicKey = base64.RawStdEncoding.EncodeToString(s.evidenceKey.public)
	pack.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.evidenceKey.private, evidenceSignaturePayload(pack)))
	encoded, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func evidencePayload(pack EvidencePack) ([]byte, error) {
	return json.Marshal(evidenceContent{
		Format:      pack.Format,
		Version:     pack.Version,
		Filter:      pack.Filter,
		Batches:     pack.Batches,
		LedgerLinks: pack.LedgerLinks,
		Truncated:   pack.Truncated,
		NextCursor:  pack.NextCursor,
		LedgerHead:  pack.LedgerHead,
	})
}

func evidenceBatch(batch HistoryBatch) EvidenceBatch {
	ledgerChangeCount := batch.ChangeCount
	if len(batch.ledgerPayload) > 0 {
		var ledgerBatch evidenceLedgerBatch
		if err := json.Unmarshal(batch.ledgerPayload, &ledgerBatch); err == nil && ledgerBatch.ChangeCount > 0 {
			ledgerChangeCount = ledgerBatch.ChangeCount
		}
	}
	out := EvidenceBatch{
		ID:                batch.ID,
		Generation:        batch.Generation,
		ObservedAt:        batch.ObservedAt,
		ChangeCount:       batch.ChangeCount,
		LedgerChangeCount: ledgerChangeCount,
		TriggerID:         batch.TriggerID,
		TriggerIDs:        append([]int64(nil), batch.TriggerIDs...),
		LedgerSequence:    batch.LedgerSequence,
		LedgerPrevHash:    batch.LedgerPrevHash,
		LedgerHash:        batch.LedgerHash,
		LedgerSignature:   batch.LedgerSignature,
		LedgerKeyID:       batch.LedgerKeyID,
		LedgerPayload:     base64.RawStdEncoding.EncodeToString(batch.ledgerPayload),
		AttributionStatus: batch.AttributionStatus,
		Events:            make([]EvidenceEvent, 0, len(batch.Events)),
		Deliveries:        make([]EvidenceDelivery, 0, len(batch.Deliveries)),
	}
	for _, event := range batch.Events {
		converted := EvidenceEvent{
			ID:              event.ID,
			BatchID:         event.BatchID,
			Generation:      event.Generation,
			ObservedAt:      event.ObservedAt,
			Collector:       event.Collector,
			EventType:       event.EventType,
			ResourceID:      event.ResourceID,
			Name:            event.Name,
			FieldsTruncated: event.FieldsTruncated,
			TotalFields:     event.TotalFields,
			Before:          evidenceJSON(event.BeforeJSON),
			After:           evidenceJSON(event.AfterJSON),
			BeforeHash:      event.BeforeHash,
			AfterHash:       event.AfterHash,
			BeforeBytes:     event.BeforeBytes,
			AfterBytes:      event.AfterBytes,
			BeforeTruncated: event.BeforeTruncated,
			AfterTruncated:  event.AfterTruncated,
			Severity:        event.Severity,
			Muted:           event.Muted,
			Attribution:     event.Attribution,
			Fields:          make([]EvidenceField, 0, len(event.Fields)),
		}
		for _, field := range event.Fields {
			converted.Fields = append(converted.Fields, EvidenceField{
				Field:      field.Field,
				Old:        evidenceJSON(field.Old),
				New:        evidenceJSON(field.New),
				OldPresent: field.HasOld,
				NewPresent: field.HasNew,
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

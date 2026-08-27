package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

const (
	evidencePackFormat     = "tailstate-drift-evidence"
	evidencePackVersion    = 3
	maxEvidenceBatches     = 100
	maxEvidenceEvents      = 2000
	maxEvidenceBytes       = 5 << 20
	maxEvidenceLedgerLinks = 10000
)

// ErrEvidencePackTooLarge indicates that the selected history cannot be
// exported within the bounded response size.
var ErrEvidencePackTooLarge = errors.New("history evidence pack exceeds the size limit")

// EvidencePack is a redacted, portable representation of explainable drift
// history. Version 3 packs include an Ed25519 signature over the content hash,
// ledger head, generation timestamp, and signing-key fingerprint.
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
	Cursor     int64  `json:"cursor,omitempty"`
	Limit      int    `json:"limit"`
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
	LedgerChangeCount int                `json:"ledger_change_count,omitempty"`
	TriggerID         int64              `json:"trigger_id,omitempty"`
	TriggerIDs        []int64            `json:"trigger_ids,omitempty"`
	LedgerSequence    int64              `json:"ledger_sequence,omitempty"`
	LedgerPrevHash    string             `json:"ledger_prev_hash,omitempty"`
	LedgerHash        string             `json:"ledger_hash,omitempty"`
	LedgerSignature   string             `json:"ledger_signature,omitempty"`
	LedgerKeyID       string             `json:"ledger_key_id,omitempty"`
	LedgerPayload     string             `json:"ledger_payload,omitempty"`
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

// ExportEvidencePack returns a bounded JSON export of the matching history.
// It includes at most 100 batches and 2,000 events, and refuses responses
// larger than 5 MiB so an unusually large drift cannot exhaust the web
// process while being downloaded.
func (s *Store) ExportEvidencePack(ctx context.Context, filter HistoryFilter) ([]byte, error) {
	filter.Limit = maxEvidenceBatches
	page, err := s.listHistory(ctx, filter, maxEvidenceBytes)
	if err != nil {
		return nil, err
	}
	if page.Truncated {
		return nil, ErrEvidencePackTooLarge
	}
	pack := EvidencePack{
		Format:      evidencePackFormat,
		Version:     evidencePackVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Filter:      EvidenceFilter(filter),
		Batches:     make([]EvidenceBatch, 0, len(page.Batches)),
		LedgerLinks: make([]EvidenceLedgerLink, 0),
		Truncated:   page.HasNext,
		NextCursor:  page.NextCursor,
	}
	pack.LedgerHead, err = s.evidenceLedgerHead(ctx)
	if err != nil {
		return nil, err
	}
	pack.LedgerLinks, err = s.evidenceLedgerLinks(ctx, page.Batches)
	if err != nil {
		return nil, err
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
	if err := validateLedgerBatchState(pack.Batches); err != nil {
		return nil, err
	}
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
	encoded = append(encoded, '\n')
	if len(encoded) > maxEvidenceBytes {
		return nil, ErrEvidencePackTooLarge
	}
	return encoded, nil
}

// VerifyEvidencePack verifies the embedded content hash and signature. The
// embedded public key identifies the producer; use VerifyEvidencePackWithKey
// when the caller has an independently trusted public key.
func VerifyEvidencePack(data []byte) error {
	return verifyEvidencePack(data, nil)
}

// VerifyEvidencePackWithKey verifies an evidence pack against a trusted
// Ed25519 public key rather than trusting the key embedded in the pack.
func VerifyEvidencePackWithKey(data, trustedPublic []byte) error {
	if len(trustedPublic) != ed25519.PublicKeySize {
		return errors.New("trusted evidence public key must be 32 bytes")
	}
	return verifyEvidencePack(data, trustedPublic)
}

func verifyEvidencePack(data, trustedPublic []byte) error {
	var pack EvidencePack
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pack); err != nil {
		return fmt.Errorf("decode evidence pack: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("evidence pack contains trailing JSON")
		}
		return fmt.Errorf("decode evidence pack: %w", err)
	}
	if pack.Format != evidencePackFormat {
		return fmt.Errorf("unsupported evidence pack format %q version %d", pack.Format, pack.Version)
	}
	if pack.Version != evidencePackVersion {
		return fmt.Errorf("unsupported evidence pack format %q version %d", pack.Format, pack.Version)
	}
	if pack.Truncated {
		if pack.NextCursor <= 0 {
			return errors.New("truncated evidence pack is missing next cursor")
		}
		if len(pack.Batches) == 0 {
			return errors.New("truncated evidence pack has no batches")
		}
		if pack.Batches[len(pack.Batches)-1].ID != pack.NextCursor {
			return errors.New("truncated evidence pack cursor does not match last batch")
		}
	} else if pack.NextCursor != 0 {
		return errors.New("complete evidence pack has an unexpected next cursor")
	}
	content, err := evidencePayload(pack)
	if err != nil {
		return fmt.Errorf("encode evidence pack content: %w", err)
	}
	hash := sha256.Sum256(content)
	if pack.ContentSHA256 != hex.EncodeToString(hash[:]) {
		return errors.New("evidence pack content hash mismatch")
	}
	if pack.SigningKeyID == "" || pack.SigningPublicKey == "" || pack.Signature == "" {
		return errors.New("evidence pack signature metadata is incomplete")
	}
	public, err := decodeKeyMaterial(pack.SigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("decode evidence signing public key: %w", err)
	}
	if pack.SigningKeyID != evidenceKeyID(public) {
		return errors.New("evidence signing key fingerprint mismatch")
	}
	if len(trustedPublic) > 0 && !bytes.Equal(public, trustedPublic) {
		return errors.New("evidence signing key is not trusted")
	}
	signature, err := decodeKeyMaterial(pack.Signature, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("decode evidence signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(public), evidenceSignaturePayload(pack), signature) {
		return errors.New("evidence pack signature verification failed")
	}
	if err := verifyLedgerLinks(pack); err != nil {
		return err
	}
	return nil
}

func evidenceSignaturePayload(pack EvidencePack) []byte {
	return []byte("tailstate-evidence-pack-v3\n" + pack.ContentSHA256 + "\n" + pack.LedgerHead + "\n" + pack.GeneratedAt + "\n" + pack.SigningKeyID)
}

func validateLedgerBatchState(batches []EvidenceBatch) error {
	hasLedgeredBatch := false
	hasUnledgeredBatch := false
	for _, batch := range batches {
		if batch.LedgerSequence < 0 {
			return fmt.Errorf("invalid ledger sequence for batch %d", batch.ID)
		}
		if batch.LedgerSequence == 0 {
			hasUnledgeredBatch = true
		} else {
			hasLedgeredBatch = true
		}
	}
	if hasLedgeredBatch && hasUnledgeredBatch {
		return errors.New("evidence ledger metadata is incomplete: pack mixes ledgered and unledgered batches")
	}
	return nil
}

// verifyLedgerPayloadBinding checks that the human-readable export is a
// faithful projection of the signed ledger payload. A filtered history export
// may intentionally omit events, so every visible event is matched against
// the complete payload rather than requiring the two lists to have the same
// length. This keeps the ledger proof useful for filtered exports while still
// preventing a payload/event mismatch from being accepted as verified.
func verifyLedgerPayloadBinding(batch EvidenceBatch, ledgerBatch evidenceLedgerBatch) error {
	if ledgerBatch.BatchID != batch.ID || ledgerBatch.Generation != batch.Generation {
		return fmt.Errorf("ledger payload metadata mismatch for batch %d", batch.ID)
	}
	changeCount := batch.LedgerChangeCount
	if changeCount == 0 {
		changeCount = batch.ChangeCount
	}
	if ledgerBatch.ChangeCount != changeCount {
		return fmt.Errorf("ledger payload metadata mismatch for batch %d", batch.ID)
	}
	if len(ledgerBatch.Events) != ledgerBatch.ChangeCount {
		return fmt.Errorf("ledger payload event count mismatch for batch %d", batch.ID)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, ledgerBatch.ObservedAt)
	if err != nil || !observedAt.Equal(batch.ObservedAt) {
		return fmt.Errorf("ledger payload timestamp mismatch for batch %d", batch.ID)
	}
	if ledgerBatch.TriggerID != batch.TriggerID || !equalInt64Slices(ledgerBatch.TriggerIDs, batch.TriggerIDs) {
		return fmt.Errorf("ledger payload trigger metadata mismatch for batch %d", batch.ID)
	}

	byID := make(map[int64]evidenceLedgerEvent, len(ledgerBatch.Events))
	for _, event := range ledgerBatch.Events {
		if _, exists := byID[event.ID]; exists {
			return fmt.Errorf("ledger payload contains duplicate event %d for batch %d", event.ID, batch.ID)
		}
		byID[event.ID] = event
	}
	seen := make(map[int64]struct{}, len(batch.Events))
	for _, event := range batch.Events {
		if _, exists := seen[event.ID]; exists {
			return fmt.Errorf("evidence export contains duplicate event %d for batch %d", event.ID, batch.ID)
		}
		seen[event.ID] = struct{}{}
		ledgerEvent, exists := byID[event.ID]
		if !exists {
			return fmt.Errorf("ledger payload is missing event %d for batch %d", event.ID, batch.ID)
		}
		if err := verifyLedgerEventBinding(event, ledgerEvent, batch.ID); err != nil {
			return err
		}
	}
	return nil
}

func verifyLedgerEventBinding(event EvidenceEvent, ledgerEvent evidenceLedgerEvent, batchID int64) error {
	if event.BatchID != batchID || event.Generation != ledgerEvent.Generation || event.Collector != ledgerEvent.Collector || event.EventType != ledgerEvent.EventType || event.ResourceID != ledgerEvent.ResourceID || event.Name != ledgerEvent.Name {
		return fmt.Errorf("ledger payload event metadata mismatch for event %d in batch %d", event.ID, batchID)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, ledgerEvent.ObservedAt)
	if err != nil || !observedAt.Equal(event.ObservedAt) {
		return fmt.Errorf("ledger payload event timestamp mismatch for event %d in batch %d", event.ID, batchID)
	}
	fields, fieldsTruncated, totalFields, err := evidenceFieldsFromLedger([]byte(ledgerEvent.Changes))
	if err != nil {
		return fmt.Errorf("decode ledger event fields for event %d in batch %d: %w", event.ID, batchID, err)
	}
	if fieldsTruncated != event.FieldsTruncated || totalFields != event.TotalFields || !equalEvidenceFields(fields, event.Fields) {
		return fmt.Errorf("ledger payload event fields mismatch for event %d in batch %d", event.ID, batchID)
	}
	if !equalEvidenceJSON(evidenceJSON(prettyJSON([]byte(ledgerEvent.Before))), event.Before) || !equalEvidenceJSON(evidenceJSON(prettyJSON([]byte(ledgerEvent.After))), event.After) {
		return fmt.Errorf("ledger payload event snapshot mismatch for event %d in batch %d", event.ID, batchID)
	}
	if err := verifyEvidenceSnapshotMetadata(event.BeforeHash, event.BeforeBytes, event.BeforeTruncated, ledgerEvent.Before, "before", event.ID, batchID); err != nil {
		return err
	}
	if err := verifyEvidenceSnapshotMetadata(event.AfterHash, event.AfterBytes, event.AfterTruncated, ledgerEvent.After, "after", event.ID, batchID); err != nil {
		return err
	}
	return nil
}

func verifyEvidenceSnapshotMetadata(hash string, bytes int64, truncated bool, raw, label string, eventID, batchID int64) error {
	// Packs created before schema v12 do not carry size metadata. Continue to
	// verify their signed raw snapshot while accepting those legacy omissions.
	if hash == "" && bytes == 0 && !truncated {
		return nil
	}
	if raw == "" {
		return fmt.Errorf("evidence %s snapshot metadata is present for empty event %d in batch %d", label, eventID, batchID)
	}
	if marker, ok := parseTruncationMarker([]byte(raw)); ok {
		if !truncated || hash != marker.TailState.SHA256 || bytes != marker.TailState.Bytes {
			return fmt.Errorf("evidence %s snapshot truncation metadata mismatch for event %d in batch %d", label, eventID, batchID)
		}
		return nil
	}
	if truncated || hash != valueHash([]byte(raw)) || bytes != int64(len(raw)) {
		return fmt.Errorf("evidence %s snapshot metadata mismatch for event %d in batch %d", label, eventID, batchID)
	}
	return nil
}

func evidenceFieldsFromLedger(raw []byte) ([]EvidenceField, bool, int, error) {
	var fields []model.FieldChange
	var fieldsTruncated bool
	var totalFields int
	if err := json.Unmarshal(raw, &fields); err != nil {
		var persisted persistedFields
		if envelopeErr := json.Unmarshal(raw, &persisted); envelopeErr != nil {
			return nil, false, 0, envelopeErr
		}
		fields = persisted.Fields
		fieldsTruncated = persisted.FieldsTruncated
		totalFields = persisted.TotalFields
	}
	if totalFields == 0 {
		totalFields = len(fields)
	}
	historyFields := formatHistoryFields(fields)
	converted := make([]EvidenceField, 0, len(historyFields))
	for _, field := range historyFields {
		converted = append(converted, EvidenceField{
			Field:      field.Field,
			Old:        evidenceJSON(field.Old),
			New:        evidenceJSON(field.New),
			OldPresent: field.HasOld,
			NewPresent: field.HasNew,
		})
	}
	return converted, fieldsTruncated, totalFields, nil
}

func equalEvidenceFields(left, right []EvidenceField) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Field != right[index].Field || left[index].OldPresent != right[index].OldPresent || left[index].NewPresent != right[index].NewPresent || !equalEvidenceJSON(left[index].Old, right[index].Old) || !equalEvidenceJSON(left[index].New, right[index].New) {
			return false
		}
	}
	return true
}

func equalEvidenceJSON(left, right json.RawMessage) bool {
	left = canonicalEvidenceJSON(left)
	right = canonicalEvidenceJSON(right)
	return bytes.Equal(left, right)
}

func canonicalEvidenceJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return append([]byte(nil), raw...)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return append([]byte(nil), raw...)
	}
	return canonical
}

func equalInt64Slices(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func verifyLedgerLinks(pack EvidencePack) error {
	if err := validateLedgerBatchState(pack.Batches); err != nil {
		return err
	}
	batchesBySequence := make(map[int64]EvidenceBatch, len(pack.Batches))
	for _, batch := range pack.Batches {
		if batch.LedgerKeyID != "" && batch.LedgerKeyID != pack.SigningKeyID {
			return fmt.Errorf("ledger signing key mismatch for batch %d", batch.ID)
		}
		if batch.LedgerSequence > 0 && len(batch.LedgerHash) != sha256.Size*2 {
			return fmt.Errorf("invalid ledger hash for batch %d", batch.ID)
		}
		if batch.LedgerSequence > 0 {
			if _, err := hex.DecodeString(batch.LedgerHash); err != nil {
				return fmt.Errorf("invalid ledger hash for batch %d: %w", batch.ID, err)
			}
			if _, exists := batchesBySequence[batch.LedgerSequence]; exists {
				return fmt.Errorf("duplicate evidence ledger sequence %d", batch.LedgerSequence)
			}
			batchesBySequence[batch.LedgerSequence] = batch
			if batch.LedgerPrevHash != "" {
				if len(batch.LedgerPrevHash) != sha256.Size*2 {
					return fmt.Errorf("invalid ledger previous hash for batch %d", batch.ID)
				}
				if _, err := hex.DecodeString(batch.LedgerPrevHash); err != nil {
					return fmt.Errorf("invalid ledger previous hash for batch %d: %w", batch.ID, err)
				}
			}
		}
	}
	for index := 0; index+1 < len(pack.Batches); index++ {
		newer, older := pack.Batches[index], pack.Batches[index+1]
		if newer.LedgerSequence > 0 && older.LedgerSequence > 0 && newer.LedgerSequence == older.LedgerSequence+1 && newer.LedgerPrevHash != older.LedgerHash {
			return fmt.Errorf("evidence ledger chain mismatch between batches %d and %d", newer.ID, older.ID)
		}
	}
	if len(batchesBySequence) == 0 {
		if len(pack.LedgerLinks) > 0 {
			return errors.New("ledger links have no exported batches")
		}
		return nil
	}
	if len(pack.LedgerLinks) == 0 {
		return errors.New("evidence ledger links are missing")
	}
	links := append([]EvidenceLedgerLink(nil), pack.LedgerLinks...)
	sort.Slice(links, func(i, j int) bool { return links[i].Sequence < links[j].Sequence })
	minBatchSequence, maxBatchSequence := int64(0), int64(0)
	for sequence := range batchesBySequence {
		if minBatchSequence == 0 || sequence < minBatchSequence {
			minBatchSequence = sequence
		}
		if sequence > maxBatchSequence {
			maxBatchSequence = sequence
		}
	}
	// ExportEvidencePack includes exactly one predecessor as a checkpoint for
	// ranges that begin in the middle of the append-only ledger. Requiring that
	// boundary here makes a missing ledger row distinguishable from a normal
	// filtered/retained range instead of silently accepting a truncated chain.
	expectedFirstSequence := minBatchSequence
	if expectedFirstSequence > 1 {
		expectedFirstSequence--
	}
	if links[0].Sequence != expectedFirstSequence {
		return fmt.Errorf("evidence ledger checkpoint is missing before sequence %d", minBatchSequence)
	}
	if links[len(links)-1].Sequence != maxBatchSequence {
		return fmt.Errorf("evidence ledger links extend beyond exported sequence %d", maxBatchSequence)
	}
	public, err := decodeKeyMaterial(pack.SigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("decode evidence ledger public key: %w", err)
	}
	seenLinks := make(map[int64]EvidenceLedgerLink, len(links))
	for index, link := range links {
		if link.Sequence <= 0 || len(link.EntryHash) != sha256.Size*2 {
			return fmt.Errorf("invalid ledger link at sequence %d", link.Sequence)
		}
		if _, exists := seenLinks[link.Sequence]; exists {
			return fmt.Errorf("duplicate evidence ledger sequence %d", link.Sequence)
		}
		seenLinks[link.Sequence] = link
		if link.KeyID != pack.SigningKeyID {
			return fmt.Errorf("ledger signing key mismatch at sequence %d", link.Sequence)
		}
		entryHash, err := hex.DecodeString(link.EntryHash)
		if err != nil {
			return fmt.Errorf("invalid ledger link hash at sequence %d: %w", link.Sequence, err)
		}
		if link.PrevHash != "" {
			if len(link.PrevHash) != sha256.Size*2 {
				return fmt.Errorf("invalid ledger link previous hash at sequence %d", link.Sequence)
			}
			if _, err := hex.DecodeString(link.PrevHash); err != nil {
				return fmt.Errorf("invalid ledger link previous hash at sequence %d: %w", link.Sequence, err)
			}
		}
		if index == 0 && link.Sequence == 1 && link.PrevHash != "" {
			return errors.New("evidence ledger genesis link has a previous hash")
		}
		if link.Signature == "" {
			return fmt.Errorf("ledger signature is missing at sequence %d", link.Sequence)
		}
		signature, err := decodeKeyMaterial(link.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(public), entryHash, signature) {
			return fmt.Errorf("ledger signature verification failed at sequence %d", link.Sequence)
		}
		if index > 0 {
			previous := links[index-1]
			if link.Sequence != previous.Sequence+1 {
				return fmt.Errorf("evidence ledger sequence gap between %d and %d", previous.Sequence, link.Sequence)
			}
			if link.PrevHash != previous.EntryHash {
				return fmt.Errorf("evidence ledger chain mismatch between sequences %d and %d", link.Sequence, previous.Sequence)
			}
		}
	}
	for sequence, batch := range batchesBySequence {
		link, ok := seenLinks[sequence]
		if !ok || link.BatchID != batch.ID || link.PrevHash != batch.LedgerPrevHash || link.EntryHash != batch.LedgerHash || link.Signature != batch.LedgerSignature || link.KeyID != batch.LedgerKeyID {
			return fmt.Errorf("evidence ledger link does not match batch %d", batch.ID)
		}
		if batch.LedgerPayload == "" {
			return fmt.Errorf("ledger payload is missing for batch %d", batch.ID)
		}
		payload, err := base64.RawStdEncoding.DecodeString(batch.LedgerPayload)
		if err != nil {
			return fmt.Errorf("decode ledger payload for batch %d: %w", batch.ID, err)
		}
		var ledgerBatch evidenceLedgerBatch
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&ledgerBatch); err != nil {
			return fmt.Errorf("decode ledger payload for batch %d: %w", batch.ID, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				return fmt.Errorf("ledger payload for batch %d contains trailing JSON", batch.ID)
			}
			return fmt.Errorf("decode ledger payload for batch %d: %w", batch.ID, err)
		}
		changeCount := batch.LedgerChangeCount
		if changeCount == 0 {
			changeCount = batch.ChangeCount
		}
		if ledgerBatch.BatchID != batch.ID || ledgerBatch.Generation != batch.Generation || ledgerBatch.ChangeCount != changeCount {
			return fmt.Errorf("ledger payload metadata mismatch for batch %d", batch.ID)
		}
		digest := ledgerDigest(batch.LedgerPrevHash, payload)
		if hex.EncodeToString(digest[:]) != batch.LedgerHash {
			return fmt.Errorf("ledger hash recomputation failed for batch %d", batch.ID)
		}
		if err := verifyLedgerPayloadBinding(batch, ledgerBatch); err != nil {
			return err
		}
	}
	return nil
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

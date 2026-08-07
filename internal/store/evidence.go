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
	"strings"
	"time"
)

const (
	evidencePackFormat  = "tailstate-drift-evidence"
	evidencePackVersion = 2
	maxEvidenceBatches  = 100
	maxEvidenceEvents   = 2000
	maxEvidenceBytes    = 5 << 20
)

// ErrEvidencePackTooLarge indicates that the selected history cannot be
// exported within the bounded response size.
var ErrEvidencePackTooLarge = errors.New("history evidence pack exceeds the size limit")

// EvidencePack is a redacted, portable representation of explainable drift
// history. Version 2 packs include an Ed25519 signature over the content hash,
// ledger head, generation timestamp, and signing-key fingerprint.
type EvidencePack struct {
	Format           string          `json:"format"`
	Version          int             `json:"version"`
	GeneratedAt      string          `json:"generated_at"`
	Filter           EvidenceFilter  `json:"filter"`
	Batches          []EvidenceBatch `json:"batches"`
	Truncated        bool            `json:"truncated"`
	NextCursor       int64           `json:"next_cursor,omitempty"`
	ContentSHA256    string          `json:"content_sha256"`
	SigningKeyID     string          `json:"signing_key_id,omitempty"`
	SigningPublicKey string          `json:"signing_public_key,omitempty"`
	LedgerHead       string          `json:"ledger_head,omitempty"`
	Signature        string          `json:"signature,omitempty"`
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
	ID              int64              `json:"id"`
	Generation      int64              `json:"generation"`
	ObservedAt      time.Time          `json:"observed_at"`
	ChangeCount     int                `json:"change_count"`
	TriggerID       int64              `json:"trigger_id,omitempty"`
	TriggerIDs      []int64            `json:"trigger_ids,omitempty"`
	LedgerSequence  int64              `json:"ledger_sequence,omitempty"`
	LedgerPrevHash  string             `json:"ledger_prev_hash,omitempty"`
	LedgerHash      string             `json:"ledger_hash,omitempty"`
	LedgerSignature string             `json:"ledger_signature,omitempty"`
	LedgerKeyID     string             `json:"ledger_key_id,omitempty"`
	Events          []EvidenceEvent    `json:"events"`
	Deliveries      []EvidenceDelivery `json:"deliveries"`
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
	LedgerHead string          `json:"ledger_head,omitempty"`
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
	pack.LedgerHead, err = s.evidenceLedgerHead(ctx)
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
	if err := json.Unmarshal(data, &pack); err != nil {
		return fmt.Errorf("decode evidence pack: %w", err)
	}
	if pack.Format != evidencePackFormat {
		return fmt.Errorf("unsupported evidence pack format %q version %d", pack.Format, pack.Version)
	}
	if pack.Version != 1 && pack.Version != evidencePackVersion {
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
	if pack.Version == 1 {
		return nil
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
	return []byte("tailstate-evidence-pack-v2\n" + pack.ContentSHA256 + "\n" + pack.LedgerHead + "\n" + pack.GeneratedAt + "\n" + pack.SigningKeyID)
}

func verifyLedgerLinks(pack EvidencePack) error {
	for index := 0; index < len(pack.Batches); index++ {
		batch := pack.Batches[index]
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
		}
		if index+1 >= len(pack.Batches) {
			continue
		}
		older := pack.Batches[index+1]
		if batch.LedgerSequence > 0 && older.LedgerSequence > 0 && batch.LedgerSequence == older.LedgerSequence+1 && batch.LedgerPrevHash != older.LedgerHash {
			return fmt.Errorf("evidence ledger chain mismatch between batches %d and %d", batch.ID, older.ID)
		}
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
		LedgerHead: pack.LedgerHead,
	})
}

func evidenceBatch(batch HistoryBatch) EvidenceBatch {
	out := EvidenceBatch{
		ID:              batch.ID,
		Generation:      batch.Generation,
		ObservedAt:      batch.ObservedAt,
		ChangeCount:     batch.ChangeCount,
		TriggerID:       batch.TriggerID,
		TriggerIDs:      append([]int64(nil), batch.TriggerIDs...),
		LedgerSequence:  batch.LedgerSequence,
		LedgerPrevHash:  batch.LedgerPrevHash,
		LedgerHash:      batch.LedgerHash,
		LedgerSignature: batch.LedgerSignature,
		LedgerKeyID:     batch.LedgerKeyID,
		Events:          make([]EvidenceEvent, 0, len(batch.Events)),
		Deliveries:      make([]EvidenceDelivery, 0, len(batch.Deliveries)),
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

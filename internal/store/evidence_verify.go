package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

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
	if len(data) > maxEvidenceBytes {
		return ErrEvidencePackTooLarge
	}
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
	if pack.Version != evidencePackVersion && pack.Version != evidencePackVersionV4 && pack.Version != evidencePackVersionV3 {
		return fmt.Errorf("unsupported evidence pack format %q version %d", pack.Format, pack.Version)
	}
	if err := verifyEvidenceVersionFields(pack); err != nil {
		return err
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

// verifyEvidenceVersionFields refuses fields that the pack's version cannot
// carry: an older pack must look exactly like its release exported it, so a
// newer pack cannot be relabelled as an older version.
func verifyEvidenceVersionFields(pack EvidencePack) error {
	for _, batch := range pack.Batches {
		if pack.Version < evidencePackVersion && batch.AttributionStatus != "" {
			return fmt.Errorf("evidence pack version %d cannot carry attribution (batch %d)", pack.Version, batch.ID)
		}
		switch batch.AttributionStatus {
		case "", AttributionComplete, AttributionUnavailable, AttributionUnsupported:
		default:
			return fmt.Errorf("invalid attribution status for batch %d", batch.ID)
		}
		for _, event := range batch.Events {
			if pack.Version == evidencePackVersionV3 && (event.Severity != "" || event.Muted) {
				return fmt.Errorf("evidence pack version %d cannot carry severity or muted flags (event %d)", pack.Version, event.ID)
			}
			if event.Attribution == nil {
				continue
			}
			if pack.Version < evidencePackVersion {
				return fmt.Errorf("evidence pack version %d cannot carry attribution (event %d)", pack.Version, event.ID)
			}
			if batch.AttributionStatus != AttributionComplete {
				return fmt.Errorf("attributed event %d in batch %d without a complete attribution lookup", event.ID, batch.ID)
			}
		}
	}
	return nil
}

// evidenceSignaturePayload is the signed statement for a pack. The domain
// names the pack version so a signature can never be replayed across
// versions.
func evidenceSignaturePayload(pack EvidencePack) []byte {
	return []byte(fmt.Sprintf("tailstate-evidence-pack-v%d\n", pack.Version) + pack.ContentSHA256 + "\n" + pack.LedgerHead + "\n" + pack.GeneratedAt + "\n" + pack.SigningKeyID)
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
	if event.Muted != ledgerEvent.Muted {
		return fmt.Errorf("ledger payload event muted flag mismatch for event %d in batch %d", event.ID, batchID)
	}
	if !equalAttribution(event.Attribution, ledgerEvent.Attribution) {
		return fmt.Errorf("ledger payload event attribution mismatch for event %d in batch %d", event.ID, batchID)
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

func equalAttribution(left, right *model.Attribution) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
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

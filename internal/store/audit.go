package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/crypt0rr/tailstate/internal/secret"
)

const evidenceAuditBatchSize = 128

// ErrEvidenceDatabaseNotFound indicates that an audit target does not exist.
// Auditing never creates the parent directory or database file.
var ErrEvidenceDatabaseNotFound = errors.New("evidence audit database not found")

// EvidenceAuditOptions bounds one read-only audit page. Cursor is the last
// verified sequence from a previous page; a zero cursor starts at genesis.
// TrustedPublicKey, when supplied, is used instead of the instance's stored
// public key so the result can be independently anchored.
type EvidenceAuditOptions struct {
	Cursor           int64
	Limit            int
	TrustedPublicKey []byte
}

// EvidenceAuditResult describes the work completed by one audit page. A
// caller can resume with NextCursor while Complete is false. Entries whose
// event batch has aged out are cryptographically checked but counted as
// UnverifiableEntries because their original canonical payload is no longer
// available for recomputation.
type EvidenceAuditResult struct {
	Entries             int64
	VerifiedEntries     int64
	UnverifiableEntries int64
	FirstSequence       int64
	LastSequence        int64
	NextCursor          int64
	LatestSequence      int64
	Complete            bool
	HeadMatches         bool
	StoredHead          string
	ObservedHead        string
	SigningKeyID        string
	TrustedKey          bool
}

// EvidenceAuditError identifies the first ledger sequence that failed a
// structural, cryptographic, or canonical-payload check.
type EvidenceAuditError struct {
	Sequence int64
	Check    string
	Err      error
}

func (e *EvidenceAuditError) Error() string {
	if e == nil {
		return "evidence ledger audit failed"
	}
	if e.Err == nil {
		return fmt.Sprintf("evidence ledger audit failed at sequence %d: %s", e.Sequence, e.Check)
	}
	return fmt.Sprintf("evidence ledger audit failed at sequence %d: %s: %v", e.Sequence, e.Check, e.Err)
}

func (e *EvidenceAuditError) Unwrap() error { return e.Err }

type evidenceAuditEntry struct {
	Sequence  int64
	BatchID   int64
	PrevHash  string
	EntryHash string
	Signature string
	KeyID     string
}

// OpenEvidenceReadOnly opens an existing TailState database without running
// bootstrap DDL, migrations, key generation, or metadata writes. It is used
// by the explicit evidence audit command and can read a live WAL database.
func OpenEvidenceReadOnly(path string, box *secret.Box) (*Store, error) {
	if box == nil {
		return nil, errors.New("master key is required")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrEvidenceDatabaseNotFound
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	closeWith := func(openErr error) (*Store, error) {
		_ = db.Close()
		return nil, openErr
	}
	if err := db.Ping(); err != nil {
		return closeWith(err)
	}
	present, err := verifyExistingMasterKey(db, box)
	if err != nil {
		return closeWith(err)
	}
	if !present {
		if err := verifyLegacyMasterKey(db, box); err != nil {
			return closeWith(err)
		}
	}
	if err := verifyDatabaseVersionPreflight(db); err != nil {
		return closeWith(err)
	}
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&version); err != nil {
		return closeWith(err)
	}
	if version != currentSchemaVersion {
		return closeWith(fmt.Errorf("evidence audit requires schema version %d, found %d; run the service migration first", currentSchemaVersion, version))
	}
	var publicEncoded, keyID string
	if err := db.QueryRow("SELECT value FROM meta WHERE key=?", evidenceSigningPublicKeyMeta).Scan(&publicEncoded); err != nil {
		return closeWith(fmt.Errorf("read evidence signing public key: %w", err))
	}
	if err := db.QueryRow("SELECT value FROM meta WHERE key=?", evidenceSigningKeyIDMeta).Scan(&keyID); err != nil {
		return closeWith(fmt.Errorf("read evidence signing key ID: %w", err))
	}
	public, err := decodeKeyMaterial(publicEncoded, ed25519.PublicKeySize)
	if err != nil {
		return closeWith(fmt.Errorf("decode evidence signing public key: %w", err))
	}
	if keyID != evidenceKeyID(public) {
		return closeWith(errors.New("evidence signing key fingerprint does not match"))
	}
	return &Store{db: db, box: box, evidenceKey: evidenceSigningKey{public: ed25519.PublicKey(public), keyID: keyID}}, nil
}

// AuditEvidenceLedger verifies one bounded page of the persisted ledger using
// read-only SELECTs. It never creates keys, updates progress metadata, or
// performs migrations, and is safe to run while the service has a WAL open.
func (s *Store) AuditEvidenceLedger(ctx context.Context, options EvidenceAuditOptions) (result EvidenceAuditResult, err error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if options.Cursor < 0 {
		return result, errors.New("evidence audit cursor must not be negative")
	}
	limit := options.Limit
	if limit <= 0 {
		limit = evidenceAuditBatchSize
	}
	if limit > 1024 {
		limit = 1024
	}
	public := append([]byte(nil), s.evidenceKey.public...)
	if len(options.TrustedPublicKey) > 0 {
		public, err = ParseEvidencePublicKey(options.TrustedPublicKey)
		if err != nil {
			return result, fmt.Errorf("parse trusted evidence public key: %w", err)
		}
		result.TrustedKey = true
	}
	if len(public) != ed25519.PublicKeySize {
		return result, errors.New("evidence signing public key is unavailable")
	}
	result.SigningKeyID = evidenceKeyID(public)
	result.StoredHead, err = evidenceAuditStoredHead(ctx, s.db)
	if err != nil {
		return result, err
	}
	result.LatestSequence, result.ObservedHead, err = evidenceAuditLatest(ctx, s.db)
	if err != nil {
		return result, err
	}

	previousHash := ""
	if options.Cursor > 0 {
		var anchor evidenceAuditEntry
		if err := s.db.QueryRowContext(ctx, `SELECT sequence,batch_id,prev_hash,entry_hash,signature,key_id FROM evidence_ledger WHERE sequence=?`, options.Cursor).Scan(&anchor.Sequence, &anchor.BatchID, &anchor.PrevHash, &anchor.EntryHash, &anchor.Signature, &anchor.KeyID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return result, evidenceAuditFailure(options.Cursor, "resume cursor is missing", nil)
			}
			return result, err
		}
		if err := validateAuditEntry(anchor, public, options.Cursor == 1, "resume cursor"); err != nil {
			return result, err
		}
		previousHash = anchor.EntryHash
	}

	rows, err := s.db.QueryContext(ctx, `SELECT sequence,batch_id,prev_hash,entry_hash,signature,key_id
		FROM evidence_ledger WHERE sequence>? ORDER BY sequence LIMIT ?`, options.Cursor, limit)
	if err != nil {
		return result, err
	}
	entries := make([]evidenceAuditEntry, 0, limit)
	for rows.Next() {
		var entry evidenceAuditEntry
		if err := rows.Scan(&entry.Sequence, &entry.BatchID, &entry.PrevHash, &entry.EntryHash, &entry.Signature, &entry.KeyID); err != nil {
			rows.Close()
			return result, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}

	expectedSequence := options.Cursor + 1
	for _, entry := range entries {
		if result.FirstSequence == 0 {
			result.FirstSequence = entry.Sequence
		}
		result.Entries++
		if entry.Sequence != expectedSequence {
			return result, evidenceAuditFailure(entry.Sequence, "sequence continuity", fmt.Errorf("expected %d", expectedSequence))
		}
		if entry.Sequence > 1 && entry.PrevHash != previousHash {
			return result, evidenceAuditFailure(entry.Sequence, "predecessor hash", errors.New("previous entry hash does not match"))
		}
		if entry.Sequence == 1 && entry.PrevHash != "" {
			return result, evidenceAuditFailure(entry.Sequence, "genesis predecessor", errors.New("genesis entry has a predecessor"))
		}
		if err := validateAuditEntry(entry, public, entry.Sequence == 1, "ledger entry"); err != nil {
			return result, err
		}
		if entry.BatchID <= 0 {
			return result, evidenceAuditFailure(entry.Sequence, "batch reference", errors.New("batch ID must be positive"))
		}
		payload, _, payloadErr := evidenceLedgerPayload(ctx, s.db, entry.BatchID)
		if payloadErr != nil {
			if errors.Is(payloadErr, sql.ErrNoRows) {
				result.UnverifiableEntries++
			} else {
				return result, evidenceAuditFailure(entry.Sequence, "canonical payload read", payloadErr)
			}
		} else {
			digest := ledgerDigest(entry.PrevHash, payload)
			if hex.EncodeToString(digest[:]) != entry.EntryHash {
				return result, evidenceAuditFailure(entry.Sequence, "canonical payload digest", errors.New("recomputed digest does not match entry hash"))
			}
		}
		result.VerifiedEntries++
		result.LastSequence = entry.Sequence
		expectedSequence++
		previousHash = entry.EntryHash
	}

	if result.Entries == 0 {
		result.LastSequence = options.Cursor
	}
	if result.LastSequence >= result.LatestSequence {
		result.Complete = true
		result.NextCursor = 0
		if result.LatestSequence == 0 {
			result.HeadMatches = result.StoredHead == ""
		} else {
			result.HeadMatches = result.StoredHead == result.ObservedHead
		}
		if !result.HeadMatches {
			return result, evidenceAuditFailure(result.LatestSequence, "stored ledger head", errors.New("metadata head does not match the latest ledger entry"))
		}
	} else {
		result.Complete = false
		result.NextCursor = result.LastSequence
	}
	return result, nil
}

func validateAuditEntry(entry evidenceAuditEntry, public []byte, genesis bool, label string) error {
	if entry.Sequence <= 0 {
		return evidenceAuditFailure(entry.Sequence, label+" sequence", errors.New("sequence must be positive"))
	}
	if len(entry.EntryHash) != 64 {
		return evidenceAuditFailure(entry.Sequence, label+" hash", errors.New("entry hash must be 32-byte hexadecimal"))
	}
	entryHash, err := hex.DecodeString(entry.EntryHash)
	if err != nil {
		return evidenceAuditFailure(entry.Sequence, label+" hash", err)
	}
	if entry.PrevHash != "" {
		if len(entry.PrevHash) != 64 {
			return evidenceAuditFailure(entry.Sequence, label+" predecessor", errors.New("predecessor hash must be 32-byte hexadecimal"))
		}
		if _, err := hex.DecodeString(entry.PrevHash); err != nil {
			return evidenceAuditFailure(entry.Sequence, label+" predecessor", err)
		}
	} else if !genesis {
		return evidenceAuditFailure(entry.Sequence, label+" predecessor", errors.New("non-genesis entry is missing a predecessor"))
	}
	if entry.KeyID != evidenceKeyID(public) {
		return evidenceAuditFailure(entry.Sequence, label+" key ID", errors.New("entry key ID does not match the trusted public key"))
	}
	signature, err := decodeKeyMaterial(entry.Signature, ed25519.SignatureSize)
	if err != nil {
		return evidenceAuditFailure(entry.Sequence, label+" signature", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(public), entryHash, signature) {
		return evidenceAuditFailure(entry.Sequence, label+" signature", errors.New("signature verification failed"))
	}
	return nil
}

func evidenceAuditFailure(sequence int64, check string, err error) error {
	return &EvidenceAuditError{Sequence: sequence, Check: check, Err: err}
}

func evidenceAuditStoredHead(ctx context.Context, db *sql.DB) (string, error) {
	var head string
	err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceLedgerHeadMeta).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return head, err
}

func evidenceAuditLatest(ctx context.Context, db *sql.DB) (int64, string, error) {
	var sequence int64
	var head string
	err := db.QueryRowContext(ctx, "SELECT sequence,entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&sequence, &head)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return sequence, head, err
}

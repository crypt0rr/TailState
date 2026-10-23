package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

// Ledger checkpoints anchor the evidence-ledger head outside the database. The
// operator chooses one notification destination; TailState then sends a signed
// statement of the newest ledger entry (its sequence and hash) to that
// destination. The destination choice and the last checkpoint live in the meta
// table, so no schema migration is needed.
const (
	evidenceCheckpointDestinationMeta = "evidence_checkpoint_destination"
	evidenceCheckpointStateMeta       = "evidence_checkpoint_state"
	evidenceCheckpointDomain          = "tailstate-ledger-checkpoint-v1\n"
)

// ErrEvidenceCheckpointDestinationUnavailable reports that the destination
// chosen for checkpoints is disabled or removed. Nothing is enqueued and the
// schedule does not advance, so the pending checkpoint is sent once the
// operator enables or replaces that destination.
var ErrEvidenceCheckpointDestinationUnavailable = errors.New("evidence checkpoint destination is disabled or removed")

// LedgerCheckpoint is one signed statement of the evidence-ledger head: the
// sequence and hash of the newest entry when the checkpoint was recorded.
type LedgerCheckpoint struct {
	Sequence int64
	// Head is the lowercase hexadecimal entry hash at Sequence.
	Head string
	// RecordedAt is the checkpoint time in whole seconds, UTC. It is part of
	// the signed statement, so it is shown verbatim in the notification.
	RecordedAt time.Time
	KeyID      string
	// Signature is the raw standard base64 Ed25519 signature over the
	// checkpoint statement (see ledgerCheckpointStatement).
	Signature string
}

// ledgerCheckpointState is the most recent checkpoint enqueued by this
// instance. Sequence zero means none has been sent.
type ledgerCheckpointState struct {
	Sequence int64  `json:"sequence"`
	Head     string `json:"head"`
	SentAt   string `json:"sent_at"`
}

// EvidenceCheckpointStatus describes the checkpoint configuration for
// operators: the chosen destination, the last checkpoint sent, and the active
// destinations an operator can choose from.
type EvidenceCheckpointStatus struct {
	// DestinationID is zero when checkpoints are off.
	DestinationID int64
	// LastSequence and LastHead describe the last checkpoint; LastSequence is
	// zero when none has been sent.
	LastSequence int64
	LastHead     string
	LastSentAt   time.Time
	// Destinations lists the active destinations, oldest first. Service URLs
	// are not included in the status output.
	Destinations []NotificationDestination
}

// ledgerCheckpointStatement is the exact text a checkpoint signature covers.
// It names the domain and version, then the sequence, head, recorded time, and
// key ID, one per line with no trailing newline, so an auditor can rebuild it
// from the notification and check the signature with the instance public key.
func ledgerCheckpointStatement(sequence int64, head string, recordedAt time.Time, keyID string) []byte {
	return []byte(evidenceCheckpointDomain + strconv.FormatInt(sequence, 10) + "\n" + head + "\n" + recordedAt.UTC().Format(time.RFC3339) + "\n" + keyID)
}

// VerifyLedgerCheckpoint checks a checkpoint's signature against a trusted
// Ed25519 public key, normally the one printed by `tailstate evidence
// public-key`.
func VerifyLedgerCheckpoint(checkpoint LedgerCheckpoint, trustedPublic []byte) error {
	if len(trustedPublic) != ed25519.PublicKeySize {
		return errors.New("trusted evidence public key must be 32 bytes")
	}
	if checkpoint.KeyID != evidenceKeyID(trustedPublic) {
		return errors.New("checkpoint key ID does not match the trusted public key")
	}
	signature, err := decodeKeyMaterial(checkpoint.Signature, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("decode checkpoint signature: %w", err)
	}
	statement := ledgerCheckpointStatement(checkpoint.Sequence, checkpoint.Head, checkpoint.RecordedAt, checkpoint.KeyID)
	if !ed25519.Verify(ed25519.PublicKey(trustedPublic), statement, signature) {
		return errors.New("checkpoint signature verification failed")
	}
	return nil
}

// NormalizeLedgerHead returns a ledger head in the canonical form the ledger
// stores: 64 lowercase hexadecimal characters.
func NormalizeLedgerHead(value string) (string, error) {
	head := strings.ToLower(strings.TrimSpace(value))
	if len(head) != sha256.Size*2 {
		return "", errors.New("ledger head must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(head); err != nil {
		return "", errors.New("ledger head must be 64 hexadecimal characters")
	}
	return head, nil
}

// SetEvidenceCheckpointDestination chooses the enabled notification destination
// that receives signed ledger checkpoints. The schedule is not reset, so a
// change of destination takes effect with the next checkpoint.
func (s *Store) SetEvidenceCheckpointDestination(ctx context.Context, destinationID int64) error {
	if destinationID <= 0 {
		return errors.New("notification destination ID must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM notification_destinations WHERE id=? AND deleted_at IS NULL", destinationID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("notification destination not found")
		}
		return err
	}
	if enabled != 1 {
		return ErrDestinationDisabled
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, evidenceCheckpointDestinationMeta, strconv.FormatInt(destinationID, 10)); err != nil {
		return fmt.Errorf("store evidence checkpoint destination: %w", err)
	}
	return tx.Commit()
}

// ClearEvidenceCheckpointDestination turns ledger checkpoints off. The last
// checkpoint is kept, so re-enabling checkpoints does not resend it.
func (s *Store) ClearEvidenceCheckpointDestination(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM meta WHERE key=?", evidenceCheckpointDestinationMeta); err != nil {
		return fmt.Errorf("clear evidence checkpoint destination: %w", err)
	}
	return nil
}

// EvidenceCheckpointStatus reports the checkpoint configuration and the last
// checkpoint. It reads through the read-only pool when the store has one.
func (s *Store) EvidenceCheckpointStatus(ctx context.Context) (EvidenceCheckpointStatus, error) {
	var status EvidenceCheckpointStatus
	var value string
	err := s.readDB().QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceCheckpointDestinationMeta).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return EvidenceCheckpointStatus{}, err
	default:
		id, parseErr := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if parseErr != nil || id <= 0 {
			return EvidenceCheckpointStatus{}, fmt.Errorf("invalid evidence checkpoint destination %q", value)
		}
		status.DestinationID = id
	}
	state, err := readLedgerCheckpointState(ctx, s.readDB())
	if err != nil {
		return EvidenceCheckpointStatus{}, err
	}
	status.LastSequence, status.LastHead = state.Sequence, state.Head
	if state.SentAt != "" {
		status.LastSentAt, err = time.Parse(time.RFC3339Nano, state.SentAt)
		if err != nil {
			return EvidenceCheckpointStatus{}, err
		}
	}
	status.Destinations, err = s.ListDestinations(ctx)
	if err != nil {
		return EvidenceCheckpointStatus{}, err
	}
	return status, nil
}

// EnqueueLedgerCheckpointIfDue enqueues one signed checkpoint of the newest
// ledger entry to the chosen destination. It is due when the ledger has
// advanced past the last checkpoint and at least interval has passed since
// that checkpoint was enqueued. The checkpoint row and the updated schedule
// are written in one transaction, so a restart cannot send the same sequence
// twice. The function reports whether it enqueued a checkpoint.
//
// Before the schedule is compared, the entry at the last checkpoint's sequence
// must still carry the checkpointed head; a missing or changed entry is an
// integrity error, not a silent reset. The message callback runs inside the
// write transaction and must not call the store.
func (s *Store) EnqueueLedgerCheckpointIfDue(ctx context.Context, now time.Time, interval time.Duration, message func(LedgerCheckpoint) notify.Message) (bool, error) {
	if len(s.evidenceKey.private) != ed25519.PrivateKeySize {
		return false, errors.New("evidence signing key is unavailable")
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var value string
	err = tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceCheckpointDestinationMeta).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	destinationID, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || destinationID <= 0 {
		return false, fmt.Errorf("invalid evidence checkpoint destination %q", value)
	}
	state, err := readLedgerCheckpointState(ctx, tx)
	if err != nil {
		return false, err
	}
	if state.Sequence > 0 {
		var anchored string
		err := tx.QueryRowContext(ctx, "SELECT entry_hash FROM evidence_ledger WHERE sequence=?", state.Sequence).Scan(&anchored)
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("evidence ledger no longer contains the last checkpoint sequence %d", state.Sequence)
		}
		if err != nil {
			return false, err
		}
		if anchored != state.Head {
			return false, fmt.Errorf("evidence ledger head at checkpoint sequence %d changed since it was anchored", state.Sequence)
		}
	}
	var sequence int64
	var head string
	err = tx.QueryRowContext(ctx, "SELECT sequence,entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&sequence, &head)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if sequence <= state.Sequence {
		return false, nil
	}
	if state.SentAt != "" {
		sentAt, parseErr := time.Parse(time.RFC3339Nano, state.SentAt)
		if parseErr != nil {
			return false, fmt.Errorf("parse evidence checkpoint time: %w", parseErr)
		}
		// A clock that moved backwards makes the interval negative; the
		// checkpoint is then due, and the new schedule time corrects it.
		if elapsed := now.Sub(sentAt); elapsed >= 0 && elapsed < interval {
			return false, nil
		}
	}
	var enabled int
	err = tx.QueryRowContext(ctx, "SELECT enabled FROM notification_destinations WHERE id=? AND deleted_at IS NULL", destinationID).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && enabled != 1) {
		return false, ErrEvidenceCheckpointDestinationUnavailable
	}
	if err != nil {
		return false, err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.evidenceKey.private, ledgerCheckpointStatement(sequence, head, now, s.evidenceKey.keyID)))
	checkpoint := LedgerCheckpoint{Sequence: sequence, Head: head, RecordedAt: now, KeyID: s.evidenceKey.keyID, Signature: signature}
	payloadFormat, payload, err := notify.EncodePayload(message(checkpoint))
	if err != nil {
		return false, err
	}
	stamp := formatTimestamp(now)
	// The row names one destination and carries no batch, so it is a system
	// notification: it bypasses routing and mute rules, and it is delivered
	// independently of every other destination.
	if _, err := tx.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,payload_format,status,next_attempt,first_attempt,created_at) VALUES(NULL,?,?,?,'pending',?,?,?)", destinationID, payload, payloadFormat, stamp, stamp, stamp); err != nil {
		return false, fmt.Errorf("enqueue evidence checkpoint: %w", err)
	}
	encoded, err := json.Marshal(ledgerCheckpointState{Sequence: sequence, Head: head, SentAt: stamp})
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, evidenceCheckpointStateMeta, string(encoded)); err != nil {
		return false, fmt.Errorf("record evidence checkpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// readLedgerCheckpointState returns the stored schedule, or the zero state
// when no checkpoint has been sent. An unreadable value is an error: silently
// resetting it could resend a checkpoint.
func readLedgerCheckpointState(ctx context.Context, db rowQueryer) (ledgerCheckpointState, error) {
	var raw string
	err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceCheckpointStateMeta).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ledgerCheckpointState{}, nil
	}
	if err != nil {
		return ledgerCheckpointState{}, err
	}
	var state ledgerCheckpointState
	if err := json.Unmarshal([]byte(raw), &state); err != nil || state.Sequence < 0 {
		return ledgerCheckpointState{}, errors.New("evidence checkpoint state is unreadable")
	}
	if state.SentAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, state.SentAt); err != nil {
			return ledgerCheckpointState{}, errors.New("evidence checkpoint state is unreadable")
		}
	}
	return state, nil
}

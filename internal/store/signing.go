package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/crypt0rr/tailstate/internal/secret"
)

const (
	evidenceSigningPrivateKeyMeta = "evidence_signing_private_key_enc"
	evidenceSigningPublicKeyMeta  = "evidence_signing_public_key"
	evidenceSigningKeyIDMeta      = "evidence_signing_key_id"
	evidenceLedgerHeadMeta        = "evidence_ledger_head"
	evidenceLedgerBackfillCutoff  = "evidence_ledger_backfill_cutoff"
	evidenceLedgerBackfilledMeta  = "evidence_ledger_backfilled_at"
	evidenceLedgerDomain          = "tailstate-evidence-ledger-v1\n"
)

type evidenceSigningKey struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

// evidenceLedgerLinks returns the complete chain segment spanning the
// selected batches. Filtered exports can therefore verify links for batches
// that are not included in the event payload itself.
func (s *Store) evidenceLedgerLinks(ctx context.Context, batches []HistoryBatch) ([]EvidenceLedgerLink, error) {
	var minSequence, maxSequence int64
	for _, batch := range batches {
		if batch.LedgerSequence == 0 {
			continue
		}
		if minSequence == 0 || batch.LedgerSequence < minSequence {
			minSequence = batch.LedgerSequence
		}
		if batch.LedgerSequence > maxSequence {
			maxSequence = batch.LedgerSequence
		}
	}
	if minSequence == 0 {
		return nil, nil
	}
	// Include the immediately preceding entry as a checkpoint when one exists.
	// A filtered or paginated export may start in the middle of the ledger; the
	// predecessor lets an offline verifier distinguish a valid range boundary
	// from a broken chain without exposing the predecessor's event payload.
	startSequence := minSequence
	if startSequence > 1 {
		startSequence--
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,batch_id,prev_hash,entry_hash,signature,key_id
		FROM evidence_ledger WHERE sequence BETWEEN ? AND ? ORDER BY sequence`, startSequence, maxSequence)
	if err != nil {
		return nil, err
	}
	// The size guard below can return before the normal rows.Close path. Keep
	// the connection release unconditional so an oversized export cannot leak
	// a SQLite rows handle and stall later history requests.
	defer rows.Close()
	links := make([]EvidenceLedgerLink, 0, min(maxEvidenceLedgerLinks, int(maxSequence-startSequence+1)))
	for rows.Next() {
		if len(links) >= maxEvidenceLedgerLinks {
			return nil, ErrEvidencePackTooLarge
		}
		var link EvidenceLedgerLink
		if err := rows.Scan(&link.Sequence, &link.BatchID, &link.PrevHash, &link.EntryHash, &link.Signature, &link.KeyID); err != nil {
			rows.Close()
			return nil, err
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return links, nil
}

type ledgerQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type evidenceLedgerBatch struct {
	BatchID     int64                 `json:"batch_id"`
	Generation  int64                 `json:"generation"`
	ObservedAt  string                `json:"observed_at"`
	ChangeCount int                   `json:"change_count"`
	TriggerID   int64                 `json:"trigger_id,omitempty"`
	TriggerIDs  []int64               `json:"trigger_ids,omitempty"`
	Events      []evidenceLedgerEvent `json:"events"`
}

type evidenceLedgerEvent struct {
	ID         int64  `json:"id"`
	Generation int64  `json:"generation"`
	ObservedAt string `json:"observed_at"`
	Collector  string `json:"collector"`
	EventType  string `json:"event_type"`
	ResourceID string `json:"resource_id"`
	Name       string `json:"name"`
	Changes    string `json:"changes,omitempty"`
	Before     string `json:"before,omitempty"`
	After      string `json:"after,omitempty"`
}

func loadOrCreateEvidenceSigningKey(ctx context.Context, db *sql.DB, box *secret.Box) (evidenceSigningKey, error) {
	values := make(map[string]string, 3)
	for _, key := range []string{evidenceSigningPrivateKeyMeta, evidenceSigningPublicKeyMeta, evidenceSigningKeyIDMeta} {
		var value string
		err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", key).Scan(&value)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return evidenceSigningKey{}, fmt.Errorf("read %s: %w", key, err)
		}
		values[key] = value
	}
	if len(values) == 0 {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return evidenceSigningKey{}, fmt.Errorf("generate evidence signing key: %w", err)
		}
		privateEnvelope, err := box.Encrypt(base64.RawStdEncoding.EncodeToString(private))
		if err != nil {
			return evidenceSigningKey{}, fmt.Errorf("encrypt evidence signing key: %w", err)
		}
		publicEncoded := base64.RawStdEncoding.EncodeToString(public)
		keyID := evidenceKeyID(public)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return evidenceSigningKey{}, fmt.Errorf("begin evidence signing key setup: %w", err)
		}
		defer tx.Rollback()
		for key, value := range map[string]string{
			evidenceSigningPrivateKeyMeta: privateEnvelope,
			evidenceSigningPublicKeyMeta:  publicEncoded,
			evidenceSigningKeyIDMeta:      keyID,
		} {
			if _, err := tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?)", key, value); err != nil {
				return evidenceSigningKey{}, fmt.Errorf("store %s: %w", key, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return evidenceSigningKey{}, fmt.Errorf("commit evidence signing key setup: %w", err)
		}
		return evidenceSigningKey{private: private, public: public, keyID: keyID}, nil
	}
	if len(values) != 3 {
		return evidenceSigningKey{}, errors.New("evidence signing key metadata is incomplete")
	}
	privateEncoded, err := box.Decrypt(values[evidenceSigningPrivateKeyMeta])
	if err != nil {
		return evidenceSigningKey{}, fmt.Errorf("decrypt evidence signing key: %w", err)
	}
	private, err := decodeKeyMaterial(privateEncoded, ed25519.PrivateKeySize)
	if err != nil {
		return evidenceSigningKey{}, fmt.Errorf("decode evidence signing key: %w", err)
	}
	public, err := decodeKeyMaterial(values[evidenceSigningPublicKeyMeta], ed25519.PublicKeySize)
	if err != nil {
		return evidenceSigningKey{}, fmt.Errorf("decode evidence signing public key: %w", err)
	}
	if !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		return evidenceSigningKey{}, errors.New("evidence signing key pair does not match")
	}
	keyID := values[evidenceSigningKeyIDMeta]
	if keyID != evidenceKeyID(public) {
		return evidenceSigningKey{}, errors.New("evidence signing key fingerprint does not match")
	}
	return evidenceSigningKey{private: ed25519.PrivateKey(private), public: ed25519.PublicKey(public), keyID: keyID}, nil
}

func decodeKeyMaterial(value string, size int) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) == size {
			return decoded, nil
		}
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == size {
		return decoded, nil
	}
	return nil, fmt.Errorf("expected %d-byte base64 or hexadecimal key", size)
}

func evidenceKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return "ed25519:" + hex.EncodeToString(digest[:16])
}

// EvidenceSigningKeyID returns the stable fingerprint of the instance key.
// It is safe to display to administrators and does not reveal key material.
func (s *Store) EvidenceSigningKeyID(context.Context) (string, error) {
	if s.evidenceKey.keyID == "" {
		return "", errors.New("evidence signing key is unavailable")
	}
	return s.evidenceKey.keyID, nil
}

// EvidenceSigningPublicKey returns a copy of the Ed25519 public key used to
// authenticate signed evidence packs.
func (s *Store) EvidenceSigningPublicKey(context.Context) ([]byte, error) {
	if len(s.evidenceKey.public) != ed25519.PublicKeySize {
		return nil, errors.New("evidence signing key is unavailable")
	}
	return append([]byte(nil), s.evidenceKey.public...), nil
}

// ParseEvidencePublicKey accepts a raw, base64, or hexadecimal Ed25519 public
// key. Text formats may contain surrounding whitespace or a trailing newline.
func ParseEvidencePublicKey(raw []byte) ([]byte, error) {
	if len(raw) > maxEvidencePublicKeyBytes {
		return nil, fmt.Errorf("evidence public key exceeds %d bytes", maxEvidencePublicKeyBytes)
	}
	if len(raw) == ed25519.PublicKeySize {
		return append([]byte(nil), raw...), nil
	}
	decoded, err := decodeKeyMaterial(string(raw), ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (s *Store) backfillEvidenceLedger(ctx context.Context) error {
	return s.backfillEvidenceLedgerUpTo(ctx, 0)
}

// backfillEvidenceLedgerUpTo imports only batches that existed at the
// migration boundary. A zero cutoff means no upper bound for this explicit
// helper; startup skips the helper when its durable cutoff is zero so a
// missing migration marker can never promote live rows into historical
// evidence.
func (s *Store) backfillEvidenceLedgerUpTo(ctx context.Context, cutoff int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Only batches with a complete event set are eligible for migration
	// backfill. ApplyBatch writes event_batches and events in one transaction;
	// an empty or mismatched row is not a valid historical batch and must not be
	// granted a signed ledger position merely because it exists in SQLite.
	query := `SELECT b.id
		FROM event_batches b
		WHERE b.change_count > 0
		  AND b.change_count = (SELECT COUNT(*) FROM events e WHERE e.batch_id=b.id)`
	args := []any{}
	if cutoff > 0 {
		query += "\n  AND b.id <= ?"
		args = append(args, cutoff)
	}
	query += "\n ORDER BY b.id"
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	var batchIDs []int64
	for rows.Next() {
		var batchID int64
		if err := rows.Scan(&batchID); err != nil {
			rows.Close()
			return err
		}
		batchIDs = append(batchIDs, batchID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, batchID := range batchIDs {
		if err := s.appendEvidenceLedgerTx(ctx, tx, batchID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) backfillEvidenceLedgerOnStartup(ctx context.Context) error {
	var marker string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceLedgerBackfilledMeta).Scan(&marker)
	if err == nil && strings.TrimSpace(marker) != "" {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	cutoff, err := s.evidenceLedgerBackfillCutoff(ctx)
	if err != nil {
		return err
	}
	if cutoff > 0 {
		if err := s.backfillEvidenceLedgerUpTo(ctx, cutoff); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", evidenceLedgerBackfilledMeta, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// evidenceLedgerBackfillCutoff establishes a durable upper bound the first
// time startup backfill runs. Keeping it separate from the completion marker
// makes retries safe after a partial failure without allowing newly inserted
// rows to acquire historical ledger positions.
func (s *Store) evidenceLedgerBackfillCutoff(ctx context.Context) (int64, error) {
	var encoded string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceLedgerBackfillCutoff).Scan(&encoded)
	if err == nil {
		cutoff, parseErr := strconv.ParseInt(strings.TrimSpace(encoded), 10, 64)
		if parseErr != nil || cutoff < 0 {
			return 0, fmt.Errorf("invalid evidence ledger backfill cutoff %q", encoded)
		}
		return cutoff, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	// A missing cutoff is deliberately a zero boundary, not the current
	// maximum batch ID. Deriving a cutoff from live rows would let rows written
	// directly into the database acquire a historical ledger position on the
	// next startup. Only the versioned migration is allowed to authorize a
	// non-zero backfill boundary.
	const cutoff int64 = 0
	if _, err := s.db.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?)", evidenceLedgerBackfillCutoff, strconv.FormatInt(cutoff, 10)); err != nil {
		return 0, fmt.Errorf("store evidence ledger backfill cutoff: %w", err)
	}
	return cutoff, nil
}

func (s *Store) appendEvidenceLedgerTx(ctx context.Context, tx *sql.Tx, batchID int64) error {
	var existing int64
	if err := tx.QueryRowContext(ctx, "SELECT sequence FROM evidence_ledger WHERE batch_id=?", batchID).Scan(&existing); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	payload, batch, err := evidenceLedgerPayload(ctx, tx, batchID)
	if err != nil {
		return err
	}
	previous, err := ledgerHeadTx(ctx, tx)
	if err != nil {
		return err
	}
	digest := ledgerDigest(previous, payload)
	entryHash := hex.EncodeToString(digest[:])
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.evidenceKey.private, digest[:]))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_ledger(batch_id,generation,observed_at,prev_hash,entry_hash,signature,key_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, batchID, batch.Generation, batch.ObservedAt, previous, entryHash, signature, s.evidenceKey.keyID, now); err != nil {
		return fmt.Errorf("append evidence ledger batch %d: %w", batchID, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, evidenceLedgerHeadMeta, entryHash); err != nil {
		return fmt.Errorf("update evidence ledger head: %w", err)
	}
	return nil
}

func evidenceLedgerPayload(ctx context.Context, queryer ledgerQueryer, batchID int64) ([]byte, evidenceLedgerBatch, error) {
	var batch evidenceLedgerBatch
	var triggerID sql.NullInt64
	if err := queryer.QueryRowContext(ctx, "SELECT id,generation,observed_at,change_count,trigger_id FROM event_batches WHERE id=?", batchID).Scan(&batch.BatchID, &batch.Generation, &batch.ObservedAt, &batch.ChangeCount, &triggerID); err != nil {
		return nil, evidenceLedgerBatch{}, err
	}
	if triggerID.Valid {
		batch.TriggerID = triggerID.Int64
	}
	triggerRows, err := queryer.QueryContext(ctx, "SELECT trigger_id FROM event_batch_triggers WHERE batch_id=? ORDER BY trigger_id", batchID)
	if err != nil {
		return nil, evidenceLedgerBatch{}, err
	}
	for triggerRows.Next() {
		var trigger int64
		if err := triggerRows.Scan(&trigger); err != nil {
			triggerRows.Close()
			return nil, evidenceLedgerBatch{}, err
		}
		if trigger > 0 {
			batch.TriggerIDs = append(batch.TriggerIDs, trigger)
		}
	}
	if err := triggerRows.Err(); err != nil {
		triggerRows.Close()
		return nil, evidenceLedgerBatch{}, err
	}
	if err := triggerRows.Close(); err != nil {
		return nil, evidenceLedgerBatch{}, err
	}
	if len(batch.TriggerIDs) == 0 && batch.TriggerID > 0 {
		batch.TriggerIDs = []int64{batch.TriggerID}
	}
	eventRows, err := queryer.QueryContext(ctx, `SELECT id,generation,observed_at,collector,event_type,resource_id,name,changes_json,before_json,after_json FROM events WHERE batch_id=? ORDER BY id`, batchID)
	if err != nil {
		return nil, evidenceLedgerBatch{}, err
	}
	for eventRows.Next() {
		var event evidenceLedgerEvent
		var changes, before, after []byte
		if err := eventRows.Scan(&event.ID, &event.Generation, &event.ObservedAt, &event.Collector, &event.EventType, &event.ResourceID, &event.Name, &changes, &before, &after); err != nil {
			eventRows.Close()
			return nil, evidenceLedgerBatch{}, err
		}
		event.Changes, event.Before, event.After = string(changes), string(before), string(after)
		batch.Events = append(batch.Events, event)
	}
	if err := eventRows.Err(); err != nil {
		eventRows.Close()
		return nil, evidenceLedgerBatch{}, err
	}
	if err := eventRows.Close(); err != nil {
		return nil, evidenceLedgerBatch{}, err
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return nil, evidenceLedgerBatch{}, err
	}
	return payload, batch, nil
}

func ledgerHeadTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var head string
	err := tx.QueryRowContext(ctx, "SELECT entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&head)
	if err == nil {
		return head, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceLedgerHeadMeta).Scan(&head); errors.Is(err, sql.ErrNoRows) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return head, nil
}

func (s *Store) evidenceLedgerHead(ctx context.Context) (string, error) {
	var head string
	err := s.db.QueryRowContext(ctx, "SELECT entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&head)
	if err == nil {
		return head, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceLedgerHeadMeta).Scan(&head); errors.Is(err, sql.ErrNoRows) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return head, nil
}

func ledgerDigest(previous string, payload []byte) [32]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(evidenceLedgerDomain))
	_, _ = hasher.Write([]byte(previous))
	_, _ = hasher.Write([]byte{'\n'})
	_, _ = hasher.Write(payload)
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

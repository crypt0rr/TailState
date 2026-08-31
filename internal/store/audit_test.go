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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func auditFixture(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"server", "server-new", "server-latest", "server-final"} {
		if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource(hostname, "100.64.0.1")}, func([]model.Change) string { return hostname }); err != nil {
			t.Fatal(err)
		}
	}
	return st, ctx
}

func TestAuditEvidenceLedgerResumesAndSupportsTrustedKey(t *testing.T) {
	st, ctx := auditFixture(t)
	public, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 1})
	if err != nil || first.Complete || first.NextCursor != 1 || first.VerifiedEntries != 1 || first.HeadMatches {
		t.Fatalf("first audit page=%+v err=%v", first, err)
	}
	second, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: first.NextCursor, Limit: 1, TrustedPublicKey: public})
	if err != nil || second.Complete || !second.TrustedKey || second.NextCursor != 2 || second.VerifiedEntries != 1 {
		t.Fatalf("second audit page=%+v err=%v", second, err)
	}
	third, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: second.NextCursor, Limit: 10, TrustedPublicKey: public})
	if err != nil || !third.Complete || !third.HeadMatches || third.LastSequence != 3 || third.LatestSequence != 3 || third.ObservedHead == "" || third.StoredHead != third.ObservedHead {
		t.Fatalf("final audit page=%+v err=%v", third, err)
	}
}

func TestAuditEvidenceLedgerReportsFirstTamperedSequence(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name   string
		mutate func(*Store) error
		check  string
		seq    int64
	}{
		{name: "predecessor", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE evidence_ledger SET prev_hash='bad' WHERE sequence=2")
			return err
		}, check: "predecessor", seq: 2},
		{name: "key id", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE evidence_ledger SET key_id='ed25519:bad' WHERE sequence=1")
			return err
		}, check: "key ID", seq: 1},
		{name: "payload digest", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE events SET name='tampered' WHERE id=(SELECT MIN(id) FROM events)")
			return err
		}, check: "canonical payload digest", seq: 1},
		{name: "stored head", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE meta SET value='bad' WHERE key=?", evidenceLedgerHeadMeta)
			return err
		}, check: "stored ledger head", seq: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			st, _ := auditFixture(t)
			if err := test.mutate(st); err != nil {
				t.Fatal(err)
			}
			_, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 10})
			var auditErr *EvidenceAuditError
			if !errors.As(err, &auditErr) || auditErr.Sequence != test.seq || !strings.Contains(auditErr.Check, test.check) {
				t.Fatalf("audit error=%v, want sequence %d check %q", err, test.seq, test.check)
			}
		})
	}
}

func TestAuditEvidenceLedgerReadOnlyAndCancellation(t *testing.T) {
	st, ctx := auditFixture(t)
	var before int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("audit changed ledger row count from %d to %d", before, after)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := st.AuditEvidenceLedger(canceled, EvidenceAuditOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled audit error=%v", err)
	}
}

func TestAuditEvidenceLedgerRejectsInvalidTrustAndCursor(t *testing.T) {
	st, ctx := auditFixture(t)
	if _, err := OpenEvidenceReadOnly(filepath.Join(t.TempDir(), "missing.db"), nil); err == nil || !strings.Contains(err.Error(), "master key is required") {
		t.Fatalf("nil master key error=%v", err)
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{TrustedPublicKey: []byte("bad")}); err == nil {
		t.Fatal("invalid trusted key was accepted")
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: -1}); err == nil {
		t.Fatal("negative audit cursor was accepted")
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: 99}); err == nil {
		t.Fatal("missing audit cursor was accepted")
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 1025}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditEvidenceLedgerCoversStructuralAndPayloadFailures(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		mutate func(*Store) error
		check  string
		seq    int64
	}{
		{name: "sequence continuity", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE evidence_ledger SET sequence=4 WHERE sequence=2")
			return err
		}, check: "sequence continuity", seq: 3},
		{name: "genesis predecessor", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE evidence_ledger SET prev_hash=? WHERE sequence=1", strings.Repeat("0", 64))
			return err
		}, check: "genesis predecessor", seq: 1},
		{name: "batch reference", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE evidence_ledger SET batch_id=0 WHERE sequence=1")
			return err
		}, check: "batch reference", seq: 1},
		{name: "signature verification", mutate: func(st *Store) error {
			_, err := st.db.Exec("UPDATE evidence_ledger SET signature=? WHERE sequence=1", base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
			return err
		}, check: "signature", seq: 1},
		{name: "aged-out payload", mutate: func(st *Store) error {
			_, err := st.db.Exec("DELETE FROM event_batches WHERE id=(SELECT batch_id FROM evidence_ledger WHERE sequence=1)")
			return err
		}, check: "", seq: 0},
		{name: "canonical payload read", mutate: func(st *Store) error {
			_, err := st.db.Exec("DROP TABLE event_batches")
			return err
		}, check: "canonical payload read", seq: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			st, _ := auditFixture(t)
			if err := test.mutate(st); err != nil {
				t.Fatal(err)
			}
			result, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 10})
			if test.name == "aged-out payload" {
				if err != nil || result.UnverifiableEntries != 1 || result.VerifiedEntries != result.Entries {
					t.Fatalf("aged-out audit result=%+v err=%v", result, err)
				}
				return
			}
			var auditErr *EvidenceAuditError
			if !errors.As(err, &auditErr) || auditErr.Sequence != test.seq || !strings.Contains(auditErr.Check, test.check) {
				t.Fatalf("audit error=%v, want sequence %d check %q", err, test.seq, test.check)
			}
		})
	}
}

func TestAuditEvidenceLedgerRejectsUnavailablePublicKeyAndBadResumeAnchor(t *testing.T) {
	st, ctx := auditFixture(t)
	withoutKey := &Store{db: st.db}
	if _, err := withoutKey.AuditEvidenceLedger(ctx, EvidenceAuditOptions{}); err == nil || !strings.Contains(err.Error(), "public key is unavailable") {
		t.Fatalf("missing evidence public key error=%v", err)
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: 1, Limit: 1, TrustedPublicKey: []byte("bad")}); err == nil {
		t.Fatal("invalid trusted key was accepted for resume")
	}
	if _, err := st.db.Exec("UPDATE evidence_ledger SET signature=? WHERE sequence=1", base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: 1, Limit: 1}); err == nil || !strings.Contains(err.Error(), "resume cursor") {
		t.Fatalf("tampered resume anchor error=%v", err)
	}
}

func TestAuditEvidenceLedgerPagesLargeChain(t *testing.T) {
	st, ctx := auditFixture(t)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(ctx, "SELECT entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&previous); err != nil {
		t.Fatal(err)
	}
	const additionalEntries = 140
	for i := 0; i < additionalEntries; i++ {
		result, err := tx.ExecContext(ctx, `INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(?,?,?,?)`, 1, "2026-01-01T00:00:00Z", 0, "2026-01-01T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		batchID, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		payload, batch, err := evidenceLedgerPayload(ctx, tx, batchID)
		if err != nil {
			t.Fatal(err)
		}
		digest := ledgerDigest(previous, payload)
		entryHash := hex.EncodeToString(digest[:])
		signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(st.evidenceKey.private, digest[:]))
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_ledger(batch_id,generation,observed_at,prev_hash,entry_hash,signature,key_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, batchID, batch.Generation, batch.ObservedAt, previous, entryHash, signature, st.evidenceKey.keyID, "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		previous = entryHash
	}
	if _, err := tx.ExecContext(ctx, "UPDATE meta SET value=? WHERE key=?", previous, evidenceLedgerHeadMeta); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var cursor, entries int64
	pages := 0
	for {
		result, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Cursor: cursor, Limit: 7})
		if err != nil {
			t.Fatalf("large-chain page %d: %v", pages, err)
		}
		entries += result.Entries
		pages++
		if result.Complete {
			if result.LatestSequence != int64(additionalEntries+3) || result.Entries != 3 || !result.HeadMatches {
				t.Fatalf("large-chain final page=%+v", result)
			}
			break
		}
		if result.NextCursor <= cursor {
			t.Fatalf("large-chain cursor did not advance: previous=%d result=%+v", cursor, result)
		}
		cursor = result.NextCursor
	}
	if entries != int64(additionalEntries+3) || pages < 20 {
		t.Fatalf("large-chain audit entries=%d pages=%d", entries, pages)
	}
}

func TestOpenEvidenceReadOnlyDoesNotMutateDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	writable, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	readonly, err := OpenEvidenceReadOnly(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readonly.db.Exec("INSERT INTO meta(key,value) VALUES('audit-write','rejected')"); err == nil {
		t.Fatal("read-only audit connection accepted a write")
	}
	result, err := readonly.AuditEvidenceLedger(context.Background(), EvidenceAuditOptions{})
	if err != nil || !result.Complete || !result.HeadMatches {
		t.Fatalf("empty read-only audit result=%+v err=%v", result, err)
	}
	if err := readonly.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("read-only audit changed database bytes")
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	otherKey, _ := secret.NewBox(wrongKey)
	if _, err := OpenEvidenceReadOnly(path, otherKey); err == nil {
		t.Fatal("read-only audit accepted the wrong master key")
	}
	missing := filepath.Join(t.TempDir(), "nested", "missing.db")
	if _, err := OpenEvidenceReadOnly(missing, box); !errors.Is(err, ErrEvidenceDatabaseNotFound) {
		t.Fatalf("missing read-only database error=%v", err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only audit created parent directory: %v", err)
	}
}

func TestOpenEvidenceReadOnlyFallsBackToEncryptedLegacyPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM meta WHERE key='master_key_check'"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	readonly, err := OpenEvidenceReadOnly(path, box)
	if err != nil {
		t.Fatalf("legacy encrypted preflight rejected a valid database: %v", err)
	}
	if err := readonly.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKey, err := secret.NewBox(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEvidenceReadOnly(path, wrongKey); err == nil || !strings.Contains(err.Error(), "verify encrypted") {
		t.Fatalf("legacy encrypted preflight accepted the wrong key: %v", err)
	}
}

func TestEvidenceAuditErrorFormattingAndEntryValidation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("audit-entry"))
	entry := evidenceAuditEntry{Sequence: 1, EntryHash: hex.EncodeToString(digest[:]), Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, digest[:])), KeyID: evidenceKeyID(public)}
	if err := validateAuditEntry(entry, public, true, "entry"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mutate  func(*evidenceAuditEntry)
		genesis bool
	}{
		{name: "sequence", mutate: func(e *evidenceAuditEntry) { e.Sequence = 0 }, genesis: true},
		{name: "hash length", mutate: func(e *evidenceAuditEntry) { e.EntryHash = "bad" }, genesis: true},
		{name: "hash encoding", mutate: func(e *evidenceAuditEntry) { e.EntryHash = strings.Repeat("z", 64) }, genesis: true},
		{name: "predecessor length", mutate: func(e *evidenceAuditEntry) { e.PrevHash = "bad" }, genesis: false},
		{name: "predecessor encoding", mutate: func(e *evidenceAuditEntry) { e.PrevHash = strings.Repeat("z", 64) }, genesis: false},
		{name: "missing predecessor", mutate: func(e *evidenceAuditEntry) { e.PrevHash = "" }, genesis: false},
		{name: "key ID", mutate: func(e *evidenceAuditEntry) { e.KeyID = "ed25519:bad" }, genesis: true},
		{name: "signature", mutate: func(e *evidenceAuditEntry) { e.Signature = "bad" }, genesis: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := entry
			test.mutate(&candidate)
			if err := validateAuditEntry(candidate, public, test.genesis, "entry"); err == nil {
				t.Fatal("invalid entry was accepted")
			}
		})
	}
	wrapped := errors.New("cause")
	auditErr := &EvidenceAuditError{Sequence: 7, Check: "tamper", Err: wrapped}
	if !strings.Contains(auditErr.Error(), "sequence 7") || !errors.Is(auditErr, wrapped) || auditErr.Unwrap() != wrapped {
		t.Fatalf("audit error formatting or unwrap failed: %v", auditErr)
	}
	if got := (&EvidenceAuditError{Sequence: 7, Check: "tamper"}).Error(); !strings.Contains(got, "tamper") {
		t.Fatalf("nil-cause audit error=%q", got)
	}
	if got := (*EvidenceAuditError)(nil).Error(); got == "" {
		t.Fatal("nil audit error has empty text")
	}
}

func TestOpenEvidenceReadOnlyRejectsUnsafeTargets(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEvidenceReadOnly(filepath.Join(t.TempDir(), "missing.db"), box); !errors.Is(err, ErrEvidenceDatabaseNotFound) {
		t.Fatalf("missing database error=%v", err)
	}
	if _, err := OpenEvidenceReadOnly(t.TempDir(), box); err == nil {
		t.Fatal("directory was accepted as an audit database")
	}
	path := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(path, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEvidenceReadOnly(path, box); err == nil {
		t.Fatal("invalid SQLite file was accepted")
	}

	makeDB := func(t *testing.T) (string, *secret.Box) {
		t.Helper()
		dbPath := filepath.Join(t.TempDir(), "tailstate.db")
		st, err := Open(dbPath, box)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		return dbPath, box
	}
	tests := []struct {
		name   string
		mutate func(*sql.DB) error
	}{
		{name: "pending schema", mutate: func(db *sql.DB) error { _, err := db.Exec("UPDATE schema_version SET version=11"); return err }},
		{name: "unsupported schema", mutate: func(db *sql.DB) error {
			_, err := db.Exec("UPDATE schema_version SET version=?", currentSchemaVersion+1)
			return err
		}},
		{name: "duplicate schema marker", mutate: func(db *sql.DB) error {
			_, err := db.Exec("INSERT INTO schema_version(version) VALUES(?)", currentSchemaVersion)
			return err
		}},
		{name: "missing public key", mutate: func(db *sql.DB) error {
			_, err := db.Exec("DELETE FROM meta WHERE key=?", evidenceSigningPublicKeyMeta)
			return err
		}},
		{name: "missing key ID", mutate: func(db *sql.DB) error {
			_, err := db.Exec("DELETE FROM meta WHERE key=?", evidenceSigningKeyIDMeta)
			return err
		}},
		{name: "bad public key", mutate: func(db *sql.DB) error {
			_, err := db.Exec("UPDATE meta SET value='bad' WHERE key=?", evidenceSigningPublicKeyMeta)
			return err
		}},
		{name: "bad key ID", mutate: func(db *sql.DB) error {
			_, err := db.Exec("UPDATE meta SET value='ed25519:bad' WHERE key=?", evidenceSigningKeyIDMeta)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, _ := makeDB(t)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(db); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenEvidenceReadOnly(path, box); err == nil {
				t.Fatal("unsafe database was accepted")
			}
		})
	}
}

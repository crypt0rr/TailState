package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestParseEvidencePublicKeyAcceptsSupportedEncodings(t *testing.T) {
	public := make([]byte, ed25519.PublicKeySize)
	for index := range public {
		public[index] = byte(index + 1)
	}
	tests := map[string][]byte{
		"raw":        public,
		"raw base64": []byte(base64.RawStdEncoding.EncodeToString(public)),
		"base64":     []byte(base64.StdEncoding.EncodeToString(public)),
		"raw url":    []byte(base64.RawURLEncoding.EncodeToString(public)),
		"url":        []byte(base64.URLEncoding.EncodeToString(public)),
		"hex":        []byte(hex.EncodeToString(public)),
		"whitespace": []byte("  \n" + base64.RawStdEncoding.EncodeToString(public) + "\n\t"),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseEvidencePublicKey(encoded)
			if err != nil {
				t.Fatalf("ParseEvidencePublicKey() error = %v", err)
			}
			if string(got) != string(public) {
				t.Fatalf("decoded key = %x, want %x", got, public)
			}
			got[0] = 0xff
			if public[0] == 0xff {
				t.Fatal("ParseEvidencePublicKey returned the input backing array")
			}
		})
	}
}

func TestParseEvidencePublicKeyRejectsInvalidMaterial(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("not-a-key"), []byte(strings.Repeat("0", 62)), make([]byte, ed25519.PublicKeySize-1)} {
		if _, err := ParseEvidencePublicKey(raw); err == nil {
			t.Fatalf("ParseEvidencePublicKey(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestEvidenceSigningKeyAccessorsAndLedgerHeadFallbacks(t *testing.T) {
	ctx := context.Background()
	var unavailable Store
	if _, err := unavailable.EvidenceSigningKeyID(ctx); err == nil {
		t.Fatal("unavailable signing key ID unexpectedly succeeded")
	}
	if _, err := unavailable.EvidenceSigningPublicKey(ctx); err == nil {
		t.Fatal("unavailable signing public key unexpectedly succeeded")
	}

	st := testStore(t)
	id, err := st.EvidenceSigningKeyID(ctx)
	if err != nil || id == "" {
		t.Fatalf("EvidenceSigningKeyID() = %q, %v", id, err)
	}
	public, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("EvidenceSigningPublicKey() = %x, %v", public, err)
	}
	public[0] ^= 0xff
	unchanged, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil || unchanged[0] == public[0] {
		t.Fatal("EvidenceSigningPublicKey did not return a copy")
	}

	if head, err := st.evidenceLedgerHead(ctx); err != nil || head != "" {
		t.Fatalf("empty evidence ledger head = %q, %v", head, err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", evidenceLedgerHeadMeta, "meta-head"); err != nil {
		t.Fatal(err)
	}
	if head, err := st.evidenceLedgerHead(ctx); err != nil || head != "meta-head" {
		t.Fatalf("metadata evidence ledger head = %q, %v", head, err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO evidence_ledger(batch_id,generation,observed_at,prev_hash,entry_hash,signature,key_id,created_at) VALUES(1,1,'now','','row-head','sig','key','now')`); err != nil {
		t.Fatal(err)
	}
	if head, err := st.evidenceLedgerHead(ctx); err != nil || head != "row-head" {
		t.Fatalf("row evidence ledger head = %q, %v", head, err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if head, err := ledgerHeadTx(ctx, tx); err != nil || head != "row-head" {
		t.Fatalf("transaction evidence ledger head = %q, %v", head, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func signedEvidencePackFixture(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pack := EvidencePack{
		Format:  evidencePackFormat,
		Version: evidencePackVersion,
		Filter:  EvidenceFilter{Limit: 1},
		Batches: []EvidenceBatch{},
	}
	content, err := evidencePayload(pack)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256Sum(content)
	pack.ContentSHA256 = hash
	pack.SigningKeyID = evidenceKeyID(public)
	pack.SigningPublicKey = base64.RawStdEncoding.EncodeToString(public)
	pack.LedgerHead = ""
	pack.GeneratedAt = "2026-01-01T00:00:00Z"
	pack.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, evidenceSignaturePayload(pack)))
	data, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return data, public
}

func TestVerifyEvidencePackRejectsMalformedSignedPacks(t *testing.T) {
	data, public := signedEvidencePackFixture(t)
	if err := VerifyEvidencePack(data); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	if err := VerifyEvidencePackWithKey(data, public[:ed25519.PublicKeySize-1]); err == nil {
		t.Fatal("short trusted key unexpectedly accepted")
	}
	tests := []struct {
		name string
		edit func(*EvidencePack)
		want string
	}{
		{name: "bad format", edit: func(pack *EvidencePack) { pack.Format = "other" }, want: "unsupported evidence pack format"},
		{name: "bad version", edit: func(pack *EvidencePack) { pack.Version = 99 }, want: "unsupported evidence pack format"},
		{name: "missing metadata", edit: func(pack *EvidencePack) { pack.Signature = "" }, want: "signature metadata is incomplete"},
		{name: "bad public key", edit: func(pack *EvidencePack) { pack.SigningPublicKey = "bad" }, want: "decode evidence signing public key"},
		{name: "fingerprint mismatch", edit: func(pack *EvidencePack) { pack.SigningKeyID = "ed25519:" + strings.Repeat("0", 32) }, want: "fingerprint mismatch"},
		{name: "bad signature encoding", edit: func(pack *EvidencePack) { pack.Signature = "bad" }, want: "decode evidence signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pack EvidencePack
			if err := json.Unmarshal(data, &pack); err != nil {
				t.Fatal(err)
			}
			tt.edit(&pack)
			mutated, err := json.Marshal(pack)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyEvidencePack(mutated); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	var untrusted EvidencePack
	if err := json.Unmarshal(data, &untrusted); err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePackWithKey(data, other); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted key error = %v", err)
	}
	_ = untrusted

	var badSignature EvidencePack
	if err := json.Unmarshal(data, &badSignature); err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, ed25519.SignatureSize)
	signature[0] = 1
	badSignature.Signature = base64.RawStdEncoding.EncodeToString(signature)
	mutated, err := json.Marshal(badSignature)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(mutated); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("bad signature error = %v", err)
	}
}

func TestVerifyLedgerLinksRejectsInvalidChains(t *testing.T) {
	_, public := signedEvidencePackFixture(t)
	keyID := evidenceKeyID(public)
	tests := []struct {
		name string
		pack EvidencePack
		want string
	}{
		{name: "key mismatch", pack: EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerKeyID: "other"}}}, want: "ledger signing key mismatch"},
		{name: "hash length", pack: EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerSequence: 1, LedgerHash: "short"}}}, want: "invalid ledger hash"},
		{name: "hash encoding", pack: EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerSequence: 1, LedgerHash: strings.Repeat("z", 64)}}}, want: "invalid ledger hash"},
		{name: "chain mismatch", pack: EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 2, LedgerSequence: 2, LedgerPrevHash: strings.Repeat("a", 64), LedgerHash: strings.Repeat("b", 64)}, {ID: 1, LedgerSequence: 1, LedgerHash: strings.Repeat("c", 64)}}}, want: "evidence ledger chain mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyLedgerLinks(tt.pack); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
	if err := verifyLedgerLinks(EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerSequence: 0}, {ID: 2, LedgerSequence: 1, LedgerHash: strings.Repeat("a", 64)}}}); err != nil {
		t.Fatalf("sequence-zero/last batch was rejected: %v", err)
	}
}

func TestEvidenceSigningMetadataValidation(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newDB := func(t *testing.T) *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); err != nil {
			db.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	put := func(t *testing.T, db *sql.DB, values map[string]string) {
		t.Helper()
		for key, value := range values {
			if _, err := db.Exec("INSERT INTO meta(key,value) VALUES(?,?)", key, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	privateEncoded := base64.RawStdEncoding.EncodeToString(private)
	publicEncoded := base64.RawStdEncoding.EncodeToString(public)
	privateEnvelope, err := box.Encrypt(privateEncoded)
	if err != nil {
		t.Fatal(err)
	}
	keyID := evidenceKeyID(public)
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{"incomplete", map[string]string{evidenceSigningPrivateKeyMeta: privateEnvelope}, "metadata is incomplete"},
		{"bad private envelope", map[string]string{evidenceSigningPrivateKeyMeta: "bad", evidenceSigningPublicKeyMeta: publicEncoded, evidenceSigningKeyIDMeta: keyID}, "decrypt evidence signing key"},
		{"bad private length", map[string]string{evidenceSigningPrivateKeyMeta: mustEncryptForTest(t, box, base64.RawStdEncoding.EncodeToString(make([]byte, 31))), evidenceSigningPublicKeyMeta: publicEncoded, evidenceSigningKeyIDMeta: keyID}, "decode evidence signing key"},
		{"bad public length", map[string]string{evidenceSigningPrivateKeyMeta: privateEnvelope, evidenceSigningPublicKeyMeta: "bad", evidenceSigningKeyIDMeta: keyID}, "decode evidence signing public key"},
		{"key pair mismatch", map[string]string{evidenceSigningPrivateKeyMeta: privateEnvelope, evidenceSigningPublicKeyMeta: base64.RawStdEncoding.EncodeToString(otherPublic), evidenceSigningKeyIDMeta: evidenceKeyID(otherPublic)}, "key pair does not match"},
		{"fingerprint mismatch", map[string]string{evidenceSigningPrivateKeyMeta: privateEnvelope, evidenceSigningPublicKeyMeta: publicEncoded, evidenceSigningKeyIDMeta: "ed25519:bad"}, "fingerprint does not match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			put(t, db, tc.values)
			if _, err := loadOrCreateEvidenceSigningKey(context.Background(), db, box); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestEvidenceLedgerOperationalErrors(t *testing.T) {
	st := testStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.backfillEvidenceLedger(context.Background()); err == nil {
		t.Fatal("backfillEvidenceLedger succeeded on a closed store")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateEvidenceSigningKey(context.Background(), db, box); err == nil || !strings.Contains(err.Error(), "read evidence_signing_private_key_enc") {
		t.Fatalf("missing metadata table error=%v", err)
	}
	if _, _, err := evidenceLedgerPayload(context.Background(), db, 1); err == nil {
		t.Fatal("evidenceLedgerPayload succeeded without event batch storage")
	}
}

func TestEvidenceLedgerHeadOperationalErrors(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.db.ExecContext(ctx, "DROP TABLE evidence_ledger"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.evidenceLedgerHead(ctx); err == nil {
		t.Fatal("evidenceLedgerHead succeeded without its table")
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := ledgerHeadTx(ctx, tx); err == nil {
		t.Fatal("ledgerHeadTx succeeded without its table")
	}
}

type failingWebhookTriggerScanner struct{}

func (failingWebhookTriggerScanner) Scan(...any) error {
	return errors.New("scan failed")
}

func TestWebhookTriggerScannerErrors(t *testing.T) {
	if _, err := readWebhookTrigger(failingWebhookTriggerScanner{}); err == nil {
		t.Fatal("readWebhookTrigger accepted a failing scanner")
	}
}

func insertSigningBatch(t *testing.T, st *Store) int64 {
	t.Helper()
	result, err := st.db.ExecContext(context.Background(), "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), 0, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEvidenceSigningDatabaseErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("backfill event batch query", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE event_batches"); err != nil {
			t.Fatal(err)
		}
		if err := st.backfillEvidenceLedger(ctx); err == nil {
			t.Fatal("backfillEvidenceLedger succeeded without event batches")
		}
	})

	t.Run("backfill event payload", func(t *testing.T) {
		st := testStore(t)
		insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE events"); err != nil {
			t.Fatal(err)
		}
		if err := st.backfillEvidenceLedger(ctx); err == nil {
			t.Fatal("backfillEvidenceLedger succeeded without events")
		}
	})

	t.Run("append payload query", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE event_batches"); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := st.appendEvidenceLedgerTx(ctx, tx, 1); err == nil {
			t.Fatal("appendEvidenceLedgerTx succeeded without event batches")
		}
	})

	t.Run("append ledger insert", func(t *testing.T) {
		st := testStore(t)
		batchID := insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_evidence_ledger_insert BEFORE INSERT ON evidence_ledger BEGIN SELECT RAISE(ABORT,'ledger insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := st.appendEvidenceLedgerTx(ctx, tx, batchID); err == nil {
			t.Fatal("appendEvidenceLedgerTx ignored ledger insert failure")
		}
	})

	t.Run("append ledger head update", func(t *testing.T) {
		st := testStore(t)
		batchID := insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_evidence_ledger_head BEFORE INSERT ON meta WHEN NEW.key='evidence_ledger_head' BEGIN SELECT RAISE(ABORT,'ledger head update failed'); END`); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := st.appendEvidenceLedgerTx(ctx, tx, batchID); err == nil {
			t.Fatal("appendEvidenceLedgerTx ignored ledger head failure")
		}
	})

	t.Run("evidence trigger payload query", func(t *testing.T) {
		st := testStore(t)
		batchID := insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE event_batch_triggers"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := evidenceLedgerPayload(ctx, st.db, batchID); err == nil {
			t.Fatal("evidenceLedgerPayload succeeded without trigger links")
		}
	})

	t.Run("evidence event payload query", func(t *testing.T) {
		st := testStore(t)
		batchID := insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE events"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := evidenceLedgerPayload(ctx, st.db, batchID); err == nil {
			t.Fatal("evidenceLedgerPayload succeeded without events")
		}
	})
}

func TestEvidenceSigningStorageAndFallbackBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("signing key insert", func(t *testing.T) {
		box, err := secret.NewBox(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.ExecContext(ctx, "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fail_signing_key_insert BEFORE INSERT ON meta BEGIN SELECT RAISE(ABORT,'signing key insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateEvidenceSigningKey(ctx, db, box); err == nil || !strings.Contains(err.Error(), "store") {
			t.Fatalf("signing key insert error=%v", err)
		}
	})

	t.Run("append ledger query", func(t *testing.T) {
		st := testStore(t)
		batchID := insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE evidence_ledger"); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := st.appendEvidenceLedgerTx(ctx, tx, batchID); err == nil {
			t.Fatal("appendEvidenceLedgerTx ignored ledger query failure")
		}
	})

	t.Run("append ledger head metadata query", func(t *testing.T) {
		st := testStore(t)
		batchID := insertSigningBatch(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE meta"); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := st.appendEvidenceLedgerTx(ctx, tx, batchID); err == nil {
			t.Fatal("appendEvidenceLedgerTx ignored ledger head metadata failure")
		}
	})

	t.Run("payload trigger fallback", func(t *testing.T) {
		st := testStore(t)
		result, err := st.db.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at,trigger_id) VALUES(1,?,?,?,77)", time.Now().UTC().Format(time.RFC3339Nano), 0, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		batchID, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		_, batch, err := evidenceLedgerPayload(ctx, st.db, batchID)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch.TriggerIDs) != 1 || batch.TriggerIDs[0] != 77 {
			t.Fatalf("trigger fallback=%v", batch.TriggerIDs)
		}
	})

	t.Run("ledger head metadata error", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE evidence_ledger"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "DROP TABLE meta"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.evidenceLedgerHead(ctx); err == nil {
			t.Fatal("evidenceLedgerHead ignored metadata query failure")
		}
	})
}

func TestVerifyEvidencePackReportsLedgerLinkErrors(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pack := EvidencePack{
		Format:           evidencePackFormat,
		Version:          evidencePackVersion,
		Filter:           EvidenceFilter{Limit: 1},
		Batches:          []EvidenceBatch{{ID: 1, LedgerKeyID: "ed25519:other"}},
		SigningKeyID:     evidenceKeyID(public),
		SigningPublicKey: base64.RawStdEncoding.EncodeToString(public),
		GeneratedAt:      "2026-01-01T00:00:00Z",
	}
	content, err := evidencePayload(pack)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Sum(content)
	pack.ContentSHA256 = digest
	pack.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, evidenceSignaturePayload(pack)))
	data, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(data); err == nil || !strings.Contains(err.Error(), "ledger signing key mismatch") {
		t.Fatalf("ledger link error=%v", err)
	}
}

func mustEncryptForTest(t *testing.T, box *secret.Box, value string) string {
	t.Helper()
	encrypted, err := box.Encrypt(value)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

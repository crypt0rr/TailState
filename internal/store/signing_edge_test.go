package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

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

func mustEncryptForTest(t *testing.T, box *secret.Box, value string) string {
	t.Helper()
	encrypted, err := box.Encrypt(value)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

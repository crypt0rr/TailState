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
	"strconv"
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

func TestVerifyEvidencePackRejectsUnknownFields(t *testing.T) {
	data, _ := signedEvidencePackFixture(t)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["untrusted_annotation"] = json.RawMessage(`"not covered by the signature"`)
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(mutated); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown evidence field was accepted: %v", err)
	}
}

func TestVerifyEvidencePackRejectsAmbiguousPagination(t *testing.T) {
	data, _ := signedEvidencePackFixture(t)
	tests := []struct {
		name string
		edit func(*EvidencePack)
		want string
	}{
		{
			name: "truncated without cursor",
			edit: func(pack *EvidencePack) {
				pack.Truncated = true
				pack.NextCursor = 0
			},
			want: "truncated evidence pack is missing next cursor",
		},
		{
			name: "truncated without batches",
			edit: func(pack *EvidencePack) {
				pack.Truncated = true
				pack.NextCursor = 1
			},
			want: "truncated evidence pack has no batches",
		},
		{
			name: "cursor does not identify last batch",
			edit: func(pack *EvidencePack) {
				pack.Truncated = true
				pack.Batches = []EvidenceBatch{{ID: 10}}
				pack.NextCursor = 42
			},
			want: "truncated evidence pack cursor does not match last batch",
		},
		{
			name: "complete with cursor",
			edit: func(pack *EvidencePack) {
				pack.Truncated = false
				pack.NextCursor = 42
			},
			want: "complete evidence pack has an unexpected next cursor",
		},
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
}

func TestVerifyEvidencePackRejectsVersionDowngrade(t *testing.T) {
	data, public := signedEvidencePackFixture(t)
	var forged EvidencePack
	if err := json.Unmarshal(data, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Version = 1
	forged.Batches = nil
	content, err := evidencePayload(forged)
	if err != nil {
		t.Fatal(err)
	}
	forged.ContentSHA256 = sha256Sum(content)
	encoded, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePackWithKey(encoded, public); err == nil {
		t.Fatal("trusted-key verification accepted a forged version-downgraded pack")
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
		{name: "mixed ledger state", pack: EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerSequence: 1, LedgerHash: strings.Repeat("a", 64)}, {ID: 2, LedgerSequence: 0}}}, want: "mixes ledgered and unledgered batches"},
		{name: "negative sequence", pack: EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerSequence: -1}}}, want: "invalid ledger sequence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyLedgerLinks(tt.pack); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
	if err := verifyLedgerLinks(EvidencePack{SigningKeyID: keyID, Batches: []EvidenceBatch{{ID: 1, LedgerSequence: 0}, {ID: 2, LedgerSequence: 0, LedgerHash: strings.Repeat("a", 64)}}}); err != nil {
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

func TestEvidenceLedgerBackfillIsStartupOnly(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.db.ExecContext(ctx, "DELETE FROM meta WHERE key IN (?,?)", evidenceLedgerBackfilledMeta, evidenceLedgerBackfillCutoff); err != nil {
		t.Fatal(err)
	}
	firstBatchID := insertCompleteSigningBatch(t, st)
	if _, err := st.db.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?)", evidenceLedgerBackfillCutoff, strconv.FormatInt(firstBatchID, 10)); err != nil {
		t.Fatal(err)
	}
	if err := st.backfillEvidenceLedgerOnStartup(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger WHERE batch_id=?", firstBatchID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("initial historical batch was not backfilled: %d ledger rows", count)
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM meta WHERE key=?", evidenceLedgerBackfilledMeta); err != nil {
		t.Fatal(err)
	}
	secondBatchID := insertCompleteSigningBatch(t, st)
	if err := st.backfillEvidenceLedgerOnStartup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger WHERE batch_id=?", secondBatchID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("post-cutoff batch acquired a historical ledger row: %d", count)
	}
}

func TestEvidenceLedgerBackfillCursorValidation(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.db.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?)", evidenceLedgerBackfillCursor, "not-a-number"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.evidenceLedgerBackfillCursor(ctx); err == nil || !strings.Contains(err.Error(), "invalid evidence ledger backfill cursor") {
		t.Fatalf("invalid ledger cursor error=%v", err)
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM meta WHERE key=?", evidenceLedgerBackfillCursor); err != nil {
		t.Fatal(err)
	}
	if cursor, err := st.evidenceLedgerBackfillCursor(ctx); err != nil || cursor != 0 {
		t.Fatalf("missing ledger cursor=%d err=%v", cursor, err)
	}
	if err := st.clearEvidenceLedgerBackfillCursor(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.clearEvidenceLedgerBackfillCursor(ctx); err == nil {
		t.Fatal("clearing cursor on closed store unexpectedly succeeded")
	}
}

func TestEvidenceLedgerBackfillResumesAfterAChunkFailure(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	for i := 0; i < evidenceLedgerBackfillChunkSize+1; i++ {
		insertCompleteSigningBatch(t, st)
	}
	if _, err := st.db.ExecContext(ctx, "CREATE TRIGGER fail_second_ledger_chunk BEFORE INSERT ON evidence_ledger WHEN NEW.batch_id>"+strconv.Itoa(evidenceLedgerBackfillChunkSize)+" BEGIN SELECT RAISE(ABORT,'pause ledger backfill'); END"); err != nil {
		t.Fatal(err)
	}
	if err := st.backfillEvidenceLedger(ctx); err == nil || !strings.Contains(err.Error(), "append evidence ledger") {
		t.Fatalf("first ledger backfill error=%v", err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != evidenceLedgerBackfillChunkSize {
		t.Fatalf("completed ledger rows=%d, want %d", count, evidenceLedgerBackfillChunkSize)
	}
	var cursor string
	if err := st.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceLedgerBackfillCursor).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != strconv.Itoa(evidenceLedgerBackfillChunkSize) {
		t.Fatalf("ledger cursor=%q, want %d", cursor, evidenceLedgerBackfillChunkSize)
	}
	if _, err := st.db.ExecContext(ctx, "DROP TRIGGER fail_second_ledger_chunk"); err != nil {
		t.Fatal(err)
	}
	if err := st.backfillEvidenceLedger(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != evidenceLedgerBackfillChunkSize+1 {
		t.Fatalf("resumed ledger rows=%d, want %d", count, evidenceLedgerBackfillChunkSize+1)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM meta WHERE key=?", evidenceLedgerBackfillCursor).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("ledger progress cursor was not cleared")
	}
}

func TestEvidenceLedgerStartupDoesNotInferMissingCutoffFromRows(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.db.ExecContext(ctx, "DELETE FROM meta WHERE key IN (?,?)", evidenceLedgerBackfilledMeta, evidenceLedgerBackfillCutoff); err != nil {
		t.Fatal(err)
	}
	batchID := insertCompleteSigningBatch(t, st)
	if err := st.backfillEvidenceLedgerOnStartup(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger WHERE batch_id=?", batchID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("startup inferred a historical cutoff and signed batch %d", batchID)
	}
}

func TestEvidenceExportRejectsMixedLedgerState(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	insertCompleteSigningBatch(t, st)
	if err := st.backfillEvidenceLedger(ctx); err != nil {
		t.Fatal(err)
	}
	// A row inserted after the one-time backfill has no ledger entry. It must
	// not be silently included beside authenticated history in a signed pack.
	insertCompleteSigningBatch(t, st)
	if _, err := st.ExportEvidencePack(ctx, HistoryFilter{Limit: 10}); err == nil || !strings.Contains(err.Error(), "mixes ledgered and unledgered batches") {
		t.Fatalf("mixed ledger export was accepted: %v", err)
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

func insertCompleteSigningBatch(t *testing.T, st *Store) int64 {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := st.db.ExecContext(context.Background(), "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,?,?)", now, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json)
		VALUES(?,?,?,?,?,?,?,?)`, id, 1, now, "devices", "changed", "device-"+strconv.FormatInt(id, 10), "server", `[]`); err != nil {
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

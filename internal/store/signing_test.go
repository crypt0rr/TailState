package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestEvidenceSigningKeyPersistsAndVerifiesExports(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
		st.Close()
		t.Fatal(err)
	}
	packData, err := st.ExportEvidencePack(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	public, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if len(public) != ed25519.PublicKeySize {
		st.Close()
		t.Fatalf("unexpected public key length %d", len(public))
	}
	var pack EvidencePack
	if err := json.Unmarshal(packData, &pack); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if pack.Version != evidencePackVersion || pack.SigningKeyID == "" || pack.Signature == "" || pack.LedgerHead == "" {
		st.Close()
		t.Fatalf("unsigned evidence pack: %#v", pack)
	}
	if err := VerifyEvidencePackWithKey(packData, public); err != nil {
		st.Close()
		t.Fatalf("trusted evidence verification failed: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedPublic, err := reopened.EvidenceSigningPublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(reopenedPublic) != string(public) {
		t.Fatal("evidence signing public key changed after restart")
	}

	var generatedTamper EvidencePack
	if err := json.Unmarshal(packData, &generatedTamper); err != nil {
		t.Fatal(err)
	}
	generatedTamper.GeneratedAt = "2000-01-01T00:00:00Z"
	tampered, err := json.Marshal(generatedTamper)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(tampered); err == nil {
		t.Fatal("tampered generated timestamp unexpectedly verified")
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePackWithKey(packData, wrongPublic); err == nil {
		t.Fatal("evidence pack verified with an unrelated key")
	}
}

func TestEvidenceLedgerChainAndEncryptedKeyMetadata(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"server", "server-one", "server-two"} {
		if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource(hostname, "100.64.0.1")}, func([]model.Change) string { return hostname }); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 2 {
		t.Fatalf("unexpected signed history batches: %#v", page.Batches)
	}
	newest, older := page.Batches[0], page.Batches[1]
	if newest.LedgerSequence != older.LedgerSequence+1 || newest.LedgerPrevHash != older.LedgerHash || newest.LedgerHash == "" || newest.LedgerSignature == "" {
		t.Fatalf("ledger chain is not continuous: newest=%#v older=%#v", newest, older)
	}
	var encrypted string
	if err := st.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceSigningPrivateKeyMeta).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "" || strings.Contains(encrypted, base64.RawStdEncoding.EncodeToString(st.evidenceKey.private)) {
		t.Fatal("evidence private key was stored without encryption")
	}
}

func TestEvidenceLedgerEntrySignaturesVerifyIndependently(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	data, err := st.ExportEvidencePack(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	if err := verifyLedgerLinks(pack); err != nil {
		t.Fatalf("valid ledger signatures rejected: %v", err)
	}
	pack.Batches[0].LedgerSignature = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	for index := range pack.LedgerLinks {
		if pack.LedgerLinks[index].BatchID == pack.Batches[0].ID {
			pack.LedgerLinks[index].Signature = pack.Batches[0].LedgerSignature
		}
	}
	if err := verifyLedgerLinks(pack); err == nil || !strings.Contains(err.Error(), "ledger signature verification failed") {
		t.Fatalf("tampered ledger signature accepted: %v", err)
	}
}

func TestEvidencePackV1IsRejected(t *testing.T) {
	pack := EvidencePack{Format: evidencePackFormat, Version: 1, Filter: EvidenceFilter{Limit: 1}, Batches: []EvidenceBatch{}}
	// The payload does not include the content hash, so compute it after the
	// stable v1 fields have been assembled.
	content, err := evidencePayload(pack)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Sum(content)
	pack.ContentSHA256 = digest
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(encoded); err == nil || !strings.Contains(err.Error(), "unsupported evidence pack format") {
		t.Fatalf("legacy evidence pack was accepted: %v", err)
	}
}

func sha256Sum(data []byte) string {
	// Keep this helper local to the test so the compatibility fixture mirrors
	// the public verifier without exposing another production API.
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

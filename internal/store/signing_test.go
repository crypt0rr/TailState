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
	"time"

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
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
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

func TestFilteredEvidencePackVerifiesWithOriginalLedgerCount(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := model.Collected{Collector: "devices", Resources: []model.Resource{
		{ID: "device-1", Type: "device", Name: "server-1", Data: map[string]any{"hostname": "server-1"}},
		{ID: "device-2", Type: "device", Name: "server-2", Data: map[string]any{"hostname": "server-2"}},
	}}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{baseline}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	changed := model.Collected{Collector: "devices", Resources: []model.Resource{
		{ID: "device-1", Type: "device", Name: "server-1-new", Data: map[string]any{"hostname": "server-1-new"}},
		{ID: "device-2", Type: "device", Name: "server-2-new", Data: map[string]any{"hostname": "server-2-new"}},
	}}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{changed}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	encoded, err := st.ExportEvidencePack(ctx, HistoryFilter{ResourceID: "device-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(encoded); err != nil {
		t.Fatalf("filtered evidence pack did not verify: %v", err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(encoded, &pack); err != nil {
		t.Fatal(err)
	}
	if len(pack.Batches) != 1 || len(pack.Batches[0].Events) != 1 {
		t.Fatalf("unexpected filtered evidence pack: %#v", pack.Batches)
	}
	if pack.Batches[0].ChangeCount != 1 || pack.Batches[0].LedgerChangeCount != 2 {
		t.Fatalf("filtered and ledger change counts were not distinguished: %#v", pack.Batches[0])
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
		if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource(hostname, "100.64.0.1")}, func([]model.Change) string { return hostname }); err != nil {
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
	links, err := st.evidenceLedgerLinks(ctx, []HistoryBatch{{LedgerSequence: newest.LedgerSequence}})
	if err != nil {
		t.Fatalf("evidenceLedgerLinks() error = %v", err)
	}
	if len(links) != 2 || links[0].Sequence != older.LedgerSequence || links[1].Sequence != newest.LedgerSequence {
		t.Fatalf("filtered ledger links = %#v, want predecessor checkpoint and selected entry", links)
	}
	var encrypted string
	if err := st.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", evidenceSigningPrivateKeyMeta).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "" || strings.Contains(encrypted, base64.RawStdEncoding.EncodeToString(st.evidenceKey.private)) {
		t.Fatal("evidence private key was stored without encryption")
	}
}

func TestEvidenceLedgerSurvivesHistoryRetention(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server-one", "100.64.0.2")}, func([]model.Change) string { return "old" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server-two", "100.64.0.3")}, func([]model.Change) string { return "new" }); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil || len(page.Batches) != 2 {
		t.Fatalf("history before retention = %#v, %v", page.Batches, err)
	}
	oldObservedAt := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE events SET observed_at=? WHERE batch_id=?", oldObservedAt, page.Batches[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var ledgerRows, batches int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM evidence_ledger").Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM event_batches").Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 2 || batches != 1 {
		t.Fatalf("retention removed ledger checkpoints: ledger=%d batches=%d", ledgerRows, batches)
	}
	pack, err := st.ExportEvidencePack(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(pack); err != nil {
		t.Fatalf("retained ledger export did not verify: %v", err)
	}
	var exported EvidencePack
	if err := json.Unmarshal(pack, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Batches) != 1 || len(exported.LedgerLinks) != 2 {
		t.Fatalf("retained ledger checkpoint missing from export: batches=%d links=%d", len(exported.Batches), len(exported.LedgerLinks))
	}
}

func TestEvidenceLedgerEntrySignaturesVerifyIndependently(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.applyBatch(ctx, generation, []model.Collected{historyResource("server-newer", "100.64.0.3")}, func([]model.Change) string { return "changed-again" }); err != nil {
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
	if len(pack.LedgerLinks) < 2 {
		t.Fatalf("expected a ledger checkpoint and selected entry, got %d links", len(pack.LedgerLinks))
	}
	withoutCheckpoint := pack
	withoutCheckpoint.LedgerLinks = append([]EvidenceLedgerLink(nil), pack.LedgerLinks[1:]...)
	if err := verifyLedgerLinks(withoutCheckpoint); err == nil || !strings.Contains(err.Error(), "ledger checkpoint is missing") {
		t.Fatalf("missing ledger checkpoint was accepted: %v", err)
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

package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
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
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{baseline}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	changed := model.Collected{Collector: "devices", Resources: []model.Resource{
		{ID: "device-1", Type: "device", Name: "server-1-new", Data: map[string]any{"hostname": "server-1-new"}},
		{ID: "device-2", Type: "device", Name: "server-2-new", Data: map[string]any{"hostname": "server-2-new"}},
	}}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{changed}, func([]model.Change) string { return "changed" }); err != nil {
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

func TestPaginatedEvidencePacksVerifyCompleteness(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxEvidenceBatches+1; i++ {
		hostname := fmt.Sprintf("server-%03d", i)
		if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource(hostname, fmt.Sprintf("100.64.0.%d", i+2))}, func([]model.Change) string { return hostname }); err != nil {
			t.Fatal(err)
		}
	}

	firstData, err := st.ExportEvidencePack(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(firstData); err != nil {
		t.Fatalf("first evidence page did not verify: %v", err)
	}
	var first EvidencePack
	if err := json.Unmarshal(firstData, &first); err != nil {
		t.Fatal(err)
	}
	if !first.Truncated || first.NextCursor <= 0 || first.Filter.Cursor != 0 || first.Filter.Limit != maxEvidenceBatches || len(first.Batches) != maxEvidenceBatches {
		t.Fatalf("unexpected first evidence page metadata: truncated=%t cursor=%d filter=%#v batches=%d", first.Truncated, first.NextCursor, first.Filter, len(first.Batches))
	}
	if first.Batches[len(first.Batches)-1].ID != first.NextCursor {
		t.Fatalf("first evidence page cursor=%d does not match final batch %d", first.NextCursor, first.Batches[len(first.Batches)-1].ID)
	}

	secondData, err := st.ExportEvidencePack(ctx, HistoryFilter{Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(secondData); err != nil {
		t.Fatalf("second evidence page did not verify: %v", err)
	}
	var second EvidencePack
	if err := json.Unmarshal(secondData, &second); err != nil {
		t.Fatal(err)
	}
	if second.Truncated || second.NextCursor != 0 || second.Filter.Cursor != first.NextCursor || second.Filter.Limit != maxEvidenceBatches || len(second.Batches) != 1 {
		t.Fatalf("unexpected second evidence page metadata: truncated=%t cursor=%d filter=%#v batches=%d", second.Truncated, second.NextCursor, second.Filter, len(second.Batches))
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
		if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource(hostname, "100.64.0.1")}, func([]model.Change) string { return hostname }); err != nil {
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
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-one", "100.64.0.2")}, func([]model.Change) string { return "old" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-two", "100.64.0.3")}, func([]model.Change) string { return "new" }); err != nil {
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
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-newer", "100.64.0.3")}, func([]model.Change) string { return "changed-again" }); err != nil {
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
	projectionTampered := pack
	projectionTampered.Batches = append([]EvidenceBatch(nil), pack.Batches...)
	projectionTampered.Batches[0].Events = append([]EvidenceEvent(nil), pack.Batches[0].Events...)
	projectionTampered.Batches[0].Events[0].Name = "tampered projection"
	if err := verifyLedgerLinks(projectionTampered); err == nil || !strings.Contains(err.Error(), "ledger payload event metadata mismatch") {
		t.Fatalf("ledger payload/event projection mismatch was accepted: %v", err)
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

func TestEvidenceLedgerGenesisCheckpointHasNoPredecessor(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "device-2", Type: "device", Name: "server-newer", Data: map[string]any{"hostname": "server-newer", "addresses": []any{"100.64.0.3"}},
	}}}}, func([]model.Change) string { return "changed-again" }); err != nil {
		t.Fatal(err)
	}
	data, err := st.ExportEvidencePack(ctx, HistoryFilter{ResourceID: "device-2"})
	if err != nil {
		t.Fatal(err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	if len(pack.Batches) != 1 || len(pack.LedgerLinks) != 2 || pack.LedgerLinks[0].Sequence != 1 {
		t.Fatalf("expected one selected batch and a genesis checkpoint: batches=%d links=%#v", len(pack.Batches), pack.LedgerLinks)
	}
	pack.LedgerLinks[0].PrevHash = strings.Repeat("a", sha256.Size*2)
	if err := verifyLedgerLinks(pack); err == nil || !strings.Contains(err.Error(), "genesis link has a previous hash") {
		t.Fatalf("non-empty genesis predecessor was accepted: %v", err)
	}
}

func TestVerifyLedgerPayloadProjectionBinding(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.2")}, func([]model.Change) string { return "changed" }); err != nil {
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
	if len(pack.Batches) != 1 || len(pack.Batches[0].Events) != 1 || len(pack.Batches[0].Events[0].Fields) == 0 {
		t.Fatalf("unexpected evidence fixture: %#v", pack.Batches)
	}
	clone := func() EvidencePack {
		encoded, marshalErr := json.Marshal(pack)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var copied EvidencePack
		if unmarshalErr := json.Unmarshal(encoded, &copied); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		return copied
	}
	tests := []struct {
		name string
		edit func(*EvidencePack)
		want string
	}{
		{name: "event metadata", edit: func(p *EvidencePack) { p.Batches[0].Events[0].Name = "tampered" }, want: "event metadata mismatch"},
		{name: "event timestamp", edit: func(p *EvidencePack) { p.Batches[0].Events[0].ObservedAt = time.Time{} }, want: "event timestamp mismatch"},
		{name: "event fields", edit: func(p *EvidencePack) { p.Batches[0].Events[0].Fields[0].Field = "tampered" }, want: "event fields mismatch"},
		{name: "event snapshot", edit: func(p *EvidencePack) { p.Batches[0].Events[0].After = json.RawMessage(`{"tampered":true}`) }, want: "event snapshot mismatch"},
		{name: "unknown event", edit: func(p *EvidencePack) { p.Batches[0].Events[0].ID = 999999 }, want: "missing event"},
		{name: "duplicate event", edit: func(p *EvidencePack) { p.Batches[0].Events = append(p.Batches[0].Events, p.Batches[0].Events[0]) }, want: "duplicate event"},
		{name: "trigger metadata", edit: func(p *EvidencePack) { p.Batches[0].TriggerIDs = []int64{99} }, want: "trigger metadata mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := clone()
			tt.edit(&mutated)
			if err := verifyLedgerLinks(mutated); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	payload, err := base64.RawStdEncoding.DecodeString(pack.Batches[0].LedgerPayload)
	if err != nil {
		t.Fatal(err)
	}
	var ledgerBatch evidenceLedgerBatch
	if err := json.Unmarshal(payload, &ledgerBatch); err != nil {
		t.Fatal(err)
	}
	validBatch := pack.Batches[0]
	if err := verifyLedgerPayloadBinding(validBatch, ledgerBatch); err != nil {
		t.Fatalf("valid ledger projection rejected: %v", err)
	}
	unknownPayload := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"unknown":true}`)...)
	unknownFieldsPack := clone()
	unknownFieldsPack.Batches[0].LedgerPayload = base64.RawStdEncoding.EncodeToString(unknownPayload)
	if err := verifyLedgerLinks(unknownFieldsPack); err == nil || !strings.Contains(err.Error(), "decode ledger payload") {
		t.Fatalf("unknown ledger payload field was accepted: %v", err)
	}
	trailingPayload := append(append([]byte(nil), payload...), []byte(` {}`)...)
	trailingPack := clone()
	trailingPack.Batches[0].LedgerPayload = base64.RawStdEncoding.EncodeToString(trailingPayload)
	if err := verifyLedgerLinks(trailingPack); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing ledger payload was accepted: %v", err)
	}
	duplicateLedgerBatch := ledgerBatch
	duplicateLedgerBatch.Events = append([]evidenceLedgerEvent(nil), ledgerBatch.Events...)
	duplicateLedgerBatch.Events = append(duplicateLedgerBatch.Events, ledgerBatch.Events[0])
	duplicateBatch := validBatch
	duplicateBatch.LedgerChangeCount = duplicateLedgerBatch.ChangeCount + 1
	duplicateLedgerBatch.ChangeCount = duplicateBatch.LedgerChangeCount
	if err := verifyLedgerPayloadBinding(duplicateBatch, duplicateLedgerBatch); err == nil || !strings.Contains(err.Error(), "duplicate event") {
		t.Fatalf("duplicate ledger event accepted: %v", err)
	}
	shortLedgerBatch := ledgerBatch
	shortLedgerBatch.Events = nil
	if err := verifyLedgerPayloadBinding(validBatch, shortLedgerBatch); err == nil || !strings.Contains(err.Error(), "event count mismatch") {
		t.Fatalf("ledger event count mismatch accepted: %v", err)
	}
	badFields, _, _, err := evidenceFieldsFromLedger([]byte(`not-json`))
	if err == nil || badFields != nil {
		t.Fatalf("invalid ledger fields accepted: fields=%#v err=%v", badFields, err)
	}
	if !bytes.Equal(canonicalEvidenceJSON(json.RawMessage(`{"b":2,"a":1}`)), []byte(`{"a":1,"b":2}`)) {
		t.Fatal("canonical evidence JSON did not normalize object keys")
	}
	if !bytes.Equal(canonicalEvidenceJSON(json.RawMessage(`not-json`)), []byte(`not-json`)) {
		t.Fatal("invalid evidence JSON was unexpectedly rewritten")
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

func TestEvidenceProjectionComparisonHelpers(t *testing.T) {
	if !equalInt64Slices([]int64{1, 2}, []int64{1, 2}) {
		t.Fatal("equal integer slices reported a matching pair as different")
	}
	for name, pair := range map[string][2][]int64{
		"length": {{1}, {1, 2}},
		"value":  {{1, 2}, {1, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			if equalInt64Slices(pair[0], pair[1]) {
				t.Fatalf("equal integer slices accepted mismatched %s", name)
			}
		})
	}
}

func sha256Sum(data []byte) string {
	// Keep this helper local to the test so the compatibility fixture mirrors
	// the public verifier without exposing another production API.
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

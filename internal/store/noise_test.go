package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

// TestFleetRolloutSendsOneSummaryLineAndHistoryListsEveryDevice is the E-009
// acceptance guarantee for rollouts: one digest line for N devices while
// History keeps one event per device.
func TestFleetRolloutSendsOneSummaryLineAndHistoryListsEveryDevice(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	const devices = 8
	available := func(value bool) func(int) map[string]any {
		return func(int) map[string]any { return map[string]any{"updateAvailable": value} }
	}
	digest := notify.Context{Tailnet: "example.com"}.Digest
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(available(false), devices)}, digest); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(available(true), devices)}, digest)
	if err != nil {
		t.Fatal(err)
	}
	payloads := pendingPayloads(t, st, batch.ID)
	if len(payloads) != 1 || strings.Count(payloads[0], "updateAvailable") != 1 || !strings.Contains(payloads[0], fmt.Sprintf("on %d resources (devices)", devices)) || strings.Contains(payloads[0], "host\\-a") {
		t.Fatalf("rollout digest is not one summary line: %q", payloads)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{BatchID: batch.ID})
	if err != nil || len(page.Batches) != 1 || len(page.Batches[0].Events) != devices {
		t.Fatalf("History does not list every device: %+v err=%v", page.Batches, err)
	}
}

// TestUpstreamSchemaAdditionFixtureProducesOneLine feeds a keys fixture
// whose upstream response gained a field on every key (as Tailscale added
// audience/issuer/subject to Key) and expects one schema-change line.
func TestUpstreamSchemaAdditionFixtureProducesOneLine(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	keys := func(withAudience bool) model.Collected {
		resources := make([]model.Resource, 0, 3)
		for index := 0; index < 3; index++ {
			data := map[string]any{"id": fmt.Sprintf("k%d", index), "description": fmt.Sprintf("key %d", index), "capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{"reusable": index%2 == 0}}}}
			if withAudience {
				data["audience"] = fmt.Sprintf("api://tailstate/%d", index)
			}
			resources = append(resources, model.Resource{ID: fmt.Sprintf("k%d", index), Type: "key", Name: fmt.Sprintf("key-%d", index), Collector: "keys", Data: data})
		}
		return model.Collected{Collector: "keys", Resources: resources}
	}
	digest := notify.Context{}.Digest
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{keys(false)}, digest); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{keys(true)}, digest)
	if err != nil || len(batch.Changes) != 3 {
		t.Fatalf("schema batch=%+v err=%v", batch, err)
	}
	payloads := pendingPayloads(t, st, batch.ID)
	if len(payloads) != 1 || strings.Count(payloads[0], "Upstream schema change") != 1 || !strings.Contains(payloads[0], "`audience` newly present on all 3 keys resources") || strings.Contains(payloads[0], "**key\\-1**") {
		t.Fatalf("schema addition digest: %q", payloads)
	}
}

// TestMutedChangesAreRecordedFlaggedAndSigned is the E-009 mute guarantee:
// muted changes are excluded from digests but stay visible, flagged, in
// History and in signed evidence exports, and the ledger binds the flag.
func TestMutedChangesAreRecordedFlaggedAndSigned(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []struct{ kind, value string }{
		{MuteField, "devices.clientVersion"},
		{MuteTag, "TAG:CI"},
		{MuteResource, "noisy-host"},
		{MuteCollector, "dns"},
	} {
		if _, err := st.AddMuteRule(ctx, rule.kind, rule.value); err != nil {
			t.Fatalf("add %s rule: %v", rule.kind, err)
		}
	}
	device := func(id, name, version string, tags []any, os string) model.Resource {
		return model.Resource{ID: id, Type: "device", Name: name, Data: map[string]any{"hostname": name, "clientVersion": version, "tags": tags, "os": os}}
	}
	fleet := func(version, os string) []model.Collected {
		return []model.Collected{
			{Collector: "devices", Resources: []model.Resource{
				device("d1", "server", version, []any{"tag:prod"}, "linux"),
				device("d2", "runner", "1.0", []any{"tag:ci"}, os),
				device("d3", "noisy-host", "1.0", nil, os),
				device("d4", "mixed", version, nil, os),
			}},
			{Collector: "dns", Resources: []model.Resource{{ID: "dns", Type: "dns", Name: "dns", Data: map[string]any{"magicDNS": os == "linux2"}}}},
		}
	}
	digest := notify.Context{}.Digest
	if _, err := st.ApplyBatchWithBatch(ctx, generation, fleet("1.0", "linux"), digest); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, fleet("1.1", "linux2"), digest)
	if err != nil {
		t.Fatal(err)
	}
	payloads := pendingPayloads(t, st, batch.ID)
	if len(payloads) != 1 {
		t.Fatalf("payloads=%q", payloads)
	}
	payload := payloads[0]
	for _, hidden := range []string{"**server**", "**runner**", "noisy", "**dns**", "clientVersion"} {
		if strings.Contains(payload, hidden) {
			t.Fatalf("muted change or field %q reached the digest:\n%s", hidden, payload)
		}
	}
	if !strings.Contains(payload, "**mixed**") || !strings.Contains(payload, "`os`") || !strings.Contains(payload, "_4 muted change(s) not shown") {
		t.Fatalf("unmuted field or muted count missing:\n%s", payload)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{BatchID: batch.ID})
	if err != nil || len(page.Batches) != 1 {
		t.Fatalf("history=%+v err=%v", page, err)
	}
	muted := map[string]bool{}
	for _, event := range page.Batches[0].Events {
		muted[event.Name] = event.Muted
	}
	if len(muted) != 5 || !muted["server"] || !muted["runner"] || !muted["noisy-host"] || !muted["dns"] || muted["mixed"] {
		t.Fatalf("History muted flags=%v", muted)
	}
	encoded, err := st.ExportEvidencePack(ctx, HistoryFilter{BatchID: batch.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(encoded); err != nil {
		t.Fatalf("evidence pack with muted events does not verify: %v", err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(encoded, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Version != evidencePackVersion {
		t.Fatalf("pack version=%d", pack.Version)
	}
	exported := 0
	for _, event := range pack.Batches[0].Events {
		if event.Muted {
			exported++
		}
		if event.Severity == "" {
			t.Fatalf("event %d has no severity in the export", event.ID)
		}
	}
	if exported != 4 {
		t.Fatalf("evidence export flags %d muted events, want 4", exported)
	}
	// Clearing a muted flag in a re-signed pack must still fail: the flag is
	// bound to the signed ledger payload.
	for index := range pack.Batches[0].Events {
		pack.Batches[0].Events[index].Muted = false
	}
	if err := VerifyEvidencePack(resignEvidencePack(t, st, pack)); err == nil || !strings.Contains(err.Error(), "muted flag mismatch") {
		t.Fatalf("unmuted forgery error=%v", err)
	}
	auditComplete(t, st)
}

// resignEvidencePack recomputes the content hash and signature of a modified
// pack with the instance key, isolating the ledger-binding checks.
func resignEvidencePack(t *testing.T, st *Store, pack EvidencePack) []byte {
	t.Helper()
	content, err := evidencePayload(pack)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	pack.ContentSHA256 = hex.EncodeToString(hash[:])
	pack.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(st.evidenceKey.private, evidenceSignaturePayload(pack)))
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestVersionThreeEvidencePacksStillVerify keeps packs exported before
// evidence format 4 verifiable, and refuses v4-only fields in a v3 pack.
func TestVersionThreeEvidencePacksStillVerify(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"one", "two"} {
		if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource(host, "100.64.0.1")}, notify.TextDigest("digest")); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := st.ExportEvidencePack(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(encoded, &pack); err != nil {
		t.Fatal(err)
	}
	// A version 3 pack is the same content without the v4 event fields,
	// signed with the v3 domain.
	pack.Version = 3
	for batch := range pack.Batches {
		for event := range pack.Batches[batch].Events {
			pack.Batches[batch].Events[event].Severity = ""
		}
	}
	legacy := resignEvidencePack(t, st, pack)
	if err := VerifyEvidencePack(legacy); err != nil {
		t.Fatalf("version 3 pack no longer verifies: %v", err)
	}
	public, _ := st.EvidenceSigningPublicKey(ctx)
	if err := VerifyEvidencePackWithKey(legacy, public); err != nil {
		t.Fatalf("version 3 pack does not verify with the trusted key: %v", err)
	}
	pack.Batches[0].Events[0].Severity = "low"
	if err := VerifyEvidencePack(resignEvidencePack(t, st, pack)); err == nil || !strings.Contains(err.Error(), "cannot carry severity or muted") {
		t.Fatalf("v3 pack with v4 fields error=%v", err)
	}
	// A v4 signature cannot be replayed as a v3 statement.
	var current EvidencePack
	if err := json.Unmarshal(encoded, &current); err != nil {
		t.Fatal(err)
	}
	current.Version = 3
	for batch := range current.Batches {
		for event := range current.Batches[batch].Events {
			current.Batches[batch].Events[event].Severity = ""
		}
	}
	content, _ := evidencePayload(current)
	hash := sha256.Sum256(content)
	current.ContentSHA256 = hex.EncodeToString(hash[:])
	replayed, _ := json.Marshal(current)
	if err := VerifyEvidencePack(replayed); err == nil {
		t.Fatal("a version 4 signature verified as a version 3 pack")
	}
	pack.Version = evidencePackVersion + 1
	if err := VerifyEvidencePack(resignEvidencePack(t, st, pack)); err == nil || !strings.Contains(err.Error(), "unsupported evidence pack") {
		t.Fatalf("future pack version error=%v", err)
	}
}

func TestMuteRuleManagementAndValidation(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	id, err := st.AddMuteRule(ctx, " FIELD ", "Devices.clientVersion")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMuteRule(ctx, "field", "devices.clientVersion"); !errors.Is(err, ErrMuteRuleExists) {
		t.Fatalf("duplicate rule error=%v", err)
	}
	rules, err := st.ListMuteRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Value != "devices.clientVersion" || rules[0].Kind != MuteField || rules[0].CreatedAt.IsZero() {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	for _, invalid := range []struct{ kind, value string }{
		{"field", "clientVersion"},
		{"field", "devices."},
		{"collector", "Bad Name"},
		{"tag", "ci"},
		{"tag", "tag:"},
		{"resource", ""},
		{"resource", "bad\nname"},
		{"resource", strings.Repeat("x", 300)},
		{"owner", "alice"},
	} {
		if _, err := st.AddMuteRule(ctx, invalid.kind, invalid.value); !errors.Is(err, ErrInvalidMuteRule) {
			t.Fatalf("invalid rule %+v error=%v", invalid, err)
		}
	}
	if err := st.DeleteMuteRule(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteMuteRule(ctx, id); err == nil {
		t.Fatal("deleting a missing rule succeeded")
	}
	for index := 0; index < MaxMuteRules; index++ {
		if _, err := st.AddMuteRule(ctx, MuteResource, fmt.Sprintf("host-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.AddMuteRule(ctx, MuteResource, "one-too-many"); !errors.Is(err, ErrInvalidMuteRule) {
		t.Fatalf("rule limit error=%v", err)
	}
}

func TestMuteSetPartialFieldsAndTruncation(t *testing.T) {
	set := newMuteSet([]MuteRule{{Kind: MuteField, Value: "devices.postureIdentity"}, {Kind: MuteTag, Value: "tag:ci"}})
	change := model.Change{Kind: "changed", Collector: "devices", Name: "x", Fields: []model.FieldChange{{Field: "postureIdentity.serialNumbers"}, {Field: "os"}}}
	muted, shown := set.evaluate(change, nil, nil)
	if muted || len(shown.Fields) != 1 || shown.Fields[0].Field != "os" || shown.TotalFields != 1 {
		t.Fatalf("partial mute muted=%v shown=%+v", muted, shown)
	}
	truncated := model.Change{Kind: "changed", Collector: "devices", Fields: []model.FieldChange{{Field: "posture_identity"}}, FieldsTruncated: true, TotalFields: 40}
	if muted, _ := set.evaluate(truncated, nil, nil); muted {
		t.Fatal("a change with unseen truncated fields was muted entirely")
	}
	if muted, _ := set.evaluate(model.Change{Kind: "removed", Collector: "devices"}, []byte(`{"tags":["TAG:CI"]}`), nil); !muted {
		t.Fatal("removed device carrying a muted tag was not muted")
	}
	if muted, _ := set.evaluate(model.Change{Kind: "created", Collector: "devices"}, nil, []byte(`{"tags":"tag:ci"}`)); muted {
		t.Fatal("malformed tags were treated as muted")
	}
	if muted, _ := newMuteSet(nil).evaluate(change, nil, nil); muted {
		t.Fatal("empty rule set muted a change")
	}
}

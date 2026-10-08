package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

// shareInvite is one invite in the shape of Tailscale's DeviceInvite. The
// values are illustrative.
func shareInvite(id, tailnetID string) map[string]any {
	return map[string]any{
		"id":              id,
		"created":         "2026-05-29T18:27:54.581818425Z",
		"tailnetId":       tailnetID,
		"deviceId":        "654495373136127",
		"sharerId":        "u1000EXAMPLE",
		"multiUse":        false,
		"allowExitNode":   false,
		"email":           "",
		"lastEmailSentAt": "2026-05-29T18:27:55Z",
		"inviteUrl":       "https://login.tailscale.com/admin/invite/example-" + id,
		"accepted":        true,
		"acceptedBy": map[string]any{
			"id":            float64(1250252329925020),
			"loginName":     "alice@example.com",
			"profilePicUrl": "https://avatars.example.com/alice.png",
		},
	}
}

func sharedDevice(invites ...map[string]any) []model.Collected {
	list := make([]any, len(invites))
	for index, invite := range invites {
		list[index] = invite
	}
	return []model.Collected{{Collector: "device_details", Resources: []model.Resource{{
		ID: "654495373136127", Type: "device_details", Name: "ludus.tail1234.ts.net", Data: map[string]any{
			"postureAttributes": map[string]any{"attributes": map[string]any{}},
			"deviceInvites":     list,
		},
	}}}}
}

// TestKeyedInvitePathsFlowThroughHistoryEvidenceAndMutes checks R-049's
// acceptance criteria end to end: a stored snapshot re-normalised on
// upgrade records nothing, one invite field change is one event field at
// its element path, History and a verified evidence pack carry that path,
// and a field rule for the list mutes it.
func TestKeyedInvitePathsFlowThroughHistoryEvidenceAndMutes(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	first, second := shareInvite("5861427050514914", "T1000EXAMPLE"), shareInvite("5861427050514999", "T1000EXAMPLE")
	if _, err := testApplyBatch(st, ctx, generation, sharedDevice(first, second), notify.TextDigest("baseline")); err != nil {
		t.Fatal(err)
	}

	// A snapshot stored by an older release (unredacted invite URL, profile
	// picture, different element order) is re-normalised without an event.
	legacy, err := json.Marshal(map[string]any{"deviceInvites": []any{second, first}, "postureAttributes": map[string]any{"attributes": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE snapshots SET canonical_json=?,content_hash='legacy-format' WHERE generation=? AND collector='device_details'", legacy, generation); err != nil {
		t.Fatal(err)
	}
	if changes, err := testApplyBatch(st, ctx, generation, sharedDevice(first, second), notify.TextDigest("upgrade")); err != nil || len(changes) != 0 {
		t.Fatalf("re-normalisation on upgrade recorded %#v (%v)", changes, err)
	}

	changed := shareInvite("5861427050514914", "T2000EXAMPLE")
	batch, err := st.ApplyBatchWithBatch(ctx, generation, sharedDevice(second, changed), notify.Context{}.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Changes) != 1 || len(batch.Changes[0].Fields) != 1 || batch.Changes[0].Fields[0].Field != "deviceInvites[5861427050514914].tailnetId" {
		t.Fatalf("invite field change = %#v", batch.Changes)
	}
	if payloads := pendingPayloads(t, st, batch.ID); len(payloads) != 1 || !strings.Contains(payloads[0], "tailnetId") {
		t.Fatalf("unmuted invite change was not notified: %q", payloads)
	}

	page, err := st.ListHistory(ctx, HistoryFilter{Collector: "device_details", EventType: "changed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 1 || len(page.Batches[0].Events) != 1 || len(page.Batches[0].Events[0].Fields) != 1 || page.Batches[0].Events[0].Fields[0].Field != "deviceInvites[5861427050514914].tailnetId" {
		t.Fatalf("History lost the element path: %#v", page.Batches)
	}

	pack, err := st.ExportEvidencePack(ctx, HistoryFilter{Collector: "device_details"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(pack); err != nil {
		t.Fatalf("evidence pack with element paths did not verify: %v", err)
	}
	if !strings.Contains(string(pack), `"deviceInvites[5861427050514914].tailnetId"`) {
		t.Fatal("evidence pack lost the element path")
	}
	tampered := strings.Replace(string(pack), `"deviceInvites[5861427050514914].tailnetId"`, `"deviceInvites[5861427050514999].tailnetId"`, 1)
	if err := VerifyEvidencePack([]byte(tampered)); err == nil {
		t.Fatal("an evidence pack with a rewritten element path verified")
	}

	if _, err := st.AddMuteRule(ctx, MuteField, "device_details.deviceInvites"); err != nil {
		t.Fatal(err)
	}
	muted, err := st.ApplyBatchWithBatch(ctx, generation, sharedDevice(second, first), notify.Context{}.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(muted.Changes) != 1 || len(pendingPayloads(t, st, muted.ID)) != 0 {
		t.Fatalf("list field rule did not mute the element change: %#v", muted.Changes)
	}
}

// TestShareSeverityAndDigestUseTheSnapshots guards E-038 in the store: the
// recorded severity and the queued digest describe an invite by the
// recipient in the snapshot, which the changed fields do not name.
func TestShareSeverityAndDigestUseTheSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	invite := shareInvite("5861427050514914", "T1000EXAMPLE")
	if _, err := testApplyBatch(st, ctx, generation, sharedDevice(invite), notify.TextDigest("baseline")); err != nil {
		t.Fatal(err)
	}
	bookkeeping, err := st.ApplyBatchWithBatch(ctx, generation, sharedDevice(shareInvite("5861427050514914", "T2000EXAMPLE")), notify.Context{}.Digest)
	if err != nil {
		t.Fatal(err)
	}
	exitNode := shareInvite("5861427050514914", "T2000EXAMPLE")
	exitNode["allowExitNode"] = true
	elevated, err := st.ApplyBatchWithBatch(ctx, generation, sharedDevice(exitNode), notify.Context{}.Digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		batch    int64
		severity string
		line     string
	}{
		{bookkeeping.ID, "low", "share with alice@example.com: `tailnetId` changed"},
		{elevated.ID, "high", "share with alice@example.com: exit node allowed"},
	} {
		page, err := st.ListHistory(ctx, HistoryFilter{BatchID: check.batch})
		if err != nil || len(page.Batches) != 1 || len(page.Batches[0].Events) != 1 {
			t.Fatalf("batch %d history: %+v %v", check.batch, page.Batches, err)
		}
		if got := page.Batches[0].Events[0].Severity; got != check.severity {
			t.Fatalf("batch %d severity = %s, want %s", check.batch, got, check.severity)
		}
		if payloads := pendingPayloads(t, st, check.batch); len(payloads) != 1 || !strings.Contains(payloads[0], check.line) {
			t.Fatalf("batch %d digest lacks %q: %q", check.batch, check.line, payloads)
		}
	}
}

func TestFieldRulesCoverListElements(t *testing.T) {
	set := newMuteSet([]MuteRule{{Kind: MuteField, Value: "device_details.deviceInvites[5861427050514914]"}, {Kind: MuteField, Value: "dns.splitDNS"}})
	cases := map[string]bool{
		"deviceInvites[5861427050514914]":           true,
		"deviceInvites[5861427050514914].tailnetId": true,
		"deviceInvites[5861427050514999].tailnetId": false,
		"deviceInvitesExtra":                        false,
	}
	for field, want := range cases {
		if got := set.fieldMuted("device_details", field); got != want {
			t.Fatalf("fieldMuted(%q) = %v, want %v", field, got, want)
		}
	}
	if !set.fieldMuted("dns", "splitDNS.corp[10.0.0.53].useWithExitNode") {
		t.Fatal("a section rule did not cover an element inside it")
	}
	whole := newMuteSet([]MuteRule{{Kind: MuteField, Value: "device_details.device_invites"}})
	if !whole.fieldMuted("device_details", "deviceInvites[5861427050514914].acceptedBy.id") {
		t.Fatal("a list rule did not cover its element fields")
	}
}

package model

import (
	"reflect"
	"testing"
)

// inviteChange records a device_details change between two invite lists the
// way the store does, with the invites for context.
func inviteChange(t *testing.T, before, after []map[string]any) Change {
	t.Helper()
	oldRaw, newRaw := detailsJSON(t, before...), detailsJSON(t, after...)
	diff := DiffDetailedFor("device_details", oldRaw, newRaw)
	return Change{Kind: "changed", Collector: "device_details", Fields: diff.Fields, FieldsTruncated: diff.FieldsTruncated, TotalFields: diff.TotalFields, Invites: DeviceInvites(oldRaw, newRaw)}
}

func withFields(invite map[string]any, fields ...any) map[string]any {
	out := make(map[string]any, len(invite))
	for key, value := range invite {
		out[key] = value
	}
	for index := 0; index+1 < len(fields); index += 2 {
		out[fields[index].(string)] = fields[index+1]
	}
	return out
}

func TestDeviceShareSeverityTable(t *testing.T) {
	accepted, pending := deviceInvite("5861427050514914", true), deviceInvite("7000000000000001", false)
	acceptor := map[string]any{"id": float64(9), "loginName": "bob@example.com"}
	cases := []struct {
		name          string
		before, after []map[string]any
		want          Severity
	}{
		{"created invite link", nil, []map[string]any{pending}, SeverityMedium},
		{"created multi-use", nil, []map[string]any{withFields(pending, "multiUse", true)}, SeverityHigh},
		{"created with exit node", nil, []map[string]any{withFields(pending, "allowExitNode", true)}, SeverityHigh},
		{"created already accepted", nil, []map[string]any{accepted}, SeverityHigh},
		{"removed", []map[string]any{accepted}, nil, SeverityMedium},
		{"accepted", []map[string]any{pending}, []map[string]any{withFields(pending, "accepted", true, "acceptedBy", acceptor)}, SeverityHigh},
		{"accepted by another user", []map[string]any{accepted}, []map[string]any{withFields(accepted, "acceptedBy", acceptor)}, SeverityHigh},
		{"exit node allowed", []map[string]any{accepted}, []map[string]any{withFields(accepted, "allowExitNode", true)}, SeverityHigh},
		{"exit node revoked", []map[string]any{withFields(accepted, "allowExitNode", true)}, []map[string]any{accepted}, SeverityMedium},
		{"multi-use enabled", []map[string]any{pending}, []map[string]any{withFields(pending, "multiUse", true)}, SeverityMedium},
		{"e-mail resent", []map[string]any{pending}, []map[string]any{withFields(pending, "lastEmailSentAt", "2026-10-01T00:00:00Z")}, SeverityLow},
		{"tailnetId", []map[string]any{accepted}, []map[string]any{withFields(accepted, "tailnetId", "T2000EXAMPLE")}, SeverityLow},
		{"sharerId and deviceId", []map[string]any{accepted}, []map[string]any{withFields(accepted, "sharerId", "u2", "deviceId", "2")}, SeverityLow},
		{"acceptedBy.id", []map[string]any{accepted}, []map[string]any{withFields(accepted, "acceptedBy", map[string]any{"id": float64(7), "loginName": "alice@example.com"})}, SeverityLow},
		{"invite URL of an accepted share", []map[string]any{accepted}, []map[string]any{withFields(accepted, "inviteUrl", "https://login.tailscale.com/admin/invite/example-other")}, SeverityLow},
		{"invite URL of a pending share", []map[string]any{pending}, []map[string]any{withFields(pending, "inviteUrl", "https://login.tailscale.com/admin/invite/example-other")}, SeverityMedium},
		{"invited e-mail", []map[string]any{pending}, []map[string]any{withFields(pending, "email", "carol@example.com")}, SeverityMedium},
		{"unknown field", []map[string]any{pending}, []map[string]any{withFields(pending, "note", "x")}, SeverityMedium},
	}
	for _, tc := range cases {
		change := inviteChange(t, tc.before, tc.after)
		if len(change.Fields) == 0 {
			t.Fatalf("%s: no fields", tc.name)
		}
		if got := Classify(change); got != tc.want {
			t.Fatalf("%s: severity %s, want %s (fields %v)", tc.name, got, tc.want, change.Fields)
		}
	}

	bookkeeping := inviteChange(t, []map[string]any{accepted}, []map[string]any{withFields(accepted, "tailnetId", "T2000EXAMPLE")})
	posture := append(append([]FieldChange{}, bookkeeping.Fields...), FieldChange{Field: "postureAttributes.custom:tier", Old: "a", New: "b", OldPresent: true, NewPresent: true})
	if got := Classify(Change{Kind: "changed", Collector: "device_details", Fields: posture, Invites: bookkeeping.Invites}); got != SeverityMedium {
		t.Fatalf("posture attribute change with bookkeeping = %s", got)
	}
	truncated := bookkeeping
	truncated.FieldsTruncated = true
	if got := Classify(truncated); got != SeverityMedium {
		t.Fatalf("truncated bookkeeping = %s", got)
	}
	for _, change := range []Change{
		{Kind: "changed", Collector: "device_details"},
		{Kind: "created", Collector: "device_details"},
		{Kind: "changed", Collector: "device_details", Fields: []FieldChange{{Field: "deviceInvites", Old: "[{\"accepted\":true…", New: "[]", OldPresent: true, NewPresent: true}}},
	} {
		if got := Classify(change); got != SeverityMedium {
			t.Fatalf("%+v = %s, want medium", change, got)
		}
	}
}

func TestShareTransitionsReadEveryRecordedShape(t *testing.T) {
	accepted := deviceInvite("5861427050514914", true)
	// A whole-list field from an earlier release, and a list that appeared.
	legacy := Change{Kind: "changed", Collector: "device_details", Fields: []FieldChange{
		{Field: "deviceInvites", Old: []any{map[string]any{"id": "1", "tailnetId": "a", "accepted": true, "acceptedBy": map[string]any{"loginName": "alice@example.com"}}}, New: []any{map[string]any{"id": "1", "tailnetId": "b", "accepted": true, "acceptedBy": map[string]any{"loginName": "alice@example.com"}}}, OldPresent: true, NewPresent: true},
		{Field: "postureAttributes.custom:tier", Old: "a", New: "b", OldPresent: true, NewPresent: true},
	}}
	transitions, others := ShareTransitions(legacy)
	if len(transitions) != 1 || transitions[0].Kind != ShareChanged || transitions[0].Invite.Recipient != "alice@example.com" || !reflect.DeepEqual(others, []int{1}) {
		t.Fatalf("legacy whole-list field = %+v, others %v", transitions, others)
	}
	appeared := Change{Kind: "changed", Collector: "device_details", Fields: []FieldChange{{Field: "deviceInvites", New: []any{map[string]any{"id": "2", "email": "carol@example.com"}}, NewPresent: true}}}
	if transitions, _ := ShareTransitions(appeared); len(transitions) != 1 || transitions[0].Kind != ShareCreated || transitions[0].Invite.Recipient != "carol@example.com" {
		t.Fatalf("appeared list = %+v", transitions)
	}

	// Shapes that are not invites stay ordinary fields.
	for _, field := range []FieldChange{
		{Field: "deviceInvites", Old: map[string]any{"unsupported": true}, New: []any{}, OldPresent: true, NewPresent: true},
		{Field: "deviceInvites", Old: "[{\"id\":\"1\"…", New: []any{}, OldPresent: true, NewPresent: true},
		{Field: "deviceInvites", Old: []any{"x"}, New: []any{}, OldPresent: true, NewPresent: true},
		{Field: "deviceInvites.unsupported", Old: true, OldPresent: true},
		{Field: "deviceInvites[]", New: true, NewPresent: true},
		{Field: "deviceInvites[1]x", New: true, NewPresent: true},
		{Field: "deviceInvites[1]", Old: 1, New: 2, OldPresent: true, NewPresent: true},
		{Field: "deviceInvites[1].", New: 2, NewPresent: true},
	} {
		if transitions, others := ShareTransitions(Change{Kind: "changed", Collector: "device_details", Fields: []FieldChange{field}}); len(transitions) != 0 || len(others) != 1 {
			t.Fatalf("%+v was read as a share: %+v", field, transitions)
		}
	}
	if transitions, others := ShareTransitions(Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{{Field: "deviceInvites[1].x"}}}); len(transitions) != 0 || !reflect.DeepEqual(others, []int{0}) {
		t.Fatal("a devices change was read as a share")
	}

	// Without snapshots, the changed fields name the recipient when they can.
	bare := Change{Kind: "changed", Collector: "device_details", Fields: []FieldChange{
		{Field: "deviceInvites[3].accepted", Old: false, New: true, OldPresent: true, NewPresent: true},
		{Field: "deviceInvites[3].acceptedBy.loginName", New: "bob@example.com", NewPresent: true},
		{Field: "deviceInvites[4].tailnetId", Old: "a", New: "b", OldPresent: true, NewPresent: true},
		{Field: "deviceInvites[5]", Old: accepted, OldPresent: true},
	}}
	transitions, _ = ShareTransitions(bare)
	if len(transitions) != 3 || !transitions[0].InviteKnown || transitions[0].Invite.Recipient != "bob@example.com" || !transitions[0].Invite.Accepted || !transitions[0].ShareAccepted() {
		t.Fatalf("bare acceptance = %+v", transitions)
	}
	if transitions[1].InviteKnown || !transitions[1].Bookkeeping() || transitions[2].Kind != ShareRemoved || transitions[2].Invite.Recipient != "alice@example.com" {
		t.Fatalf("bare transitions = %+v", transitions)
	}
	if (ShareTransition{Kind: ShareCreated}).Bookkeeping() || (ShareTransition{Kind: ShareChanged}).Bookkeeping() {
		t.Fatal("a created or empty transition is bookkeeping")
	}
}

func TestDeviceInvitesReadsSnapshots(t *testing.T) {
	before := detailsJSON(t, deviceInvite("1", true), deviceInvite("2", false))
	after := detailsJSON(t, withFields(deviceInvite("1", true), "allowExitNode", true), withFields(deviceInvite("3", false), "email", " carol@example.com "))
	invites := DeviceInvites(before, after)
	want := map[string]DeviceInvite{
		"1": {Recipient: "alice@example.com", Accepted: true, AllowExitNode: true},
		"2": {},
		"3": {Recipient: "carol@example.com"},
	}
	if !reflect.DeepEqual(invites, want) {
		t.Fatalf("invites = %+v", invites)
	}
	if got := DeviceInvites([]byte("not json"), []byte(`{"deviceInvites":{"unsupported":true},"other":[]}`)); len(got) != 0 {
		t.Fatalf("non-invite snapshots = %+v", got)
	}
}

package model

import (
	"strings"
	"testing"
	"time"
)

func auditEntry(login, targetType, targetID, action, property string, at time.Time) AuditEntry {
	return AuditEntry{EventTime: at, Origin: "ADMIN_CONSOLE", ActorType: "USER", ActorLogin: login, ActorName: strings.ToUpper(login), TargetType: targetType, TargetID: targetID, Action: action, Property: property}
}

// TestAttributionCorrelatesAuditTargets correlates mock audit-log fixtures
// for device, policy, key, and user changes by target: the device is matched
// by its node ID from the snapshot, tailnet-wide collectors by the TAILNET
// property, and keys and users by ID. Only an action that fits the change
// kind and changed fields is credited, failed entries never are, the latest
// entry wins, and a change without a matching entry is unattributed.
func TestAttributionCorrelatesAuditTargets(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	device := []byte(`{"id":"101","nodeId":"nDB01","name":"db-01"}`)
	entries := []AuditEntry{
		auditEntry("early", "NODE", "nDB01", "UPDATE", "ACL_TAGS", base.Add(-time.Minute)),
		auditEntry("alice", "NODE", "nDB01", "UPDATE", "ACL_TAGS", base),
		auditEntry("mallory", "NODE", "nDB01", "UPDATE", "ACL_TAGS", base.Add(time.Second)),
		auditEntry("namer", "NODE", "nDB01", "UPDATE", "MACHINE_NAME", base),
		auditEntry("approver", "NODE", "nDB01", "APPROVE", "", base),
		auditEntry("enroller", "NODE", "nNEW", "LOGIN", "", base),
		auditEntry("creator", "NODE", "nNEW", "CREATE", "", base.Add(-time.Second)),
		auditEntry("deleter", "NODE", "nOLD", "DELETE", "", base),
		auditEntry("bob", "TAILNET", "T1", "UPDATE", "ACL", base),
		auditEntry("dns-admin", "TAILNET", "T1", "UPDATE", "DNS_CONFIG", base),
		auditEntry("settings-admin", "TAILNET", "T1", "ENABLE", "HTTPS", base),
		auditEntry("keymaker", "API_KEY", "kKEY1", "CREATE", "", base),
		auditEntry("revoker", "API_KEY", "kKEY2", "REVOKE", "", base),
		auditEntry("hr", "USER", "u42", "UPDATE", "USER_ROLE", base),
		auditEntry("hook", "WEBHOOK_ENDPOINT", "w1", "UPDATE", "SUBSCRIBED_EVENTS", base),
		auditEntry("posture", "TAILNET", "T1", "CREATE", "POSTURE_INTEGRATION", base),
		auditEntry("services", "SERVICE", "svc:web", "UPDATE", "", base),
	}
	entries[2].Failed = true
	for _, tc := range []struct {
		name          string
		change        Change
		before, after []byte
		want          string
	}{
		{"device tags", Change{Kind: "changed", Collector: "devices", ResourceID: "101", Fields: []FieldChange{{Field: "tags"}}}, device, device, "alice"},
		{"device rename", Change{Kind: "changed", Collector: "devices", ResourceID: "101", Fields: []FieldChange{{Field: "name"}}}, device, device, "namer"},
		{"device authorized", Change{Kind: "changed", Collector: "devices", ResourceID: "101", Fields: []FieldChange{{Field: "authorized"}}}, device, device, "approver"},
		{"device self-reported", Change{Kind: "changed", Collector: "devices", ResourceID: "101", Fields: []FieldChange{{Field: "clientVersion"}, {Field: "addresses"}}}, device, device, ""},
		{"device truncated fields", Change{Kind: "changed", Collector: "devices", ResourceID: "101", FieldsTruncated: true}, device, device, "alice"},
		{"device details", Change{Kind: "changed", Collector: "device_details", ResourceID: "101", Fields: []FieldChange{{Field: "postureAttributes.custom:x"}}}, device, device, ""},
		{"device created", Change{Kind: "created", Collector: "devices", ResourceID: "201"}, nil, []byte(`{"nodeId":"nNEW"}`), "creator"},
		{"device removed", Change{Kind: "removed", Collector: "devices", ResourceID: "301"}, []byte(`{"nodeId":"nOLD"}`), nil, "deleter"},
		{"device removed by update", Change{Kind: "removed", Collector: "devices", ResourceID: "101"}, device, nil, ""},
		{"policy", Change{Kind: "changed", Collector: "policy", ResourceID: "policy"}, nil, nil, "bob"},
		{"dns", Change{Kind: "changed", Collector: "dns", ResourceID: "dns"}, nil, nil, "dns-admin"},
		{"settings", Change{Kind: "changed", Collector: "settings", ResourceID: "settings"}, nil, nil, "settings-admin"},
		{"contacts unmatched", Change{Kind: "changed", Collector: "contacts", ResourceID: "contacts"}, nil, nil, ""},
		{"key created", Change{Kind: "created", Collector: "keys", ResourceID: "kKEY1"}, nil, nil, "keymaker"},
		{"key removed", Change{Kind: "removed", Collector: "keys", ResourceID: "kKEY2"}, nil, nil, "revoker"},
		{"key created wrong kind", Change{Kind: "removed", Collector: "keys", ResourceID: "kKEY1"}, nil, nil, ""},
		{"user role", Change{Kind: "changed", Collector: "users", ResourceID: "u42", Fields: []FieldChange{{Field: "role"}}}, nil, nil, "hr"},
		{"user other id", Change{Kind: "changed", Collector: "users", ResourceID: "u43"}, nil, nil, ""},
		{"user wrong target type", Change{Kind: "changed", Collector: "users", ResourceID: "nDB01"}, nil, nil, ""},
		{"webhook", Change{Kind: "changed", Collector: "webhooks", ResourceID: "w1"}, nil, nil, "hook"},
		{"posture integration", Change{Kind: "created", Collector: "posture", ResourceID: "p1"}, nil, nil, "posture"},
		{"service by id", Change{Kind: "changed", Collector: "services", ResourceID: "svc:web"}, nil, nil, "services"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attribution, ok := Attribute(tc.change, tc.before, tc.after, entries, base.Add(time.Minute))
			if got := attribution.ActorLogin; got != tc.want || ok != (tc.want != "") {
				t.Fatalf("attributed to %q (ok=%v), want %q", got, ok, tc.want)
			}
		})
	}
	if _, ok := Attribute(Change{Kind: "changed", Collector: "devices", ResourceID: "101", Fields: []FieldChange{{Field: "tags"}}}, device, device, entries, base.Add(-30*time.Second)); !ok {
		t.Fatal("an entry before the observation bound was not credited")
	}
	if attribution, _ := Attribute(Change{Kind: "changed", Collector: "devices", ResourceID: "101", Fields: []FieldChange{{Field: "tags"}}}, device, device, entries, base.Add(-30*time.Second)); attribution.ActorLogin != "early" {
		t.Fatalf("an entry after the observation bound was credited: %q", attribution.ActorLogin)
	}
}

// TestTailnetFieldChangesMatchOnlyTheirProperty is R-068: a settings or
// DNS field change is credited only to an entry for a property that can
// change that field, not to a later entry for another setting; a field
// without a known property, or a truncated field list, still accepts any of
// the collector's properties.
func TestTailnetFieldChangesMatchOnlyTheirProperty(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	entries := []AuditEntry{
		auditEntry("alice", "TAILNET", "T1", "ENABLE", "HTTPS", base.Add(-time.Minute)),
		auditEntry("bob", "TAILNET", "T1", "DISABLE", "FILE_SHARING", base.Add(-10*time.Second)),
		auditEntry("carol", "TAILNET", "T1", "UPDATE", "DNS_CONFIG", base.Add(-time.Minute)),
		auditEntry("dave", "TAILNET", "T1", "ENABLE", "MAGIC_DNS", base.Add(-10*time.Second)),
	}
	settings := func(fields ...string) Change {
		change := Change{Kind: "changed", Collector: "settings", ResourceID: "settings"}
		for _, field := range fields {
			change.Fields = append(change.Fields, FieldChange{Field: field})
		}
		return change
	}
	dns := settings("nameservers")
	dns.Collector = "dns"
	magic := settings("preferences.magicDNS")
	magic.Collector = "dns"
	override := settings("preferences.overrideLocalDNS")
	override.Collector = "dns"
	truncated := settings("httpsEnabled")
	truncated.FieldsTruncated = true
	for name, tc := range map[string]struct {
		change Change
		want   string
	}{
		"https setting":         {settings("httpsEnabled"), "alice"},
		"unmatched setting":     {settings("usersApprovalOn"), ""},
		"unmapped setting":      {settings("regionalRoutingOn"), "bob"},
		"mapped and unmapped":   {settings("httpsEnabled", "regionalRoutingOn"), "bob"},
		"truncated settings":    {truncated, "bob"},
		"nameservers":           {dns, "carol"},
		"magicDNS":              {magic, "dave"},
		"unmapped dns field":    {override, "dave"},
		"created settings":      {Change{Kind: "created", Collector: "settings", ResourceID: "settings"}, "bob"},
		"settings without list": {settings(), "bob"},
	} {
		attribution, ok := Attribute(tc.change, nil, nil, entries, base)
		if attribution.ActorLogin != tc.want || ok != (tc.want != "") {
			t.Fatalf("%s: attributed to %q (ok=%v), want %q", name, attribution.ActorLogin, ok, tc.want)
		}
	}
}

// TestDeviceSharesMatchInviteAndShareEntries is R-069's attribution part:
// a change to a device's share invites is credited to an Invite or Share
// audit entry (type strings matched loosely) that names the changed invite
// by ID, or the device by name, legacy id, or node ID, and never to a NODE
// entry or an entry for another invite.
func TestDeviceSharesMatchInviteAndShareEntries(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	device := []byte(`{"id":"654495373136127","nodeId":"nLUDUS","name":"ludus.tail1234.ts.net"}`)
	share := func(fields ...string) Change {
		change := Change{Kind: "changed", Collector: "device_details", ResourceID: "654495373136127", Name: "ludus.tail1234.ts.net"}
		for _, field := range fields {
			change.Fields = append(change.Fields, FieldChange{Field: field})
		}
		return change
	}
	invite := func(login, targetType, id, name, action string, at time.Time) AuditEntry {
		entry := auditEntry(login, targetType, id, action, "", at)
		entry.TargetName = name
		return entry
	}
	for name, tc := range map[string]struct {
		change  Change
		entries []AuditEntry
		related [][]byte
		want    string
	}{
		"invite by invite id": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("alice", "INVITE", "5861427050514914", "", "CREATE", base.Add(-time.Minute)),
		}, nil, "alice"},
		"accepted share by invite id": {share("deviceInvites[5861427050514914].accepted", "deviceInvites[5861427050514914].acceptedBy.loginName"), []AuditEntry{
			invite("bob", "NODE_SHARE_INVITE", "5861427050514914", "", "ACCEPT", base.Add(-time.Minute)),
		}, nil, "bob"},
		"share by device name": {share("deviceInvites[5861427050514914].allowExitNode"), []AuditEntry{
			invite("carol", "Share", "s-1", "LUDUS.tail1234.ts.net", "UPDATE", base.Add(-time.Minute)),
		}, nil, "carol"},
		"share by legacy id": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("dave", "SHARE", "654495373136127", "", "DELETE", base.Add(-time.Minute)),
		}, nil, "dave"},
		"share by node id from the device snapshot": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("erin", "SHARE", "nLUDUS", "", "CREATE", base.Add(-time.Minute)),
		}, [][]byte{device}, "erin"},
		"node id without the device snapshot": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("erin", "SHARE", "nLUDUS", "", "CREATE", base.Add(-time.Minute)),
		}, nil, ""},
		"other invite": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("mallory", "INVITE", "7000000000000001", "", "CREATE", base.Add(-time.Minute)),
		}, nil, ""},
		"other device": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("mallory", "SHARE", "s-2", "web-01.tail1234.ts.net", "CREATE", base.Add(-time.Minute)),
		}, [][]byte{device}, ""},
		"node entry for the device": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			auditEntry("mallory", "NODE", "nLUDUS", "UPDATE", "ATTRIBUTES", base.Add(-time.Minute)),
			auditEntry("mallory", "NODE", "654495373136127", "UPDATE", "ACL_TAGS", base.Add(-time.Minute)),
		}, [][]byte{device}, ""},
		"node entry for a truncated share change": {Change{Kind: "changed", Collector: "device_details", ResourceID: "654495373136127", Fields: []FieldChange{{Field: "deviceInvites[5861427050514914].accepted"}}, FieldsTruncated: true}, []AuditEntry{
			auditEntry("mallory", "NODE", "654495373136127", "UPDATE", "ATTRIBUTES", base.Add(-time.Minute)),
		}, nil, ""},
		"share entry for a posture change": {share("postureAttributes.custom:tier"), []AuditEntry{
			invite("mallory", "SHARE", "654495373136127", "", "UPDATE", base.Add(-time.Minute)),
		}, nil, ""},
		"posture change by node id": {share("postureAttributes.custom:tier"), []AuditEntry{
			auditEntry("frank", "NODE", "nLUDUS", "UPDATE", "ATTRIBUTES", base.Add(-time.Minute)),
		}, [][]byte{device}, "frank"},
		"latest share entry": {share("deviceInvites[5861427050514914]"), []AuditEntry{
			invite("early", "INVITE", "5861427050514914", "", "CREATE", base.Add(-2*time.Minute)),
			invite("late", "SHARE", "654495373136127", "", "CREATE", base.Add(-time.Minute)),
			invite("after", "SHARE", "654495373136127", "", "UPDATE", base.Add(time.Minute)),
		}, nil, "late"},
	} {
		attribution, ok := Attribute(tc.change, nil, nil, tc.entries, base, tc.related...)
		if attribution.ActorLogin != tc.want || ok != (tc.want != "") {
			t.Fatalf("%s: attributed to %q (ok=%v), want %q", name, attribution.ActorLogin, ok, tc.want)
		}
	}
}

// TestAttributionRecordIsBoundedAndRedacted keeps only bounded identifying
// fields: control characters are removed, long names are cut, identifiers
// keep only identifier characters, and the record round-trips through its
// stored form.
func TestAttributionRecordIsBoundedAndRedacted(t *testing.T) {
	entry := AuditEntry{
		EventTime:  time.Date(2026, 10, 6, 12, 0, 0, 5, time.FixedZone("x", 3600)),
		Origin:     "CONFIG_API\n<script>",
		ActorType:  "OAUTH_CLIENT",
		ActorLogin: "k123\x00 " + strings.Repeat("a", 400),
		ActorName:  "Bot\tName",
		TargetType: "NODE",
		TargetID:   "nDB01 OR 1=1",
		Action:     "UPDATE",
		Property:   "ACL_TAGS",
		TargetName: "ignored.example.ts.net",
	}
	attribution := NewAttribution(entry)
	if len(attribution.ActorLogin) > maxAttributionLogin || strings.ContainsAny(attribution.ActorLogin, "\x00 ") || !strings.HasPrefix(attribution.ActorLogin, "k123 aaa") {
		t.Fatalf("login=%q", attribution.ActorLogin)
	}
	if attribution.ActorName != "Bot Name" || attribution.Origin != "CONFIG_APIscript" || attribution.Target != "NODE:nDB01OR11" || attribution.Action != "NODE.UPDATE.ACL_TAGS" || attribution.OccurredAt != "2026-10-06T11:00:00.000000005Z" {
		t.Fatalf("attribution=%+v", attribution)
	}
	stored := MarshalAttribution(attribution)
	if strings.Contains(stored, "ignored.example") {
		t.Fatalf("the target name was stored: %s", stored)
	}
	decoded, ok := UnmarshalAttribution(stored)
	if !ok || decoded != attribution {
		t.Fatalf("round trip=%+v ok=%v", decoded, ok)
	}
	for _, raw := range []string{"", "   ", "{", `{}`} {
		if _, ok := UnmarshalAttribution(raw); ok {
			t.Fatalf("UnmarshalAttribution(%q) reported an attribution", raw)
		}
	}
	if MarshalAttribution(Attribution{}) != "" {
		t.Fatal("an empty attribution was stored")
	}
	long := Attribution{Action: strings.Repeat("A", 500), Target: strings.Repeat("T", 500)}.Bounded()
	if len(long.Action) != maxAttributionAction || len(long.Target) != maxAttributionTarget {
		t.Fatalf("bounded lengths action=%d target=%d", len(long.Action), len(long.Target))
	}
	for _, tc := range []struct {
		attribution Attribution
		want        string
	}{
		{Attribution{ActorLogin: "alice@example.com", ActorName: "Alice", ActorType: "USER", Origin: "ADMIN_CONSOLE"}, "alice@example.com (Alice) via admin console"},
		{Attribution{ActorLogin: "alice@example.com", ActorName: "ALICE@example.com", ActorType: "USER"}, "alice@example.com"},
		{Attribution{ActorName: "Alice"}, "Alice"},
		{Attribution{ActorLogin: "k123", ActorType: "OAUTH_CLIENT", Origin: "CONFIG_API"}, "k123 [OAuth client] via API"},
		{Attribution{ActorType: "AUTOMATED_WORKER", Origin: "CONTROL"}, "automation via control plane"},
		{Attribution{ActorType: "SECRET_SCANNER", Origin: "SECURITY_NOTIFICATION"}, "secret scanner via security notification"},
		{Attribution{Action: "NODE.UPDATE"}, ActorUnknown},
	} {
		if got := tc.attribution.Display(); got != tc.want {
			t.Fatalf("Display(%+v)=%q, want %q", tc.attribution, got, tc.want)
		}
	}
	if NewAttribution(AuditEntry{TargetType: "TAILNET"}).Target != "TAILNET" || NewAttribution(AuditEntry{}).OccurredAt != "" {
		t.Fatal("an entry without target ID or time was not represented safely")
	}
}

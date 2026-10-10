package model

import "testing"

func fieldChange(field string, old, new any) FieldChange {
	return FieldChange{Field: field, Old: old, New: new, OldPresent: old != nil, NewPresent: new != nil}
}

// TestSeverityTable is the documented, built-in severity table
// (docs/notifications.md, "Severity and routing"). Every row of the table has a case here.
func TestSeverityTable(t *testing.T) {
	cases := []struct {
		name   string
		change Change
		want   Severity
	}{
		// High.
		{"policy change", Change{Kind: "changed", Collector: "policy"}, SeverityHigh},
		{"log streaming created", Change{Kind: "created", Collector: "log_streaming"}, SeverityHigh},
		{"tailnet settings change", Change{Kind: "changed", Collector: "settings"}, SeverityHigh},
		{"webhook endpoint removed", Change{Kind: "removed", Collector: "webhooks"}, SeverityHigh},
		{"key created", Change{Kind: "created", Collector: "keys"}, SeverityHigh},
		{"oauth app created", Change{Kind: "created", Collector: "oauth_apps"}, SeverityHigh},
		{"oauth app removed", Change{Kind: "removed", Collector: "oauth_apps"}, SeverityHigh},
		{"oauth app scopes changed", Change{Kind: "changed", Collector: "oauth_apps", Fields: []FieldChange{fieldChange("scopes", []any{"devices:core:read"}, []any{"all"})}}, SeverityHigh},
		{"user role change", Change{Kind: "changed", Collector: "users", Fields: []FieldChange{fieldChange("role", "member", "admin")}}, SeverityHigh},
		{"device authorized", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("authorized", false, true)}}, SeverityHigh},
		{"device authorized first seen", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("authorized", nil, true)}}, SeverityHigh},
		{"key expiry disabled", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("keyExpiryDisabled", false, true)}}, SeverityHigh},
		{"device tags", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("clientVersion", "1", "2"), fieldChange("tags", nil, []any{"tag:prod"})}}, SeverityHigh},
		{"admin user created", Change{Kind: "created", Collector: "users", Created: CreatedStateOf("users", []byte(`{"loginName":"a@example.com","role":"admin"}`))}, SeverityHigh},
		{"admin invite created", Change{Kind: "created", Collector: "user_invites", Created: CreatedStateOf("user_invites", []byte(`{"email":"a@example.com","role":"admin"}`))}, SeverityHigh},
		{"tagged device created", Change{Kind: "created", Collector: "devices", Created: CreatedStateOf("devices", []byte(`{"name":"db","tags":["tag:prod"]}`))}, SeverityHigh},
		{"device created with key expiry disabled", Change{Kind: "created", Collector: "devices", Created: CreatedStateOf("devices", []byte(`{"name":"db","keyExpiryDisabled":true}`))}, SeverityHigh},
		// Medium.
		{"device created", Change{Kind: "created", Collector: "devices"}, SeverityMedium},
		{"untagged device created", Change{Kind: "created", Collector: "devices", Created: CreatedStateOf("devices", []byte(`{"name":"db","tags":[],"keyExpiryDisabled":false}`))}, SeverityMedium},
		{"member user created", Change{Kind: "created", Collector: "users", Created: CreatedStateOf("users", []byte(`{"loginName":"a@example.com","role":"Member"}`))}, SeverityMedium},
		{"member invite created", Change{Kind: "created", Collector: "user_invites", Created: CreatedStateOf("user_invites", []byte(`{"email":"a@example.com","role":"member"}`))}, SeverityMedium},
		{"user created without a role", Change{Kind: "created", Collector: "users", Created: CreatedStateOf("users", []byte(`{"loginName":"a@example.com"}`))}, SeverityMedium},
		{"admin user removed", Change{Kind: "removed", Collector: "users", Created: &CreatedState{Role: "admin"}}, SeverityMedium},
		{"device removed", Change{Kind: "removed", Collector: "devices"}, SeverityMedium},
		{"routes enabled", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("enabledRoutes", []any{}, []any{"10.0.0.0/8"})}}, SeverityMedium},
		{"user invite", Change{Kind: "created", Collector: "user_invites"}, SeverityMedium},
		{"device deauthorized", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("authorized", true, false)}}, SeverityMedium},
		{"key expiry re-enabled", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("keyExpiryDisabled", true, false)}}, SeverityMedium},
		{"key removed", Change{Kind: "removed", Collector: "keys"}, SeverityMedium},
		{"user name change", Change{Kind: "changed", Collector: "users", Fields: []FieldChange{fieldChange("displayName", "a", "b")}}, SeverityMedium},
		{"dns change", Change{Kind: "changed", Collector: "dns"}, SeverityMedium},
		{"device change without fields", Change{Kind: "changed", Collector: "devices"}, SeverityMedium},
		{"client upgrade with truncated fields", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("clientVersion", "1", "2")}, FieldsTruncated: true}, SeverityMedium},
		{"client upgrade plus rename", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("clientVersion", "1", "2"), fieldChange("name", "a", "b")}}, SeverityMedium},
		// Low.
		{"client version", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("clientVersion", "1.80.0", "1.82.1")}}, SeverityLow},
		{"update available and os", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("updateAvailable", false, true), fieldChange("os", "linux", "linux2")}}, SeverityLow},
		{"distro detail", Change{Kind: "changed", Collector: "devices", Fields: []FieldChange{fieldChange("distro.version", "12", "13")}}, SeverityLow},
	}
	for _, test := range cases {
		if got := Classify(test.change); got != test.want {
			t.Fatalf("%s: Classify=%q, want %q", test.name, got, test.want)
		}
	}
}

func TestCreatedStateOfReadsOnlyClassifiedCollectors(t *testing.T) {
	if state := CreatedStateOf("keys", []byte(`{"role":"admin"}`)); state != nil {
		t.Fatalf("keys state=%+v, want none", state)
	}
	if state := CreatedStateOf("users", []byte(`not json`)); state != nil {
		t.Fatalf("undecodable state=%+v, want none", state)
	}
	if state := CreatedStateOf("devices", []byte(`null`)); state != nil {
		t.Fatalf("null state=%+v, want none", state)
	}
	state := CreatedStateOf("devices", []byte(`{"tags":"tag:prod","keyExpiryDisabled":"true","role":7}`))
	if state == nil || state.Tagged || state.KeyExpiryDisabled || state.Role != "" {
		t.Fatalf("malformed values state=%+v, want an unprivileged state", state)
	}
	if Classify(Change{Kind: "created", Collector: "user_invites", Created: &CreatedState{Tagged: true}}) != SeverityMedium {
		t.Fatal("a device-only flag raised an invite's severity")
	}
	if Classify(Change{Kind: "created", Collector: "posture", Created: &CreatedState{Role: "admin"}}) != SeverityMedium {
		t.Fatal("an initial state raised the severity of a collector classified on kind alone")
	}
}

func TestSeverityParsingAndOrdering(t *testing.T) {
	for _, value := range []string{"low", " Medium ", "HIGH"} {
		if _, ok := ParseSeverity(value); !ok {
			t.Fatalf("ParseSeverity(%q) failed", value)
		}
	}
	if _, ok := ParseSeverity("critical"); ok {
		t.Fatal("unknown severity accepted")
	}
	if !SeverityHigh.AtLeast(SeverityMedium) || SeverityLow.AtLeast(SeverityMedium) || !Severity("").AtLeast(SeverityLow) {
		t.Fatal("severity ordering is wrong")
	}
	if len(Severities) != 3 || Severities[0] != SeverityLow || Severities[2] != SeverityHigh {
		t.Fatalf("severity list=%v", Severities)
	}
}

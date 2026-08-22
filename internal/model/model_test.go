package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalIgnoresVolatileAndOrder(t *testing.T) {
	a := map[string]any{"addresses": []any{"fd7a::1", "100.64.0.1"}, "lastSeen": "now", "connectedToControl": false, "clientConnectivity": map[string]any{"endpoints": []any{"1.2.3.4:5"}}}
	b := map[string]any{"addresses": []any{"100.64.0.1", "fd7a::1"}, "lastSeen": "later", "connectedToControl": true}
	_, ha, err := Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	_, hb, _ := Canonical(b)
	if ha != hb {
		t.Fatalf("volatile/order differences changed hash: %s != %s", ha, hb)
	}
}

func TestRedactionAndCanonicalizationHandleUnserializableValues(t *testing.T) {
	redacted := redactedValue(func() {})
	if len(redacted) != 1 || redacted["redacted_sha256"] == nil {
		t.Fatalf("unserializable value was not fingerprinted: %#v", redacted)
	}
	if _, _, err := CanonicalFor("", func() {}); err == nil {
		t.Fatal("canonicalization unexpectedly accepted an unserializable value")
	}
}

func TestTenantControlledSecretNamedKeysRemainVisible(t *testing.T) {
	before := map[string]any{
		"group:eng":          []any{"alice@corp"},
		"group:secrets-team": []any{"alice@corp"},
	}
	after := map[string]any{
		"group:eng":          []any{"alice@corp"},
		"group:secrets-team": []any{"alice@corp", "mallory@corp"},
	}
	raw, beforeHash, err := CanonicalFor("policy", before)
	if err != nil {
		t.Fatal(err)
	}
	_, afterHash, err := CanonicalFor("policy", after)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "group:secrets-team") {
		t.Fatalf("tenant-controlled key was removed from policy canonical form: %s", raw)
	}
	if beforeHash == afterHash {
		t.Fatal("membership change in a secret-named policy group was invisible")
	}
	nested := map[string]any{"groups": map[string]any{"secret": []any{"alice@corp"}}}
	if raw, _, err := CanonicalFor("policy", nested); err != nil || !strings.Contains(string(raw), `"secret"`) {
		t.Fatalf("nested tenant key was removed: %s (%v)", raw, err)
	}
}

func TestAllTenantKeyedPolicyAndDNSMapsRetainSecretNamedKeys(t *testing.T) {
	policyCases := []struct {
		section string
		key     string
	}{
		{section: "tagOwners", key: "tag:secrets-team"},
		{section: "hosts", key: "secrets.internal"},
	}
	for _, testCase := range policyCases {
		t.Run("policy/"+testCase.section, func(t *testing.T) {
			before := map[string]any{testCase.section: map[string]any{testCase.key: []any{"alice@corp"}}}
			after := map[string]any{testCase.section: map[string]any{testCase.key: []any{"alice@corp", "mallory@corp"}}}
			raw, beforeHash, err := CanonicalFor("policy", before)
			if err != nil {
				t.Fatal(err)
			}
			_, afterHash, err := CanonicalFor("policy", after)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), testCase.key) || beforeHash == afterHash {
				t.Fatalf("tenant key %q was dropped or its membership change was invisible: %s", testCase.key, raw)
			}
		})
	}

	beforeDNS := map[string]any{"split-dns": map[string]any{"secrets.internal": []any{"100.64.0.1"}}}
	afterDNS := map[string]any{"split-dns": map[string]any{"secrets.internal": []any{"100.64.0.1", "100.64.0.2"}}}
	raw, beforeHash, err := CanonicalFor("dns", beforeDNS)
	if err != nil {
		t.Fatal(err)
	}
	_, afterHash, err := CanonicalFor("dns", afterDNS)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "secrets.internal") || beforeHash == afterHash {
		t.Fatalf("split DNS tenant key was dropped or its value change was invisible: %s", raw)
	}
}

func TestCanonicalForSectionNeverTreatsTenantKeysAsSecretFields(t *testing.T) {
	cases := []struct {
		name      string
		collector string
		section   string
		key       string
		before    any
		after     any
	}{
		{
			name:      "policy groups",
			collector: "policy",
			section:   "groups",
			key:       "secret",
			before:    []any{"alice@corp"},
			after:     []any{"alice@corp", "mallory@corp"},
		},
		{
			name:      "policy tag owners",
			collector: "policy",
			section:   "tagOwners",
			key:       "token",
			before:    []any{"alice@corp"},
			after:     []any{"alice@corp", "mallory@corp"},
		},
		{
			name:      "policy hosts",
			collector: "policy",
			section:   "hosts",
			key:       "password",
			before:    "100.64.0.1",
			after:     "100.64.0.2",
		},
		{
			name:      "dns split dns",
			collector: "dns",
			section:   "split-dns",
			key:       "secret",
			before:    []any{"100.64.0.1"},
			after:     []any{"100.64.0.1", "100.64.0.2"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			before := map[string]any{testCase.key: testCase.before}
			after := map[string]any{testCase.key: testCase.after}
			raw, beforeHash, err := CanonicalForSection(testCase.collector, testCase.section, before)
			if err != nil {
				t.Fatal(err)
			}
			_, afterHash, err := CanonicalForSection(testCase.collector, testCase.section, after)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), `"`+testCase.key+`"`) {
				t.Fatalf("tenant key %q was redacted: %s", testCase.key, raw)
			}
			if beforeHash == afterHash {
				t.Fatalf("change under tenant key %q was invisible", testCase.key)
			}
		})
	}
}

func TestDNSCanonicalizationPreservesResolverOrder(t *testing.T) {
	first := map[string]any{"nameservers": map[string]any{"dns": []any{"1.1.1.1", "9.9.9.9"}}, "searchpaths": map[string]any{"dns": []any{"corp.example", "lab.example"}}}
	second := map[string]any{"nameservers": map[string]any{"dns": []any{"9.9.9.9", "1.1.1.1"}}, "searchpaths": map[string]any{"dns": []any{"lab.example", "corp.example"}}}
	_, firstHash, err := CanonicalFor("dns", first)
	if err != nil {
		t.Fatal(err)
	}
	_, secondHash, err := CanonicalFor("dns", second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("order-significant DNS configuration was normalized as unordered")
	}
}

func TestNestedDNSCanonicalizationPreservesResolverOrder(t *testing.T) {
	first := map[string]any{"split-dns": map[string]any{"corp.example": map[string]any{"nameservers": []any{"1.1.1.1", "9.9.9.9"}, "search_paths": []any{"corp.example", "lab.example"}}}}
	second := map[string]any{"split-dns": map[string]any{"corp.example": map[string]any{"nameservers": []any{"9.9.9.9", "1.1.1.1"}, "search_paths": []any{"lab.example", "corp.example"}}}}
	_, firstHash, err := CanonicalFor("dns", first)
	if err != nil {
		t.Fatal(err)
	}
	_, secondHash, err := CanonicalFor("dns", second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("nested order-significant DNS configuration was normalized as unordered")
	}
}

func TestTailnetAddressChangeDetected(t *testing.T) {
	a, _, _ := Canonical(map[string]any{"addresses": []any{"100.64.0.1"}})
	b, _, _ := Canonical(map[string]any{"addresses": []any{"100.64.0.2"}})
	changes := Diff(a, b)
	if len(changes) != 1 || changes[0].Field != "addresses" {
		t.Fatalf("unexpected changes: %#v", changes)
	}
}
func TestSensitiveURLIsHashed(t *testing.T) {
	raw, _, _ := Canonical(map[string]any{"url": "https://mattermost.example/hooks/super-secret"})
	if strings.Contains(string(raw), "super-secret") {
		t.Fatal("URL leaked into canonical snapshot")
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["url"] == nil {
		t.Fatal("URL fingerprint missing")
	}

	_, firstHash, err := Canonical(map[string]any{"url": "https://mattermost.example/hooks/first"})
	if err != nil {
		t.Fatal(err)
	}
	_, secondHash, err := Canonical(map[string]any{"url": "https://mattermost.example/hooks/second"})
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("configuration URL changes must remain detectable")
	}
}

func TestKnownSecretFieldsAreRedactedWithoutLosingPresence(t *testing.T) {
	before := map[string]any{
		"clientSecret": "first-secret",
		"token":        "first-token",
	}
	after := map[string]any{
		"clientSecret": "rotated-secret",
		"token":        "first-token",
	}
	beforeRaw, beforeHash, err := Canonical(before)
	if err != nil {
		t.Fatal(err)
	}
	afterRaw, afterHash, err := Canonical(after)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{beforeRaw, afterRaw} {
		text := string(raw)
		if strings.Contains(text, "first-secret") || strings.Contains(text, "rotated-secret") || strings.Contains(text, "first-token") {
			t.Fatalf("secret value leaked into canonical snapshot: %s", raw)
		}
		if !strings.Contains(text, "redacted_sha256") {
			t.Fatalf("redacted secret fingerprint missing: %s", raw)
		}
	}
	if beforeHash == afterHash {
		t.Fatal("secret rotation was invisible to drift detection")
	}
	var normalized any
	if err := json.Unmarshal(beforeRaw, &normalized); err != nil {
		t.Fatal(err)
	}
	roundTrip, roundTripHash, err := Canonical(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripHash != beforeHash || string(roundTrip) != string(beforeRaw) {
		t.Fatalf("redacted secret normalization was not idempotent: %s -> %s", beforeRaw, roundTrip)
	}
}

func TestCanonicalURLRedactionIsIdempotent(t *testing.T) {
	value := map[string]any{
		"deviceInvites": []any{
			map[string]any{
				"id":        "invite-1",
				"inviteUrl": "https://login.tailscale.com/admin/invite/super-secret",
			},
		},
	}
	firstRaw, firstHash, err := CanonicalFor("device_details", value)
	if err != nil {
		t.Fatal(err)
	}
	var stored any
	if err := json.Unmarshal(firstRaw, &stored); err != nil {
		t.Fatal(err)
	}
	secondRaw, secondHash, err := CanonicalFor("device_details", stored)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash || string(firstRaw) != string(secondRaw) {
		t.Fatalf("canonical URL fingerprint changed when normalized again:\n%s\n%s", firstRaw, secondRaw)
	}
}

func TestCanonicalIgnoresProfilePictureURL(t *testing.T) {
	before := map[string]any{
		"deviceInvites": []any{
			map[string]any{
				"accepted": true,
				"acceptedBy": map[string]any{
					"id":            float64(123),
					"loginName":     "user@example.com",
					"profilePicUrl": "https://avatars.example.com/old",
				},
			},
		},
	}
	after := map[string]any{
		"deviceInvites": []any{
			map[string]any{
				"accepted": true,
				"acceptedBy": map[string]any{
					"id":            float64(123),
					"loginName":     "user@example.com",
					"profilePicUrl": "https://avatars.example.com/new",
				},
			},
		},
	}

	beforeRaw, beforeHash, err := Canonical(before)
	if err != nil {
		t.Fatal(err)
	}
	afterRaw, afterHash, err := Canonical(after)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != afterHash {
		t.Fatalf("profile picture URL changed canonical hash:\n%s\n%s", beforeRaw, afterRaw)
	}
	if strings.Contains(string(beforeRaw), "profilePicUrl") {
		t.Fatalf("profile picture URL retained in canonical snapshot: %s", beforeRaw)
	}
}

func TestDeviceRuntimeFieldsIgnoredButUpdateAvailabilityAlerted(t *testing.T) {
	before := map[string]any{
		"hostname":            "server",
		"connectedToControl":  false,
		"multipleConnections": false,
		"machineKey":          "machine:old",
		"nodeKey":             "node:old",
		"futureAPIMetadata":   "old",
		"updateAvailable":     false,
	}
	runtimeOnly := map[string]any{
		"hostname":            "server",
		"connectedToControl":  true,
		"multipleConnections": true,
		"machineKey":          "machine:new",
		"nodeKey":             "node:new",
		"futureAPIMetadata":   "new",
		"updateAvailable":     false,
	}
	updateAvailable := map[string]any{
		"hostname":            "server",
		"connectedToControl":  true,
		"multipleConnections": true,
		"machineKey":          "machine:new",
		"nodeKey":             "node:new",
		"futureAPIMetadata":   "newer",
		"updateAvailable":     true,
	}

	_, beforeHash, err := CanonicalFor("devices", before)
	if err != nil {
		t.Fatal(err)
	}
	_, runtimeHash, err := CanonicalFor("devices", runtimeOnly)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != runtimeHash {
		t.Fatal("runtime-only device fields changed the canonical hash")
	}
	beforeRaw, _, _ := CanonicalFor("devices", runtimeOnly)
	updateRaw, updateHash, err := CanonicalFor("devices", updateAvailable)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeHash == updateHash {
		t.Fatal("updateAvailable change was ignored")
	}
	changes := Diff(beforeRaw, updateRaw)
	if len(changes) != 1 || changes[0].Field != "updateAvailable" {
		t.Fatalf("unexpected client update changes: %#v", changes)
	}
}

func TestUserConnectivityStateIsStable(t *testing.T) {
	active := map[string]any{"loginName": "user@example.com", "status": "active", "currentlyConnected": true, "lastSeen": "now"}
	idle := map[string]any{"loginName": "user@example.com", "status": "idle", "currentlyConnected": false, "lastSeen": "later"}
	suspended := map[string]any{"loginName": "user@example.com", "status": "suspended", "currentlyConnected": false}

	_, activeHash, err := CanonicalFor("users", active)
	if err != nil {
		t.Fatal(err)
	}
	_, idleHash, err := CanonicalFor("users", idle)
	if err != nil {
		t.Fatal(err)
	}
	if activeHash != idleHash {
		t.Fatal("active/idle connectivity state changed the user hash")
	}
	_, suspendedHash, err := CanonicalFor("users", suspended)
	if err != nil {
		t.Fatal(err)
	}
	if idleHash == suspendedHash {
		t.Fatal("suspended user status was ignored")
	}
}

func TestOperationalStatusUsesStableHealthState(t *testing.T) {
	before := map[string]any{
		"configuration": map[string]any{
			"status": map[string]any{
				"lastActivity":    "2026-07-23T20:00:00Z",
				"numBytesSent":    float64(100),
				"numEntriesSent":  float64(10),
				"rateEntriesSent": 1.5,
				"lastError":       "",
			},
		},
	}
	after := map[string]any{
		"configuration": map[string]any{
			"status": map[string]any{
				"lastActivity":    "2026-07-23T20:05:00Z",
				"numBytesSent":    float64(200),
				"numEntriesSent":  float64(20),
				"rateEntriesSent": 2.5,
				"lastError":       "",
			},
		},
	}
	failed := map[string]any{
		"configuration": map[string]any{
			"status": map[string]any{
				"lastActivity": "2026-07-23T20:10:00Z",
				"lastError":    "temporary provider error with changing request ID",
			},
		},
	}

	_, beforeHash, err := CanonicalFor("log_streaming", before)
	if err != nil {
		t.Fatal(err)
	}
	_, afterHash, err := CanonicalFor("log_streaming", after)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != afterHash {
		t.Fatal("operational counters changed the log-streaming hash")
	}
	_, failedHash, err := CanonicalFor("log_streaming", failed)
	if err != nil {
		t.Fatal(err)
	}
	if afterHash == failedHash {
		t.Fatal("log-streaming health transition was ignored")
	}

	postureA := map[string]any{"status": map[string]any{"lastSync": "first", "matchedCount": float64(1), "error": ""}}
	postureB := map[string]any{"status": map[string]any{"lastSync": "second", "matchedCount": float64(2), "error": ""}}
	_, postureAHash, _ := CanonicalFor("posture", postureA)
	_, postureBHash, _ := CanonicalFor("posture", postureB)
	if postureAHash != postureBHash {
		t.Fatal("posture synchronization telemetry changed the hash")
	}
}

func TestDeviceDetailsExcludeDuplicatedCoreDevice(t *testing.T) {
	value := map[string]any{
		"detail":  map[string]any{"hostname": "server", "addresses": []any{"100.64.0.1"}},
		"routes":  map[string]any{"enabledRoutes": []any{"10.0.0.0/24"}},
		"invites": []any{},
	}
	raw, _, err := CanonicalFor("device_details", value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "detail") || strings.Contains(string(raw), "hostname") {
		t.Fatalf("duplicated core device retained: %s", raw)
	}
	if !strings.Contains(string(raw), "enabledRoutes") {
		t.Fatalf("secondary device details were removed: %s", raw)
	}
}

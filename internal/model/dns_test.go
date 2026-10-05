package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func canonicalDNS(t *testing.T, raw string) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	out, _, err := CanonicalFor("dns", value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const (
	legacyDNS        = `{"nameservers":{"dns":["8.8.8.8","1.1.1.1"]},"preferences":{"magicDNS":true},"searchpaths":{"searchPaths":["corp.example.com"]},"split-dns":{"corp.example.com":["10.0.0.53","10.0.1.53"],"gone.example.com":null}}`
	configurationDNS = `{"nameservers":[{"address":"8.8.8.8","useWithExitNode":true},{"address":"1.1.1.1"}],"preferences":{"overrideLocalDNS":false,"magicDNS":true},"searchPaths":["corp.example.com"],"splitDNS":{"corp.example.com":[{"address":"10.0.1.53"},{"address":"10.0.0.53","useWithExitNode":true}],"gone.example.com":[]}}`
)

func TestDNSShapeTransitionComparesCommonFields(t *testing.T) {
	legacy, configuration := canonicalDNS(t, legacyDNS), canonicalDNS(t, configurationDNS)
	for _, pair := range [][2][]byte{{legacy, configuration}, {configuration, legacy}} {
		oldCmp, newCmp, transition := ShapeTransition("dns", pair[0], pair[1])
		if !transition || string(oldCmp) != string(newCmp) {
			t.Fatalf("equivalent shapes differ: transition=%v\n%s\n%s", transition, oldCmp, newCmp)
		}
	}
	// Nameserver order is significant and is preserved by the projection.
	reordered := canonicalDNS(t, strings.Replace(configurationDNS, `{"address":"8.8.8.8","useWithExitNode":true},{"address":"1.1.1.1"}`, `{"address":"1.1.1.1"},{"address":"8.8.8.8"}`, 1))
	oldCmp, newCmp, transition := ShapeTransition("dns", legacy, reordered)
	if !transition || string(oldCmp) == string(newCmp) {
		t.Fatal("nameserver reordering across a shape transition was absorbed")
	}
	if diff := Diff(oldCmp, newCmp); len(diff) != 1 || diff[0].Field != "nameservers" {
		t.Fatalf("diff=%#v", diff)
	}
	magicOff := canonicalDNS(t, strings.Replace(configurationDNS, `"magicDNS":true`, `"magicDNS":false`, 1))
	if oldCmp, newCmp, _ := ShapeTransition("dns", legacy, magicOff); string(oldCmp) == string(newCmp) {
		t.Fatal("MagicDNS change across a shape transition was absorbed")
	}
}

func TestDNSShapeTransitionIgnoresUnknownLegacySections(t *testing.T) {
	partial := canonicalDNS(t, `{"nameservers":{"unsupported":true},"preferences":{"unsupported":true},"searchpaths":{"searchPaths":["corp.example.com"]},"split-dns":{"unsupported":true}}`)
	configuration := canonicalDNS(t, configurationDNS)
	oldCmp, newCmp, transition := ShapeTransition("dns", partial, configuration)
	if !transition || string(oldCmp) != string(newCmp) || strings.Contains(string(newCmp), "8.8.8.8") {
		t.Fatalf("unknown legacy sections must be excluded: %s / %s", oldCmp, newCmp)
	}
	oldCmp, newCmp, _ = ShapeTransition("dns", configuration, partial)
	if string(oldCmp) != string(newCmp) {
		t.Fatalf("reverse transition with unknown sections: %s / %s", oldCmp, newCmp)
	}
}

func TestDNSShapeTransitionOnlyAppliesAcrossDNSShapes(t *testing.T) {
	legacy, configuration := canonicalDNS(t, legacyDNS), canonicalDNS(t, configurationDNS)
	for _, test := range []struct {
		name               string
		collector          string
		oldRaw, newRaw     []byte
		expectedTransition bool
	}{
		{"other collector", "settings", legacy, configuration, false},
		{"same legacy shape", "dns", legacy, legacy, false},
		{"same configuration shape", "dns", configuration, configuration, false},
		{"invalid json", "dns", []byte("{"), configuration, false},
		{"array", "dns", []byte("[]"), configuration, false},
		{"unknown shape", "dns", []byte(`{"other":1}`), configuration, false},
		{"empty object", "dns", []byte(`{}`), legacy, false},
		{"legacy via searchpaths only", "dns", []byte(`{"searchpaths":{"searchPaths":[]}}`), []byte(`{"searchPaths":[]}`), true},
		{"legacy via nameservers only", "dns", []byte(`{"nameservers":{"dns":[]}}`), []byte(`{"nameservers":[]}`), true},
		{"configuration via splitDNS only", "dns", []byte(`{"split-dns":{}}`), []byte(`{"splitDNS":{}}`), true},
	} {
		_, _, transition := ShapeTransition(test.collector, test.oldRaw, test.newRaw)
		if transition != test.expectedTransition {
			t.Fatalf("%s: transition=%v", test.name, transition)
		}
	}
	if resolverAddresses([]any{"9.9.9.9", 7, map[string]any{"address": 1}})[0] != "9.9.9.9" {
		t.Fatal("string resolver entries must be accepted")
	}
}

func TestServicesAndOAuthAppsUseFieldAllowlists(t *testing.T) {
	service := map[string]any{"name": "svc:web", "displayName": "Web", "addrs": []any{"fd7a::1", "100.64.0.1"}, "comment": "c", "ports": []any{"tcp:443"}, "tags": []any{"tag:web"}, "unexpected": "dropped"}
	raw, _, err := CanonicalFor("services", service)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unexpected") || !strings.Contains(string(raw), `"addrs":["100.64.0.1","fd7a::1"]`) {
		t.Fatalf("services canonical=%s", raw)
	}
	app := map[string]any{"id": "a1", "name": "app", "clientSecret": "secret-value", "created": "2026-01-01T00:00:00Z", "updated": "2026-01-02T00:00:00Z", "scopes": []any{"b", "a"}}
	raw, _, err = CanonicalFor("oauth_apps", app)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-value") || strings.Contains(string(raw), "2026") || !strings.Contains(string(raw), `"scopes":["a","b"]`) {
		t.Fatalf("oauth_apps canonical=%s", raw)
	}
}

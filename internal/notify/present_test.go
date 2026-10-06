package notify

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

const (
	hashA = "3f9a1c0e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7"
	hashB = "c41b7e2a9d0f3c6b8e1a4d7f0c3b6e9a2d5f8c1b4e7a0d3f6c9b2e5a8d1f4c7b"
	hashC = "9e8d7c6b5a49382716f5e4d3c2b1a0f9e8d7c6b5a49382716f5e4d3c2b1a0f90"
)

func redacted(hash string) map[string]any { return map[string]any{"redacted_sha256": hash} }

func set(field string, old, new any) model.FieldChange {
	return model.FieldChange{Field: field, Old: old, New: new, OldPresent: true, NewPresent: true}
}

// presenterDigest covers every kind of value the presenter distinguishes.
func presenterDigest() Message {
	return Context{Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
		{Kind: "changed", Collector: "policy", Name: "Tailnet policy", Fields: []model.FieldChange{
			set("acls", hashA, hashB),
			{Field: "ssh", New: hashC, NewPresent: true},
			{Field: "tests", Old: hashA, OldPresent: true},
		}},
		{Kind: "changed", Collector: "webhooks", Name: "SIEM webhook", Fields: []model.FieldChange{
			set("endpointUrl", redacted(hashA), redacted(hashB)),
			{Field: "secret", New: redacted(hashC), NewPresent: true},
			{Field: "token", Old: redacted(hashC), OldPresent: true},
		}},
		{Kind: "changed", Collector: "devices", Name: "web-02", Fields: []model.FieldChange{
			set("tags", []any{"tag:old", "tag:prod"}, []any{"tag:db", "tag:prod"}),
			set("enabledRoutes", []string{"10.0.0.0/24"}, []string{"10.0.0.0/24", "10.1.0.0/24"}),
			set("name", "web-02", "web-02b"),
			set("keyExpiryDisabled", false, true),
			set("retries", json.Number("3"), 4.5),
			{Field: "description", Old: "old text", OldPresent: true, New: json.RawMessage("null"), NewPresent: true},
			{Field: "comment", New: "", NewPresent: true},
			set("posture", map[string]any{"fingerprint": hashA, "ok": true}, map[string]any{"ok": false}),
		}},
		{Kind: "changed", Collector: "dns", Name: "DNS configuration", Fields: []model.FieldChange{
			set("searchPaths", []any{"corp.example.com", "example.com"}, []any{"example.com", "corp.example.com"}),
			set("nameservers", []any{map[string]any{"address": "1.1.1.1"}}, []any{map[string]any{"address": "8.8.8.8"}, map[string]any{"address": "1.1.1.1"}}),
			{Field: "splitDNS.corp", New: []any{"10.0.0.53"}, NewPresent: true},
		}},
	}})
}

// TestPresentedValuesAreGolden is E-032's golden test: policy sections,
// redacted secrets, scalars, list differences, ordered DNS lists, and absent
// values in every format.
func TestPresentedValuesAreGolden(t *testing.T) {
	golden := map[string]string{
		FormatMarkdown: "### 🔴 4 Tailscale changes (3 high) · example.com\n" +
			"4 changed · 🔴 3 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ **web\\-02** (device) changed\n" +
			"  - `tags`: +`tag:db`, −`tag:old`\n" +
			"  - `enabledRoutes`: +`10.1.0.0/24`\n" +
			"  - `name`: `web-02` → `web-02b`\n" +
			"  - `keyExpiryDisabled`: `false` → `true`\n" +
			"  - `retries`: `3` → `4.5`\n" +
			"  - `description`: `old text` → (not set)\n" +
			"  - `comment`: (not set) → (empty)\n" +
			"  - `posture`: `{\"fingerprint\":\"3f9a1c0e…\",\"ok\":true}` → `{\"ok\":false}`\n" +
			"🔴 ✏️ **Tailnet policy** changed\n" +
			"  - section `acls` changed (`3f9a1c0e` → `c41b7e2a`)\n" +
			"  - section `ssh` added (`9e8d7c6b`)\n" +
			"  - section `tests` removed\n" +
			"🔴 ✏️ **SIEM webhook** (webhook) changed\n" +
			"  - `endpointUrl`: secret changed (fingerprint `3f9a1c0e` → `c41b7e2a`)\n" +
			"  - `secret`: secret set\n" +
			"  - `token`: secret removed\n" +
			"🟠 ✏️ **DNS configuration** changed\n" +
			"  - `searchPaths`: now `example.com`, `corp.example.com`\n" +
			"  - `nameservers`: now `8.8.8.8`, `1.1.1.1` (+`8.8.8.8`)\n" +
			"  - `splitDNS.corp`: +`10.0.0.53`\n" +
			"\n" +
			"5 Oct 2026 12:00 UTC",
		FormatSlack: "*🔴 4 Tailscale changes (3 high) · example.com*\n" +
			"4 changed · 🔴 3 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ *web-02* (device) changed\n" +
			"    • `tags`: +`tag:db`, −`tag:old`\n" +
			"    • `enabledRoutes`: +`10.1.0.0/24`\n" +
			"    • `name`: `web-02` → `web-02b`\n" +
			"    • `keyExpiryDisabled`: `false` → `true`\n" +
			"    • `retries`: `3` → `4.5`\n" +
			"    • `description`: `old text` → (not set)\n" +
			"    • `comment`: (not set) → (empty)\n" +
			"    • `posture`: `{\"fingerprint\":\"3f9a1c0e…\",\"ok\":true}` → `{\"ok\":false}`\n" +
			"🔴 ✏️ *Tailnet policy* changed\n" +
			"    • section `acls` changed (`3f9a1c0e` → `c41b7e2a`)\n" +
			"    • section `ssh` added (`9e8d7c6b`)\n" +
			"    • section `tests` removed\n" +
			"🔴 ✏️ *SIEM webhook* (webhook) changed\n" +
			"    • `endpointUrl`: secret changed (fingerprint `3f9a1c0e` → `c41b7e2a`)\n" +
			"    • `secret`: secret set\n" +
			"    • `token`: secret removed\n" +
			"🟠 ✏️ *DNS configuration* changed\n" +
			"    • `searchPaths`: now `example.com`, `corp.example.com`\n" +
			"    • `nameservers`: now `8.8.8.8`, `1.1.1.1` (+`8.8.8.8`)\n" +
			"    • `splitDNS.corp`: +`10.0.0.53`\n" +
			"\n" +
			"5 Oct 2026 12:00 UTC",
		FormatPlain: "🔴 4 Tailscale changes (3 high) · example.com\n" +
			"4 changed · 🔴 3 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ web-02 (device) changed\n" +
			"  • tags: +tag:db, −tag:old\n" +
			"  • enabledRoutes: +10.1.0.0/24\n" +
			"  • name: web-02 → web-02b\n" +
			"  • keyExpiryDisabled: false → true\n" +
			"  • retries: 3 → 4.5\n" +
			"  • description: old text → (not set)\n" +
			"  • comment: (not set) → (empty)\n" +
			"  • posture: {\"fingerprint\":\"3f9a1c0e…\",\"ok\":true} → {\"ok\":false}\n" +
			"🔴 ✏️ Tailnet policy changed\n" +
			"  • section acls changed (3f9a1c0e → c41b7e2a)\n" +
			"  • section ssh added (9e8d7c6b)\n" +
			"  • section tests removed\n" +
			"🔴 ✏️ SIEM webhook (webhook) changed\n" +
			"  • endpointUrl: secret changed (fingerprint 3f9a1c0e → c41b7e2a)\n" +
			"  • secret: secret set\n" +
			"  • token: secret removed\n" +
			"🟠 ✏️ DNS configuration changed\n" +
			"  • searchPaths: now example.com, corp.example.com\n" +
			"  • nameservers: now 8.8.8.8, 1.1.1.1 (+8.8.8.8)\n" +
			"  • splitDNS.corp: +10.0.0.53\n" +
			"\n" +
			"5 Oct 2026 12:00 UTC",
	}
	message := presenterDigest()
	for format, want := range golden {
		if got := Render(message, format); got != want {
			t.Fatalf("%s rendering mismatch\n got: %q\nwant: %q", format, got, want)
		}
	}
}

// TestNoFingerprintsInRenderedNotifications is E-032's acceptance criterion
// that no 64-character hash reaches a rendered notification.
func TestNoFingerprintsInRenderedNotifications(t *testing.T) {
	hash := regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	for _, message := range []Message{presenterDigest(), sampleDigest()} {
		for _, format := range Formats {
			if got := Render(message, format); hash.MatchString(got) {
				t.Fatalf("%s rendering contains a hash:\n%s", format, got)
			}
		}
	}
	if strings.Contains(Render(presenterDigest(), FormatPlain), "redacted_sha256") {
		t.Fatal("redacted object rendered as JSON")
	}
}

// TestPresentedValuesStayInert keeps the injection guarantees with unquoted
// values: list elements and scalars stay inside code spans in Markdown, are
// entity-escaped in Slack, and lose control characters everywhere.
func TestPresentedValuesStayInert(t *testing.T) {
	hostile := "x` [click](https://evil.example) <!channel> <https://evil.example|go>\n# heading\r"
	message := Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
		{Kind: "changed", Collector: "devices", Name: "host", Fields: []model.FieldChange{
			set("tags", []any{"tag:a"}, []any{"tag:a", hostile}),
			set("name", "plain", hostile),
		}},
		{Kind: "changed", Collector: "dns", Name: "dns", Fields: []model.FieldChange{
			set("searchPaths", []any{"a"}, []any{hostile, "a"}),
		}},
	}})
	markdown := Render(message, FormatMarkdown)
	for _, current := range strings.Split(markdown, "\n") {
		if strings.Count(current, "`")%2 != 0 || strings.HasPrefix(current, "#") && !strings.HasPrefix(current, "### ") {
			t.Fatalf("markdown line broke out of its code span: %q", current)
		}
	}
	slackText := Render(message, FormatSlack)
	if strings.Contains(slackText, "<!channel>") || strings.Contains(slackText, "<https://evil") {
		t.Fatalf("slack value is active:\n%s", slackText)
	}
	for _, format := range Formats {
		if got := Render(message, format); strings.ContainsAny(got, "\r") || strings.Contains(got, "\n# heading") {
			t.Fatalf("%s value broke a line:\n%s", format, got)
		}
	}
}

// TestPresenterEdgeCases covers the fallbacks and bounds of the presenter.
func TestPresenterEdgeCases(t *testing.T) {
	render := func(collector string, field model.FieldChange) string {
		return Plain(Message{Title: "t", Lines: []Line{item(presentField(collector, field)...)}})
	}
	many := make([]any, 0, 15)
	for i := 0; i < 15; i++ {
		many = append(many, string(rune('a'+i)))
	}
	cases := map[string]struct {
		collector string
		field     model.FieldChange
	}{
		"t\n  • tags: +a, +b, +c, +d, +e, +f, +g, +h, +i, +j, 5 more": {"devices", set("tags", []any{}, many)},
		"t\n  • addresses: [{\"x\":1}] → [{\"x\":2}]":                 {"devices", set("addresses", []any{map[string]any{"x": 1}}, []any{map[string]any{"x": 2}})},
		"t\n  • tags: [\"a\"] → [\"a\"]":                              {"devices", set("tags", []any{"a"}, []any{"a"})},
		"t\n  • nameservers: (not set)":                               {"dns", model.FieldChange{Field: "nameservers", Old: []any{"1.1.1.1"}, OldPresent: true}},
		"t\n  • searchPaths: now (empty) (−a)":                        {"dns", set("searchPaths", []any{"a"}, []any{})},
		"t\n  • nameservers: now 1.1.1.1":                             {"dns", model.FieldChange{Field: "nameservers", New: []any{map[string]any{"address": "1.1.1.1"}}, NewPresent: true}},
		"t\n  • nameservers: [{\"address\":\"1.1.1.1\",\"useWithExitNode\":false}] → [{\"address\":\"1.1.1.1\",\"useWithExitNode\":true}]": {"dns", set("nameservers", []any{map[string]any{"address": "1.1.1.1", "useWithExitNode": false}}, []any{map[string]any{"address": "1.1.1.1", "useWithExitNode": true}})},
		"t\n  • keyId: 3f9a1c0e… → c41b7e2a…":         {"keys", set("keyId", hashA, hashB)},
		"t\n  • acls: plain → c41b7e2a…":              {"policy", set("acls", "plain", hashB)},
		"t\n  • value: (not set) → (not set)":         {"devices", model.FieldChange{Field: "value"}},
		"t\n  • mixed: a → [\"a\"]":                   {"devices", set("mixed", "a", []any{"a"})},
		"t\n  • endpointUrl: secret 3f9a1c0e → plain": {"webhooks", set("endpointUrl", redacted(hashA), "plain")},
	}
	for want, tc := range cases {
		if got := render(tc.collector, tc.field); got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	}
	if got := plainJSON(make(chan int)); got == nil {
		t.Fatal("unencodable value was dropped")
	}
	// A fleet summary uses the same presenter.
	changes := make([]model.Change, 0, 6)
	for i := 0; i < 6; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: string(rune('a' + i)), Name: string(rune('a' + i)), Fields: []model.FieldChange{set("tags", []any{"tag:prod"}, []any{"tag:db", "tag:prod"})}})
	}
	if got := Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes})); !strings.Contains(got, "🔴 📦 6 devices: tags +tag:db\n") {
		t.Fatalf("fleet line:\n%s", got)
	}
}

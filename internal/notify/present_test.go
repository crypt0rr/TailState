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
			"🔴 ✏️ **web-02** (device) changed\n" +
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
		FormatTeams: "**🔴 4 Tailscale changes (3 high) · example.com**\n" +
			"4 changed · 🔴 3 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ **web-02** (device) changed\n" +
			"- tags: +tag:db, −tag:old\n" +
			"- enabledRoutes: +10.1.0.0/24\n" +
			"- name: web-02 → web-02b\n" +
			"- keyExpiryDisabled: false → true\n" +
			"- retries: 3 → 4.5\n" +
			"- description: old text → (not set)\n" +
			"- comment: (not set) → (empty)\n" +
			"- posture: {\"fingerprint\":\"3f9a1c0e…\",\"ok\":true} → {\"ok\":false}\n" +
			"🔴 ✏️ **Tailnet policy** changed\n" +
			"- section acls changed (3f9a1c0e → c41b7e2a)\n" +
			"- section ssh added (9e8d7c6b)\n" +
			"- section tests removed\n" +
			"🔴 ✏️ **SIEM webhook** (webhook) changed\n" +
			"- endpointUrl: secret changed (fingerprint 3f9a1c0e → c41b7e2a)\n" +
			"- secret: secret set\n" +
			"- token: secret removed\n" +
			"🟠 ✏️ **DNS configuration** changed\n" +
			"- searchPaths: now example.com, corp.example.com\n" +
			"- nameservers: now 8.8.8.8, 1.1.1.1 (+8.8.8.8)\n" +
			"- splitDNS.corp: +10.0.0.53\n" +
			"\n" +
			"5 Oct 2026 12:00 UTC",
		FormatHTML: "<b>🔴 4 Tailscale changes (3 high) · example.com</b>\n" +
			"4 changed · 🔴 3 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ <b>web-02</b> (device) changed\n" +
			"  • <code>tags</code>: +<code>tag:db</code>, −<code>tag:old</code>\n" +
			"  • <code>enabledRoutes</code>: +<code>10.1.0.0/24</code>\n" +
			"  • <code>name</code>: <code>web-02</code> → <code>web-02b</code>\n" +
			"  • <code>keyExpiryDisabled</code>: <code>false</code> → <code>true</code>\n" +
			"  • <code>retries</code>: <code>3</code> → <code>4.5</code>\n" +
			"  • <code>description</code>: <code>old text</code> → (not set)\n" +
			"  • <code>comment</code>: (not set) → (empty)\n" +
			"  • <code>posture</code>: <code>{&#34;fingerprint&#34;:&#34;3f9a1c0e…&#34;,&#34;ok&#34;:true}</code> → <code>{&#34;ok&#34;:false}</code>\n" +
			"🔴 ✏️ <b>Tailnet policy</b> changed\n" +
			"  • section <code>acls</code> changed (<code>3f9a1c0e</code> → <code>c41b7e2a</code>)\n" +
			"  • section <code>ssh</code> added (<code>9e8d7c6b</code>)\n" +
			"  • section <code>tests</code> removed\n" +
			"🔴 ✏️ <b>SIEM webhook</b> (webhook) changed\n" +
			"  • <code>endpointUrl</code>: secret changed (fingerprint <code>3f9a1c0e</code> → <code>c41b7e2a</code>)\n" +
			"  • <code>secret</code>: secret set\n" +
			"  • <code>token</code>: secret removed\n" +
			"🟠 ✏️ <b>DNS configuration</b> changed\n" +
			"  • <code>searchPaths</code>: now <code>example.com</code>, <code>corp.example.com</code>\n" +
			"  • <code>nameservers</code>: now <code>8.8.8.8</code>, <code>1.1.1.1</code> (+<code>8.8.8.8</code>)\n" +
			"  • <code>splitDNS.corp</code>: +<code>10.0.0.53</code>\n" +
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

	// R-064: bare URLs and broadcast mentions in values, in every span a
	// value reaches, are broken up by a word joiner in every renderer, while
	// TailState's own links still render.
	inert := []string{"https://evil.example", "www.evil.example", "WWW.evil.example", "@channel", "@all", "@here", "@room", "@everyone", "@Channel"}
	value := strings.Join(inert, " ")
	// E-mail addresses whose domain starts like a mention keyword stay
	// exactly as written, so they can still be copied.
	for _, address := range []string{"bob@allcorp.example", "carol@hereford.example", "dave@room.example", "x.y@channel.example"} {
		if got := neutralize(address); got != address {
			t.Fatalf("address %q became %q", address, got)
		}
	}
	if got := neutralize("(@here) ping"); !strings.Contains(got, "@"+wordJoiner+"here") {
		t.Fatalf("mention after punctuation stays active: %q", got)
	}
	tenant := Context{Label: value, Tailnet: "example.com", PublicURL: "https://tailstate.example"}
	messages := []Message{
		tenant.Digest(DigestInput{BatchID: 7, ObservedAt: testObservedAt, Attributed: true, Changes: []model.Change{
			{Kind: "changed", Collector: "devices", Name: value, Attribution: &model.Attribution{ActorLogin: value, ActorName: value}, Fields: []model.FieldChange{
				set("tags", []any{"tag:a"}, []any{"tag:a", value}),
				set("name", "plain", value),
			}},
			{Kind: "created", Collector: "keys", Name: value},
		}}),
		tenant.CollectorsUnhealthy([]CollectorHealth{{Collector: value, Reason: value}}, testObservedAt),
		tenant.ExpiryWarning(3, []ExpiryLine{{Kind: value, Name: value, Tags: []string{value}, Expires: testObservedAt}}, testObservedAt),
		tenant.Test(testObservedAt),
		{Title: "t", Lines: []Line{line(link(value, "javascript:x"))}},
	}
	links := map[string]string{
		FormatMarkdown: "](https://tailstate.example/history?batch=7)",
		FormatSlack:    "<https://tailstate.example/history?batch=7|",
		FormatPlain:    ": https://tailstate.example/history?batch=7",
		FormatTeams:    "](https://tailstate.example/history?batch=7)",
		FormatHTML:     `<a href="https://tailstate.example/history?batch=7">`,
	}
	for _, format := range Formats {
		for index, message := range messages {
			got := Render(message, format)
			for _, active := range inert {
				if strings.Contains(strings.ToLower(got), strings.ToLower(active)) {
					t.Fatalf("%s message %d keeps %q contiguous:\n%s", format, index, active, got)
				}
			}
			if !strings.Contains(got, wordJoiner) {
				t.Fatalf("%s message %d has no neutralised value:\n%s", format, index, got)
			}
		}
		if got := Render(messages[0], format); !strings.Contains(got, links[format]) {
			t.Fatalf("%s lost the History link:\n%s", format, got)
		}
		title := plainTitle(messages[3])
		if strings.Contains(title, "@here") || strings.Contains(title, "https://") {
			t.Fatalf("title parameter keeps a value active: %q", title)
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

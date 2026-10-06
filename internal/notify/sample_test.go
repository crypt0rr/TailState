package notify

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// sampleContext and sampleDigest reproduce the notification assessment's
// sample batch: 19 changes with attribution and mutes, a 12-device client
// rollout, and policy, secret, tag, role, key, device, and DNS changes.
var sampleContext = Context{Label: "prod", Tailnet: "example.com", PublicURL: "https://tailstate.example"}

func sampleDigest() Message {
	alice := &model.Attribution{ActorLogin: "alice@example.com", ActorType: "USER", Action: "update", Target: "policy"}
	ci := &model.Attribution{ActorLogin: "ci-bot", ActorType: "API_KEY", Action: "update", Target: "devices"}
	changes := []model.Change{
		{Kind: "created", Collector: "devices", ResourceID: "n1", Name: "laptop-new.tail1234.ts.net"},
		{Kind: "changed", Collector: "dns", ResourceID: "dns", Name: "DNS configuration", Fields: []model.FieldChange{
			{Field: "searchPaths", Old: []any{"corp.example.com", "example.com"}, New: []any{"example.com", "corp.example.com"}, OldPresent: true, NewPresent: true},
		}},
		{Kind: "changed", Collector: "policy", ResourceID: "policy", Name: "Tailnet policy", Attribution: alice, Fields: []model.FieldChange{
			{Field: "acls", Old: "3f9a1c0e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7", New: "c41b7e2a9d0f3c6b8e1a4d7f0c3b6e9a2d5f8c1b4e7a0d3f6c9b2e5a8d1f4c7b", OldPresent: true, NewPresent: true},
			{Field: "ssh", New: "9e8d7c6b5a49382716f5e4d3c2b1a0f9e8d7c6b5a49382716f5e4d3c2b1a0f90", NewPresent: true},
		}},
		{Kind: "changed", Collector: "users", ResourceID: "u2", Name: "bob@example.com", Attribution: alice, Fields: []model.FieldChange{
			{Field: "role", Old: "member", New: "admin", OldPresent: true, NewPresent: true},
		}},
		{Kind: "changed", Collector: "devices", ResourceID: "w2", Name: "web-02.tail1234.ts.net", Attribution: ci, Fields: []model.FieldChange{
			{Field: "tags", Old: []any{"tag:prod"}, New: []any{"tag:db", "tag:prod"}, OldPresent: true, NewPresent: true},
		}},
		{Kind: "changed", Collector: "webhooks", ResourceID: "wh1", Name: "SIEM webhook", Fields: []model.FieldChange{
			{Field: "endpointUrl", Old: map[string]any{"redacted_sha256": "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899"}, New: map[string]any{"redacted_sha256": "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"}, OldPresent: true, NewPresent: true},
		}},
		{Kind: "created", Collector: "keys", ResourceID: "k9", Name: "kAbc123CNTRL", Attribution: alice},
	}
	for i := 1; i <= 12; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("node-%02d.tail1234.ts.net", i), Fields: []model.FieldChange{
			{Field: "clientVersion", Old: "1.80.2", New: "1.82.1", OldPresent: true, NewPresent: true},
		}})
	}
	return sampleContext.Digest(DigestInput{BatchID: 1842, ObservedAt: testObservedAt, Changes: changes, MutedCount: 3, Attributed: true})
}

// Rendered sizes of the sample digest before the compact layout: in v0.15.0,
// the notification assessment's baseline, and with readable values (#230)
// but the earlier layout. Teams then received Markdown and Telegram plain
// text; Telegram's HTML adds tags to the same visible text, so it is only
// compared with v0.15.0.
var sampleBaselineBytes = []map[string]int{
	{FormatMarkdown: 1786, FormatSlack: 1794, FormatPlain: 1674, FormatTeams: 1786, FormatHTML: 1674},
	{FormatMarkdown: 1425, FormatSlack: 1433, FormatPlain: 1317, FormatTeams: 1425},
}

// TestAssessmentSampleIsGolden pins the assessment's sample digest in every
// format: the counts and top severity in the title, high-severity changes
// first, compact change lines with their known actors, one merged fleet
// line, readable values without hashes, no duplicate lines, and one closing
// context line. The compact layout (E-036) and naming only known actors
// (E-033) keep every change, actor, and field while the rendering is at
// least 25% smaller than before.
func TestAssessmentSampleIsGolden(t *testing.T) {
	golden := map[string]string{
		FormatMarkdown: "### 🔴 19 Tailscale changes (5 high) · prod (example.com)\n" +
			"2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low\n" +
			"Attributed: 4 of 19 changes\n" +
			"\n" +
			"🔴 ✏️ **web-02** (device) changed by ci-bot \\[api key\\]\n" +
			"  - `tags`: +`tag:db`\n" +
			"🔴 ➕ **kAbc123CNTRL** (key) created by alice@example.com\n" +
			"🔴 ✏️ **Tailnet policy** changed by alice@example.com\n" +
			"  - section `acls` changed (`3f9a1c0e` → `c41b7e2a`)\n" +
			"  - section `ssh` added (`9e8d7c6b`)\n" +
			"🔴 ✏️ **bob@example.com** (user) changed by alice@example.com\n" +
			"  - `role`: `member` → `admin`\n" +
			"🔴 ✏️ **SIEM webhook** (webhook) changed\n" +
			"  - `endpointUrl`: secret changed (fingerprint `aa11bb22` → `99887766`)\n" +
			"🟠 ➕ **laptop-new** (device) created\n" +
			"🟠 ✏️ **DNS configuration** changed\n" +
			"  - `searchPaths`: now `example.com`, `corp.example.com`\n" +
			"⚪ 📦 12 devices: `clientVersion` `1.80.2` → `1.82.1`\n" +
			"\n" +
			"3 muted changes not shown · 5 Oct 2026 12:00 UTC · [Batch 1842 in History](https://tailstate.example/history?batch=1842)",
		FormatSlack: "*🔴 19 Tailscale changes (5 high) · prod (example.com)*\n" +
			"2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low\n" +
			"Attributed: 4 of 19 changes\n" +
			"\n" +
			"🔴 ✏️ *web-02* (device) changed by ci-bot [api key]\n" +
			"    • `tags`: +`tag:db`\n" +
			"🔴 ➕ *kAbc123CNTRL* (key) created by alice@example.com\n" +
			"🔴 ✏️ *Tailnet policy* changed by alice@example.com\n" +
			"    • section `acls` changed (`3f9a1c0e` → `c41b7e2a`)\n" +
			"    • section `ssh` added (`9e8d7c6b`)\n" +
			"🔴 ✏️ *bob@example.com* (user) changed by alice@example.com\n" +
			"    • `role`: `member` → `admin`\n" +
			"🔴 ✏️ *SIEM webhook* (webhook) changed\n" +
			"    • `endpointUrl`: secret changed (fingerprint `aa11bb22` → `99887766`)\n" +
			"🟠 ➕ *laptop-new* (device) created\n" +
			"🟠 ✏️ *DNS configuration* changed\n" +
			"    • `searchPaths`: now `example.com`, `corp.example.com`\n" +
			"⚪ 📦 12 devices: `clientVersion` `1.80.2` → `1.82.1`\n" +
			"\n" +
			"3 muted changes not shown · 5 Oct 2026 12:00 UTC · <https://tailstate.example/history?batch=1842|Batch 1842 in History>",
		FormatPlain: "🔴 19 Tailscale changes (5 high) · prod (example.com)\n" +
			"2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low\n" +
			"Attributed: 4 of 19 changes\n" +
			"\n" +
			"🔴 ✏️ web-02 (device) changed by ci-bot [api key]\n" +
			"  • tags: +tag:db\n" +
			"🔴 ➕ kAbc123CNTRL (key) created by alice@example.com\n" +
			"🔴 ✏️ Tailnet policy changed by alice@example.com\n" +
			"  • section acls changed (3f9a1c0e → c41b7e2a)\n" +
			"  • section ssh added (9e8d7c6b)\n" +
			"🔴 ✏️ bob@example.com (user) changed by alice@example.com\n" +
			"  • role: member → admin\n" +
			"🔴 ✏️ SIEM webhook (webhook) changed\n" +
			"  • endpointUrl: secret changed (fingerprint aa11bb22 → 99887766)\n" +
			"🟠 ➕ laptop-new (device) created\n" +
			"🟠 ✏️ DNS configuration changed\n" +
			"  • searchPaths: now example.com, corp.example.com\n" +
			"⚪ 📦 12 devices: clientVersion 1.80.2 → 1.82.1\n" +
			"\n" +
			"3 muted changes not shown · 5 Oct 2026 12:00 UTC · Batch 1842 in History: https://tailstate.example/history?batch=1842",
		FormatTeams: "**🔴 19 Tailscale changes (5 high) · prod (example.com)**\n" +
			"2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low\n" +
			"Attributed: 4 of 19 changes\n" +
			"\n" +
			"🔴 ✏️ **web-02** (device) changed by ci-bot [api key]\n" +
			"- tags: +tag:db\n" +
			"🔴 ➕ **kAbc123CNTRL** (key) created by alice@example.com\n" +
			"🔴 ✏️ **Tailnet policy** changed by alice@example.com\n" +
			"- section acls changed (3f9a1c0e → c41b7e2a)\n" +
			"- section ssh added (9e8d7c6b)\n" +
			"🔴 ✏️ **bob@example.com** (user) changed by alice@example.com\n" +
			"- role: member → admin\n" +
			"🔴 ✏️ **SIEM webhook** (webhook) changed\n" +
			"- endpointUrl: secret changed (fingerprint aa11bb22 → 99887766)\n" +
			"🟠 ➕ **laptop-new** (device) created\n" +
			"🟠 ✏️ **DNS configuration** changed\n" +
			"- searchPaths: now example.com, corp.example.com\n" +
			"⚪ 📦 12 devices: clientVersion 1.80.2 → 1.82.1\n" +
			"\n" +
			"3 muted changes not shown · 5 Oct 2026 12:00 UTC · [Batch 1842 in History](https://tailstate.example/history?batch=1842)",
		FormatHTML: "<b>🔴 19 Tailscale changes (5 high) · prod (example.com)</b>\n" +
			"2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low\n" +
			"Attributed: 4 of 19 changes\n" +
			"\n" +
			"🔴 ✏️ <b>web-02</b> (device) changed by ci-bot [api key]\n" +
			"  • <code>tags</code>: +<code>tag:db</code>\n" +
			"🔴 ➕ <b>kAbc123CNTRL</b> (key) created by alice@example.com\n" +
			"🔴 ✏️ <b>Tailnet policy</b> changed by alice@example.com\n" +
			"  • section <code>acls</code> changed (<code>3f9a1c0e</code> → <code>c41b7e2a</code>)\n" +
			"  • section <code>ssh</code> added (<code>9e8d7c6b</code>)\n" +
			"🔴 ✏️ <b>bob@example.com</b> (user) changed by alice@example.com\n" +
			"  • <code>role</code>: <code>member</code> → <code>admin</code>\n" +
			"🔴 ✏️ <b>SIEM webhook</b> (webhook) changed\n" +
			"  • <code>endpointUrl</code>: secret changed (fingerprint <code>aa11bb22</code> → <code>99887766</code>)\n" +
			"🟠 ➕ <b>laptop-new</b> (device) created\n" +
			"🟠 ✏️ <b>DNS configuration</b> changed\n" +
			"  • <code>searchPaths</code>: now <code>example.com</code>, <code>corp.example.com</code>\n" +
			"⚪ 📦 12 devices: <code>clientVersion</code> <code>1.80.2</code> → <code>1.82.1</code>\n" +
			"\n" +
			"3 muted changes not shown · 5 Oct 2026 12:00 UTC · <a href=\"https://tailstate.example/history?batch=1842\">Batch 1842 in History</a>",
	}
	message := sampleDigest()
	hash := regexp.MustCompile(`[0-9a-f]{32,}`)
	for format, want := range golden {
		got := Render(message, format)
		if got != want {
			t.Fatalf("%s rendering mismatch\n got: %q\nwant: %q", format, got, want)
		}
		seen := map[string]bool{}
		for _, current := range strings.Split(got, "\n")[1:] {
			if severityOfLine(current) >= 0 && seen[current] {
				t.Fatalf("%s: duplicate line %q", format, current)
			}
			seen[current] = true
		}
		if hash.MatchString(got) {
			t.Fatalf("%s: hash in rendering", format)
		}
		assertSeverityOrder(t, format, got)
		for _, baselines := range sampleBaselineBytes {
			if baseline, ok := baselines[format]; ok && len(got)*4 > baseline*3 {
				t.Fatalf("%s: %d bytes is not at least 25%% smaller than %d", format, len(got), baseline)
			}
		}
		// No information is lost: every change, actor, field, the muted
		// count, the time, and the History link are still present.
		for _, text := range []string{"web-02", "kAbc123CNTRL", "Tailnet policy", "bob@example.com", "SIEM webhook", "laptop-new", "DNS configuration", "12 devices", "ci-bot", "alice@example.com", "tags", "acls", "ssh", "role", "endpointUrl", "searchPaths", "clientVersion", "3 muted changes", "5 Oct 2026 12:00 UTC", "history?batch=1842"} {
			if !strings.Contains(strings.ReplaceAll(got, "\\", ""), text) {
				t.Fatalf("%s: %q was lost", format, text)
			}
		}
	}
}

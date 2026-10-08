package notify

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestOrdinaryNamesRenderWithoutBackslashes is R-048's first acceptance
// criterion: hyphens, dots, parentheses, and e-mail addresses only have
// Markdown meaning at the start of a line, so ordinary names, labels, and
// actors are rendered without backslashes.
func TestOrdinaryNamesRenderWithoutBackslashes(t *testing.T) {
	context := Context{Label: "prod-monitor", Tailnet: "example.com"}
	changes := []model.Change{
		{Kind: "created", Collector: "keys", Name: "ci-runner auth key", Attribution: &model.Attribution{ActorLogin: "alice.admin@example.com", ActorName: "Alice (Ops)", Origin: "ADMIN_CONSOLE"}},
		{Kind: "created", Collector: "keys", Name: "db-01.tail1234.ts.net"},
		{Kind: "changed", Collector: "users", Name: "first.last+tag@example.com", Fields: []model.FieldChange{set("role", "member", "admin")}},
		{Kind: "removed", Collector: "devices", Name: "host #1 (eu-west) > backup!"},
	}
	got := Markdown(context.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes, Attributed: true}))
	if strings.Contains(got, "\\") {
		t.Fatalf("ordinary names gained backslashes:\n%s", got)
	}
	for _, want := range []string{
		"### 🔴 4 Tailscale changes (3 high) · prod-monitor (example.com)\n",
		"**ci-runner auth key** (key) created by alice.admin@example.com (Alice (Ops)) via admin console\n",
		"**db-01.tail1234.ts.net** (key) created\n",
		"**first.last+tag@example.com** (user) changed\n",
		"**host #1 (eu-west) > backup!** (device) removed\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("digest is missing %q:\n%s", want, got)
		}
	}
}

// TestMarkdownInjectionInValuesStaysInert is R-048's second acceptance
// criterion: with minimal escaping, images, links, emphasis, HTML, autolinks,
// code, strike-through, and table syntax inside values are still inert in
// every inline position (titles, bold names, prose, and link labels).
func TestMarkdownInjectionInValuesStaysInert(t *testing.T) {
	cases := map[string]string{
		"![x](https://evil.example/i.png)":  `!\[x\](https://evil.example/i.png)`,
		"[x](https://evil.example)":         `\[x\](https://evil.example)`,
		"*bold* and **strong**":             `\*bold\* and \*\*strong\*\*`,
		"_it_ and __under__":                `\_it\_ and \_\_under\_\_`,
		"<script>alert(1)</script>":         `\<script>alert(1)\</script>`,
		"<https://evil.example>":            `\<https://evil.example>`,
		"`code` and ~~strike~~ ||spoiler||": "\\`code\\` and \\~\\~strike\\~\\~ \\|\\|spoiler\\|\\|",
		"trailing backslash \\":             `trailing backslash \\`,
	}
	for value, want := range cases {
		message := Context{Label: value, Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
			{Kind: "created", Collector: "keys", Name: value, Attribution: &model.Attribution{ActorLogin: value}},
		}, Attributed: true})
		message.Lines = append(message.Lines, line(link(value, "https://tailstate.example/history")))
		got := Markdown(message)
		title, _, _ := strings.Cut(got, "\n")
		for position, text := range map[string]string{
			"title": title,
			"bold":  "**" + want + "** (key) created",
			"prose": "created by " + want + "\n",
			"link":  "[" + want + "](https://tailstate.example/history)",
		} {
			if !strings.Contains(got, text) || (position == "title" && !strings.HasSuffix(title, " · "+want+" (example.com)")) {
				t.Fatalf("%q in the %s is not escaped as %q:\n%s", value, position, want, got)
			}
		}
	}
	// A value cut at the length bound never ends in half an escape.
	long := Markdown(Message{Title: "t", Lines: []Line{line(bold(strings.Repeat("a", 255) + "**"))}})
	if !strings.HasSuffix(long, "a…**") {
		t.Fatalf("bounded value=%q", long[len(long)-12:])
	}
}

// tenantMarker starts every generated tenant value, so a rendered line that
// starts with tenant-controlled text is recognisable.
const tenantMarker = "⁂"

// tenantSyntax is the alphabet of generated tenant values: block and inline
// syntax of every rendering format, line breaks, and control characters.
var tenantSyntax = []string{
	"#", "## ", ">", "- ", "+ ", "* ", "_", "1. ", "=", "|", "~", "`", "```", "<", "[", "]", "(", ")",
	"!", "\\", "&", ";", "@", ":", "/", " ", "    ", "a", "B", "é", "\n", "\r", "\t", "\u2028", "\u2029",
	"\x00", "\x1b", "<!channel>", "<b>", "</b>", "&amp;", "\"", "'", "<a href=\"x\">", "*bold*",
	"[x](https://evil.example)", "\n# heading", "\n- item", "\n> quote",
}

func tenantValue(r *rand.Rand) string {
	var b strings.Builder
	b.WriteString(tenantMarker)
	for range 1 + r.IntN(12) {
		b.WriteString(tenantSyntax[r.IntN(len(tenantSyntax))])
	}
	return b.String()
}

// tenantMessages builds every notification type with generated tenant
// values in every position a tenant (or operator) controls.
func tenantMessages(r *rand.Rand) []Message {
	value := func() string { return tenantValue(r) }
	context := Context{Label: value(), Tailnet: value(), PublicURL: "https://tailstate.example", Version: value()}
	var changes []model.Change
	for index, collector := range []string{"devices", "users", "keys", "policy", "dns", value()} {
		changes = append(changes, model.Change{
			Kind: []string{"created", "changed", "removed", value()}[index%4], Collector: collector, ResourceID: value(), Name: value(),
			Attribution: &model.Attribution{ActorLogin: value(), ActorName: value(), Origin: value()},
			Fields: []model.FieldChange{
				set(value(), value(), value()),
				set("tags", []any{value()}, []any{value(), value()}),
				{Field: value(), New: map[string]any{value(): value()}, NewPresent: true},
			},
		})
	}
	for i := 0; i < FleetSummaryMinimum; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: value(), Name: value(), Attribution: &model.Attribution{ActorLogin: value()}, Fields: []model.FieldChange{set("clientVersion", "1", "2")}})
	}
	// Device shares: recipients, device names, and other field values are
	// tenant values on single and grouped share lines.
	recipient := value()
	for i := 0; i < 2; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "device_details", ResourceID: value(), Name: value(), Attribution: &model.Attribution{ActorLogin: value()},
			Invites: map[string]model.DeviceInvite{"1": {Recipient: recipient, Accepted: true}, "2": {Recipient: value(), MultiUse: true}, "3": {Recipient: value(), AllowExitNode: true}},
			Fields: []model.FieldChange{
				set("deviceInvites[1].tailnetId", value(), value()),
				set("deviceInvites[2].accepted", false, true),
				set("deviceInvites[2]."+value(), value(), value()),
				{Field: "deviceInvites[3]", New: map[string]any{"id": "3"}, NewPresent: true},
			}})
	}
	return []Message{
		context.Digest(DigestInput{BatchID: 7, ObservedAt: testObservedAt, Changes: changes, MutedCount: 2, Attributed: true}),
		context.CollectorsUnhealthy([]CollectorHealth{{Collector: value(), Reason: value()}}, testObservedAt),
		context.CollectorsRecovered([]string{value(), value()}, testObservedAt),
		context.Update(value(), value(), testObservedAt),
		context.AdminChange(value(), []string{value(), value()}, value(), value(), testObservedAt),
		context.Test(testObservedAt),
		context.ExpiryWarning(3, []ExpiryLine{{Kind: value(), Name: value(), Tags: []string{value()}, Expires: testObservedAt.Add(48 * time.Hour), DaysLeft: 2}}, testObservedAt),
	}
}

// trustedSpan reports span styles whose text TailState writes itself.
func trustedSpan(style string) bool {
	return style == SpanLiteral || style == SpanStrong || style == SpanEmph || style == SpanLink
}

// TestNoRenderedLineStartsWithTenantText is R-048's third acceptance
// criterion and the guarantee that makes minimal escaping safe: a tenant
// value can never start a block. For generated values full of block syntax,
// line breaks, and control characters, in every message type and format
// (and in the body a destination with a separate title receives), every
// rendered line starts with trusted text, and a value never adds a line.
func TestNoRenderedLineStartsWithTenantText(t *testing.T) {
	r := rand.New(rand.NewPCG(232, 48))
	for iteration := 0; iteration < 60; iteration++ {
		for _, message := range tenantMessages(r) {
			for _, l := range message.Lines {
				if (l.Kind == LinePlain || l.Kind == LineContext) && len(l.Spans) > 0 && !trustedSpan(l.Spans[0].Style) {
					t.Fatalf("a line of %q starts with a %s span", message.Title, l.Spans[0].Style)
				}
			}
			for _, format := range Formats {
				outputs := []string{Render(message, format)}
				for _, serviceURL := range []string{discordURL, pushoverURL, telegramURL, teamsURL} {
					outputs = append(outputs, PrepareMessage(message, serviceURL, format).Message())
				}
				for index, rendered := range outputs {
					lines := strings.Split(rendered, "\n")
					if index == 0 && len(lines) > 1+len(message.Lines) {
						t.Fatalf("%s: a value added a line to %q:\n%s", format, message.Title, rendered)
					}
					for _, current := range lines {
						trimmed := strings.TrimLeft(current, " ")
						if strings.HasPrefix(trimmed, tenantMarker) || strings.ContainsAny(current, "\r\u2028\u2029\x00\x1b") {
							t.Fatalf("%s: line starts with tenant text or keeps a control character: %q\n%s", format, current, rendered)
						}
					}
				}
			}
		}
	}
}

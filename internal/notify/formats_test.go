package notify

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

func goldenDigest() Message {
	return Context{Label: "lab", Tailnet: "example.com", PublicURL: "https://tailstate.example"}.Digest(DigestInput{
		BatchID:    42,
		ObservedAt: testObservedAt,
		MutedCount: 1,
		Changes: []model.Change{
			{Kind: "created", Collector: "devices", Name: "web_*1*<!channel>"},
			{Kind: "changed", Collector: "users", Name: "alice", Fields: []model.FieldChange{{Field: "role", Old: "member", New: "admin", OldPresent: true, NewPresent: true}}},
		},
	})
}

// TestRenderedFormatsAreGolden pins the exact output of each renderer for
// one digest (E-019 golden tests).
func TestRenderedFormatsAreGolden(t *testing.T) {
	golden := map[string]string{
		FormatMarkdown: "### 🔴 2 Tailscale changes (1 high) · lab (example.com)\n" +
			"1 created, 1 changed · 🔴 1 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ **alice** (user) changed\n" +
			"  - `role`: `member` → `admin`\n" +
			"🟠 ➕ **web\\_\\*1\\*\\<!channel>** (device) created\n" +
			"\n" +
			"1 muted change not shown · 5 Oct 2026 12:00 UTC · [Batch 42 in History](https://tailstate.example/history?batch=42)",
		FormatSlack: "*🔴 2 Tailscale changes (1 high) · lab (example.com)*\n" +
			"1 created, 1 changed · 🔴 1 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ *alice* (user) changed\n" +
			"    • `role`: `member` → `admin`\n" +
			"🟠 ➕ *web_∗1∗&lt;!channel&gt;* (device) created\n" +
			"\n" +
			"1 muted change not shown · 5 Oct 2026 12:00 UTC · <https://tailstate.example/history?batch=42|Batch 42 in History>",
		FormatPlain: "🔴 2 Tailscale changes (1 high) · lab (example.com)\n" +
			"1 created, 1 changed · 🔴 1 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ alice (user) changed\n" +
			"  • role: member → admin\n" +
			"🟠 ➕ web_*1*<!channel> (device) created\n" +
			"\n" +
			"1 muted change not shown · 5 Oct 2026 12:00 UTC · Batch 42 in History: https://tailstate.example/history?batch=42",
		FormatTeams: "**🔴 2 Tailscale changes (1 high) · lab (example.com)**\n" +
			"1 created, 1 changed · 🔴 1 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ **alice** (user) changed\n" +
			"- role: member → admin\n" +
			"🟠 ➕ **web＿∗1∗<!channel>** (device) created\n" +
			"\n" +
			"1 muted change not shown · 5 Oct 2026 12:00 UTC · [Batch 42 in History](https://tailstate.example/history?batch=42)",
		FormatHTML: "<b>🔴 2 Tailscale changes (1 high) · lab (example.com)</b>\n" +
			"1 created, 1 changed · 🔴 1 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ <b>alice</b> (user) changed\n" +
			"  • <code>role</code>: <code>member</code> → <code>admin</code>\n" +
			"🟠 ➕ <b>web_*1*&lt;!channel&gt;</b> (device) created\n" +
			"\n" +
			"1 muted change not shown · 5 Oct 2026 12:00 UTC · <a href=\"https://tailstate.example/history?batch=42\">Batch 42 in History</a>",
	}
	message := goldenDigest()
	for format, want := range golden {
		if got := Render(message, format); got != want {
			t.Fatalf("%s rendering mismatch\n got: %q\nwant: %q", format, got, want)
		}
	}
	// The stored payload round-trips through JSON without changing output.
	payloadFormat, payload, err := EncodePayload(message)
	if err != nil || payloadFormat != PayloadMessage {
		t.Fatalf("encode format=%q err=%v", payloadFormat, err)
	}
	var decoded Message
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil || Render(decoded, FormatSlack) != golden[FormatSlack] {
		t.Fatalf("decoded payload renders differently: %v", err)
	}
}

// TestSlackDigestUsesMrkdwnWithoutHeadings is the E-019 Slack acceptance
// criterion, and keeps tenant values from creating mentions or links.
func TestSlackDigestUsesMrkdwnWithoutHeadings(t *testing.T) {
	got := Render(goldenDigest(), FormatFor("slack://hooks/T000/B000/XXXX", ""))
	if strings.Contains(got, "###") || strings.Contains(got, "**") || !strings.HasPrefix(got, "*🔴 2 Tailscale changes (1 high)") || !strings.Contains(got, "*alice*") {
		t.Fatalf("slack digest is not mrkdwn:\n%s", got)
	}
	if strings.Contains(got, "<!channel>") || strings.Contains(got, "\\") {
		t.Fatalf("slack digest contains an active mention or Markdown escapes:\n%s", got)
	}
}

// TestPlainOutputHasNoMarkdownControlSyntax is the E-019 plain-text
// acceptance criterion.
func TestPlainOutputHasNoMarkdownControlSyntax(t *testing.T) {
	messages := []Message{
		Context{Tailnet: "example.com", PublicURL: "https://tailstate.example"}.Digest(DigestInput{BatchID: 3, ObservedAt: testObservedAt, Changes: append(rollout(6), model.Change{Kind: "changed", Collector: "devices", Name: "server", Fields: make([]model.FieldChange, 2), FieldsTruncated: true, TotalFields: 30})}),
		Context{Tailnet: "example.com", PublicURL: "https://tailstate.example"}.CollectorsUnhealthy([]CollectorHealth{{Collector: "devices", Reason: "auth rejected"}}, testObservedAt),
		Context{Tailnet: "example.com"}.Update("1.0", "1.1", testObservedAt),
		Context{Label: "lab", Tailnet: "example.com", Version: "1.1"}.Test(testObservedAt),
	}
	for _, message := range messages {
		got := Render(message, FormatPlain)
		for _, syntax := range []string{"**", "###", "`", "\\", "](", " _", "_\n", "[", "<https"} {
			if strings.Contains(got, syntax) {
				t.Fatalf("plain output contains Markdown syntax %q:\n%s", syntax, got)
			}
		}
		if strings.HasSuffix(got, "_") {
			t.Fatalf("plain output ends with emphasis:\n%s", got)
		}
	}
	fitted := FitMessageFor(Render(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: rollout(4)}), FormatPlain), 200, FormatPlain)
	if len(fitted) > 200 || strings.Contains(fitted, "_") || !strings.Contains(fitted, "Shortened for this destination") {
		t.Fatalf("plain fitting added Markdown or exceeded the budget:\n%s", fitted)
	}
}

func TestFormatSelectionByServiceAndOverride(t *testing.T) {
	cases := map[string]string{
		"slack://hooks/a/b/c":                                  FormatSlack,
		"googlechat://chat.googleapis.com/v1/x":                FormatSlack,
		"mattermost://host/token":                              FormatMarkdown,
		"discord://token@id":                                   FormatMarkdown,
		"generic+https://example.com/hook":                     FormatMarkdown,
		"telegram://token@telegram?chats=1":                    FormatHTML,
		"telegram://token@telegram?chats=1&parsemode=HTML":     FormatHTML,
		"telegram://token@telegram?chats=1&parsemode=Markdown": FormatHTML,
		"telegram://token@telegram?chats=1&parsemode=None":     FormatHTML,
		"smtp://user:pass@host:25/?to=a@b":                     FormatPlain,
		"pushover://shoutrrr:token@user":                       FormatPlain,
		"matrix://:token@matrix.example/":                      FormatPlain,
		"ntfy://ntfy.sh/topic":                                 FormatPlain,
		"ntfy://ntfy.sh/topic?markdown=yes":                    FormatMarkdown,
		"smtp://user:pass@host:25/?to=a@b&usehtml=yes":         FormatPlain,
		"unknownservice://x":                                   FormatMarkdown,
		"not a url":                                            FormatMarkdown,
	}
	for serviceURL, want := range cases {
		if got := FormatFor(serviceURL, ""); got != want {
			t.Fatalf("FormatFor(%q)=%q, want %q", serviceURL, got, want)
		}
	}
	if got := FormatFor("slack://hooks/a/b/c", "plain"); got != FormatPlain {
		t.Fatalf("override ignored: %q", got)
	}
	if got := FormatFor("telegram://t@telegram", "bogus"); got != FormatHTML {
		t.Fatalf("invalid override was applied: %q", got)
	}
	for _, valid := range []string{"", "Markdown", " slack ", "plain", "Teams", "HTML"} {
		if _, err := ValidateFormat(valid); err != nil {
			t.Fatalf("ValidateFormat(%q): %v", valid, err)
		}
	}
	if _, err := ValidateFormat("markdownv2"); err == nil {
		t.Fatal("unknown format accepted")
	}
	if len(Formats) != 5 {
		t.Fatalf("formats=%v", Formats)
	}
}

// TestPrepareDeliversLegacyRowsUnchanged covers rows queued before the
// schema v14 migration: they are pre-rendered Markdown and are sent exactly
// as stored, whatever the destination's format.
func TestPrepareDeliversLegacyRowsUnchanged(t *testing.T) {
	legacy := "### Tailscale inventory changed\n**1 change(s):** 1 created"
	for _, payloadFormat := range []string{"", PayloadMarkdown} {
		got, err := Prepare(payloadFormat, legacy, "slack://hooks/a/b/c", FormatPlain)
		if err != nil || got != legacy {
			t.Fatalf("legacy row changed: %q err=%v", got, err)
		}
	}
	if _, err := Prepare("html", "x", "slack://a", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("unknown payload format error=%v", err)
	}
	if _, err := Prepare(PayloadMessage, "{", "slack://a", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("damaged payload error=%v", err)
	}
	_, payload, _ := EncodePayload(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: largeChanges(300)}))
	fitted, err := Prepare(PayloadMessage, payload, "pushover://shoutrrr:token@user", "")
	if err != nil || len(fitted) > 1024 || strings.Contains(fitted, "**") || !strings.Contains(fitted, "Shortened for this destination") {
		t.Fatalf("prepared pushover payload is not fitted plain text (%d bytes): %s err=%v", len(fitted), fitted, err)
	}
	if format, text, err := EncodePayload(Text("raw")); err != nil || format != PayloadMarkdown || text != "raw" {
		t.Fatalf("text payload encoded as %q %q %v", format, text, err)
	}
	if got := Render(Text("**kept**"), FormatPlain); got != "**kept**" || Slack(Text("x")) != "x" || Plain(Message{}) != "" {
		t.Fatalf("text messages must pass through every renderer unchanged")
	}
	if got := Render(Message{Title: "t", Lines: []Line{line(link("bad", "http://x"))}}, FormatSlack); strings.Contains(got, "<http") {
		t.Fatalf("unsafe slack link rendered: %s", got)
	}
	if got := Plain(Message{Title: "t", Lines: []Line{line(link("bad", "http://x")), note("n"), item(code("c"))}}); strings.Contains(got, "http://x") {
		t.Fatalf("unsafe plain link rendered: %s", got)
	}
	if got := Slack(Message{Title: "t", Lines: []Line{note("n"), line(Span{Style: "other", Text: "*x*"})}}); !strings.Contains(got, "    _n_") || !strings.Contains(got, "∗x∗") {
		t.Fatalf("slack note or unknown span: %s", got)
	}
}

// TestHTMLEmailAndMarkdownNtfyKeepValuesInert is R-059's acceptance
// criterion: an SMTP URL with usehtml=yes receives an HTML-escaped body with
// <br> line breaks, also with a Markdown or plain override, and an ntfy URL
// with markdown=yes receives the Markdown rendering, whose values are
// escaped. Without these options both render as before.
func TestHTMLEmailAndMarkdownNtfyKeepValuesInert(t *testing.T) {
	hostile := `<a href="https://evil.example/reauth">Re-authenticate now</a> <img src="https://evil.example/b.png"> [click](https://evil.example)`
	message := Context{Label: hostile, Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
		{Kind: "created", Collector: "keys", Name: hostile},
		{Kind: "changed", Collector: "users", Name: "bob", Fields: []model.FieldChange{set("role", "member", hostile)}},
	}})
	// Markdown escapes a value's < and ] with a backslash; an unescaped one
	// outside a code span (whose content is literal) would be live markup.
	codeSpan := regexp.MustCompile("`[^`]*`")
	rawMarkup := regexp.MustCompile(`(^|[^\\])(<a|<img|\]\()`)
	live := func(text string) bool { return rawMarkup.MatchString(codeSpan.ReplaceAllString(text, "")) }
	server := newSMTPServer(t)
	smtpURL := "smtp://" + server.listener.Addr().String() + "/?from=tailstate@example.com&to=ops@example.com&encryption=None&usestarttls=No&auth=None"
	for _, override := range []string{"", FormatPlain, FormatMarkdown, FormatHTML} {
		prepared := PrepareMessage(message, smtpURL+"&usehtml=yes", override)
		if prepared.Title == "" || prepared.Format != FormatHTML {
			t.Fatalf("%q: prepared=%+v", override, prepared)
		}
		for _, text := range []string{prepared.Text, prepared.Body} {
			// In an HTML part, Markdown link syntax is plain text.
			if strings.Contains(text, "<a") || strings.Contains(text, "<img") {
				t.Fatalf("%q: HTML e-mail keeps markup from a value:\n%s", override, text)
			}
			lines := strings.Split(text, "\n")
			for _, current := range lines[:len(lines)-1] {
				if !strings.HasSuffix(current, "<br>") {
					t.Fatalf("%q: HTML e-mail line without <br>: %q", override, current)
				}
			}
		}
		if err := New().SendPrepared(context.Background(), smtpURL+"&usehtml=yes", prepared); err != nil {
			t.Fatalf("%q: send: %v", override, err)
		}
	}
	// The subject is a plain-text header; the parts are checked.
	for _, data := range server.messages() {
		_, parts, found := strings.Cut(data, "Content-Type: text/plain")
		if !found || !strings.Contains(parts, "Content-Type: text/html") || !strings.Contains(parts, "<br>") || strings.Contains(parts, "<a href") || strings.Contains(parts, "<img") {
			t.Fatalf("HTML e-mail keeps markup from a value:\n%s", data)
		}
	}
	for _, override := range []string{"", FormatPlain, FormatSlack, FormatHTML} {
		prepared := PrepareMessage(message, ntfyURL+"?markdown=yes", override)
		text := prepared.Message()
		if prepared.Format != FormatMarkdown || live(text) || !strings.Contains(text, `\[click\](https:`) {
			t.Fatalf("%q: Markdown ntfy message keeps markup from a value:\n%s", override, text)
		}
		if lines := strings.Split(text, "\n"); len(lines) < 4 || !strings.HasSuffix(lines[0], "  ") {
			t.Fatalf("%q: Markdown ntfy message lost its line breaks:\n%s", override, text)
		}
	}
	mock := &mockProviders{}
	if err := senderWithTransport(mock).SendPrepared(context.Background(), ntfyURL+"?markdown=yes", PrepareMessage(message, ntfyURL+"?markdown=yes", "")); err != nil {
		t.Fatal(err)
	}
	if request := mock.all()[0]; request.header.Get("Content-Type") != "text/markdown" || live(request.body) {
		t.Fatalf("ntfy request=%+v", request)
	}
	// Without the options, both keep their plain rendering.
	_, plainBody, _ := strings.Cut(Plain(message), "\n")
	for _, serviceURL := range []string{smtpURL, smtpURL + "&usehtml=no", ntfyURL, ntfyURL + "?markdown=no"} {
		if prepared := PrepareMessage(message, serviceURL, ""); prepared.Format != FormatPlain || prepared.Body != plainBody {
			t.Fatalf("%s: prepared=%+v", serviceURL, prepared)
		}
	}
}

func largeChanges(count int) []model.Change {
	changes := make([]model.Change, 0, count)
	for i := 0; i < count; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "devices", Name: strings.Repeat("n", 20) + string(rune('a'+i%26))})
	}
	return changes
}

package notify

import (
	"encoding/json"
	"errors"
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
		"slack://hooks/a/b/c":                   FormatSlack,
		"googlechat://chat.googleapis.com/v1/x": FormatSlack,
		"mattermost://host/token":               FormatMarkdown,
		"discord://token@id":                    FormatMarkdown,
		"generic+https://example.com/hook":      FormatMarkdown,
		"telegram://token@telegram?chats=1":     FormatPlain,
		"smtp://user:pass@host:25/?to=a@b":      FormatPlain,
		"pushover://shoutrrr:token@user":        FormatPlain,
		"matrix://:token@matrix.example/":       FormatPlain,
		"ntfy://ntfy.sh/topic":                  FormatPlain,
		"unknownservice://x":                    FormatMarkdown,
		"not a url":                             FormatMarkdown,
	}
	for serviceURL, want := range cases {
		if got := FormatFor(serviceURL, ""); got != want {
			t.Fatalf("FormatFor(%q)=%q, want %q", serviceURL, got, want)
		}
	}
	if got := FormatFor("slack://hooks/a/b/c", "plain"); got != FormatPlain {
		t.Fatalf("override ignored: %q", got)
	}
	if got := FormatFor("telegram://t@telegram", "bogus"); got != FormatPlain {
		t.Fatalf("invalid override was applied: %q", got)
	}
	for _, valid := range []string{"", "Markdown", " slack ", "plain"} {
		if _, err := ValidateFormat(valid); err != nil {
			t.Fatalf("ValidateFormat(%q): %v", valid, err)
		}
	}
	if _, err := ValidateFormat("html"); err == nil {
		t.Fatal("unknown format accepted")
	}
	if len(Formats) != 4 {
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

func largeChanges(count int) []model.Change {
	changes := make([]model.Change, 0, count)
	for i := 0; i < count; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "devices", Name: strings.Repeat("n", 20) + string(rune('a'+i%26))})
	}
	return changes
}

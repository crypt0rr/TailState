package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

// telegramTags matches the markup a Telegram HTML message may contain, and
// telegramEntities the entities.
var (
	telegramTags     = regexp.MustCompile(`<(/?)(b|i|code|a)( href="https://[^"<>]*")?>`)
	telegramEntities = regexp.MustCompile(`&(amp|lt|gt|#34|#39);`)
)

// validTelegramHTML reports whether text uses only Telegram's HTML subset:
// balanced <b>, <i>, <code>, and <a href> tags, links only to the public
// URL, and only the entities html.EscapeString writes.
func validTelegramHTML(t *testing.T, text string) {
	t.Helper()
	var stack []string
	rest := text
	for {
		index := strings.IndexByte(rest, '<')
		if index < 0 {
			break
		}
		match := telegramTags.FindStringSubmatchIndex(rest[index:])
		if match == nil || match[0] != 0 {
			t.Fatalf("unexpected markup at %q", rest[index:min(len(rest), index+40)])
		}
		closing, name := rest[index+match[2]:index+match[3]] == "/", rest[index+match[4]:index+match[5]]
		if name == "a" && !closing && !strings.HasPrefix(rest[index:], `<a href="https://tailstate.example/`) {
			t.Fatalf("link to another site: %q", rest[index:index+match[1]])
		}
		if closing {
			if len(stack) == 0 || stack[len(stack)-1] != name {
				t.Fatalf("unbalanced </%s> in %q", name, text)
			}
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, name)
		}
		rest = rest[index+match[1]:]
	}
	if len(stack) != 0 {
		t.Fatalf("unclosed tags %v in %q", stack, text)
	}
	if stripped := telegramEntities.ReplaceAllString(text, ""); strings.Contains(stripped, "&") || strings.ContainsAny(telegramTags.ReplaceAllString(stripped, ""), "<>\"") {
		t.Fatalf("raw &, <, >, or \" in %q", text)
	}
}

// TestTelegramHTMLIsGolden is E-035's golden test for a digest, a health
// alert, and an expiry warning.
func TestTelegramHTMLIsGolden(t *testing.T) {
	context := Context{Label: "lab", Tailnet: "example.com", PublicURL: "https://tailstate.example"}
	for name, tc := range map[string]struct {
		message Message
		want    string
	}{
		"digest": {goldenDigest(), "<b>🔴 2 Tailscale changes (1 high) · lab (example.com)</b>\n" +
			"1 created, 1 changed · 🔴 1 high, 🟠 1 medium\n" +
			"\n" +
			"🔴 ✏️ <b>alice</b> (user) changed\n" +
			"  • <code>role</code>: <code>member</code> → <code>admin</code>\n" +
			"🟠 ➕ <b>web_*1*&lt;!channel&gt;</b> (device) created\n" +
			"\n" +
			"1 muted change not shown · 5 Oct 2026 12:00 UTC · <a href=\"https://tailstate.example/history?batch=42\">Batch 42 in History</a>"},
		"health": {context.CollectorsUnhealthy([]CollectorHealth{{Collector: "devices", Reason: "auth rejected"}, {Collector: "dns", Reason: "timeout"}}, testObservedAt), "<b>⚠️ Tailscale API collectors unhealthy · lab (example.com)</b>\n" +
			"2 collectors failed three consecutive polls. TailState will keep retrying.\n" +
			"  • <code>devices</code>: auth rejected\n" +
			"  • <code>dns</code>: timeout\n" +
			"Observed at 5 Oct 2026 12:00 UTC\n" +
			"<a href=\"https://tailstate.example/status\">Open TailState status</a>"},
		"expiry": {context.ExpiryWarning(7, []ExpiryLine{{Kind: "Device node key", Name: "web-02.tail1234.ts.net", Tags: []string{"tag:prod"}, Expires: testObservedAt.Add(72 * time.Hour), DaysLeft: 3}}, testObservedAt), "<b>⏳ Tailscale keys expiring within 7 days · lab (example.com)</b>\n" +
			"<b>1 resource</b> entered the 7-day expiry warning window. Re-authenticate devices or replace auth keys before they expire.\n" +
			"Observed at 5 Oct 2026 12:00 UTC\n" +
			"<a href=\"https://tailstate.example/status\">Open TailState status</a>\n" +
			"\n" +
			"  • Device node key <b>web-02</b> (<code>tag:prod</code>) expires 8 Oct 2026 12:00 UTC (3 days left)"},
	} {
		got := Render(tc.message, FormatHTML)
		if got != tc.want || HTML(tc.message) != got {
			t.Fatalf("%s rendering mismatch\n got: %q\nwant: %q", name, got, tc.want)
		}
		validTelegramHTML(t, got)
	}
}

// TestTelegramHTMLValuesCannotInjectMarkup is E-035's injection criterion:
// tag, attribute, and entity injection through device names, tags, labels,
// and actors is escaped, and a link only ever points at the public URL.
func TestTelegramHTMLValuesCannotInjectMarkup(t *testing.T) {
	hostile := []string{
		`<b>bold</b><a href="https://evil.example">x</a>`,
		`" onmouseover="alert(1)`,
		`</code><script>alert(1)</script>`,
		`&amp;lt;b&gt; &#60;i&#62; &nbsp;`,
		"<tg-spoiler>s</tg-spoiler> <blockquote>q",
	}
	for _, value := range hostile {
		context := Context{Label: value, Tailnet: value, PublicURL: "https://tailstate.example"}
		messages := []Message{
			context.Digest(DigestInput{BatchID: 1, ObservedAt: testObservedAt, Attributed: true, Changes: []model.Change{
				{Kind: "changed", Collector: "devices", Name: value, Attribution: &model.Attribution{ActorLogin: value}, Fields: []model.FieldChange{set("tags", []any{"tag:a"}, []any{"tag:a", value}), set(value, value, value)}},
			}}),
			context.ExpiryWarning(3, []ExpiryLine{{Kind: value, Name: value, Tags: []string{value}, Expires: testObservedAt}}, testObservedAt),
			context.CollectorsUnhealthy([]CollectorHealth{{Collector: value, Reason: value}}, testObservedAt),
			context.Test(testObservedAt),
		}
		for _, message := range messages {
			got := Render(message, FormatHTML)
			validTelegramHTML(t, got)
			if strings.Contains(got, value) {
				t.Fatalf("value %q kept its markup:\n%s", value, got)
			}
		}
		// A damaged stored link is shown as its label only.
		if got := Render(Message{Title: "t", Lines: []Line{line(link(value, "https://evil.example/\"x")), line(link("ok", "javascript:alert(1)"))}}, FormatHTML); strings.Contains(got, "<a ") {
			t.Fatalf("unsafe link rendered: %s", got)
		}
	}
}

// TestTelegramReceivesFittedHTML is E-035's delivery criterion: a Telegram
// mock receives parse_mode=HTML, the title in bold, and a valid body fitted
// to 4,096 bytes; an operator parse mode in the URL is respected; and plain
// text stays available as an explicit override.
func TestTelegramReceivesFittedHTML(t *testing.T) {
	send := func(serviceURL, override string, message Message) map[string]any {
		t.Helper()
		mock := &mockProviders{}
		if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, PrepareMessage(message, serviceURL, override)); err != nil {
			t.Fatalf("%s: %v", serviceURL, err)
		}
		requests := mock.all()
		if len(requests) != 1 {
			t.Fatalf("requests=%d", len(requests))
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(requests[0].body), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	var changes []model.Change
	for i := 0; i < 300; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "devices", Name: fmt.Sprintf("ci-runner-<%03d>&.tail1234.ts.net", i)})
	}
	changes = append(changes, model.Change{Kind: "changed", Collector: "policy", Name: "Tailnet policy", Fields: []model.FieldChange{set("acls", "a", "b")}})
	large := Context{Label: "lab & <ops>", Tailnet: "example.com", PublicURL: "https://tailstate.example"}.Digest(DigestInput{BatchID: 3, ObservedAt: testObservedAt, Changes: changes})

	payload := send(telegramURL, "", large)
	text, _ := payload["text"].(string)
	title, body, _ := strings.Cut(text, "\n")
	if payload["parse_mode"] != "HTML" || title != "<b>🔴 301 Tailscale changes (1 high) · lab &amp; &lt;ops&gt; (example.com)</b>" {
		t.Fatalf("parse_mode=%v title=%q", payload["parse_mode"], title)
	}
	if len(body) > 4096-len(plainTitle(large))-1 || !strings.Contains(body, "🔴 ✏️ <b>Tailnet policy</b> changed") || !strings.Contains(body, "<i>Shortened for this destination: ") || !strings.HasSuffix(body, `<a href="https://tailstate.example/history?batch=3">Batch 3 in History</a>`) {
		t.Fatalf("telegram body is not fitted HTML (%d bytes):\n%s", len(body), body)
	}
	validTelegramHTML(t, body)

	small := Context{Tailnet: "example.com"}.Test(testObservedAt)
	// An operator parse mode wins: Markdown gets plain text with the title
	// line, and an operator HTML mode gets the HTML rendering.
	payload = send(telegramURL+"&parsemode=Markdown", "", small)
	if text, _ := payload["text"].(string); payload["parse_mode"] != "Markdown" || !strings.HasPrefix(text, "🧪 TailState test · example.com\nTailState test:") {
		t.Fatalf("operator Markdown mode: %v", payload)
	}
	payload = send(telegramURL+"&parsemode=HTML", "", small)
	if text, _ := payload["text"].(string); payload["parse_mode"] != "HTML" || !strings.HasPrefix(text, "<b>🧪 TailState test · example.com</b>\n<b>TailState test:</b> notifications") {
		t.Fatalf("operator HTML mode: %v", payload)
	}
	// Plain text stays available: Shoutrrr escapes it in its own HTML mode.
	payload = send(telegramURL, FormatPlain, small)
	if text, _ := payload["text"].(string); payload["parse_mode"] != "HTML" || !strings.HasPrefix(text, "<b>🧪 TailState test · example.com</b>\nTailState test: notifications") {
		t.Fatalf("plain override: %v", payload)
	}
	// A plain override on a URL that forces HTML mode is escaped, so a
	// value cannot add markup.
	hostile := Context{Label: "<b>lab</b> &", Tailnet: "example.com"}.Test(testObservedAt)
	payload = send(telegramURL+"&parsemode=HTML", FormatPlain, hostile)
	if text, _ := payload["text"].(string); payload["parse_mode"] != "HTML" || !strings.Contains(text, "\nInstance: &lt;b&gt;lab&lt;/b&gt; &amp;\n") {
		t.Fatalf("plain override in a forced HTML mode: %v", payload)
	} else {
		validTelegramHTML(t, text)
	}
	if params := parseDestination(telegramURL).params(Prepared{Title: "t", Format: FormatPlain}); params == nil || (*params)["parsemode"] != "" {
		t.Fatalf("plain override passes a parse mode: %v", params)
	}
}

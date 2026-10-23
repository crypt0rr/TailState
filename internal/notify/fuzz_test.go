package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Production digests are budgeted to 12 KB (digestBudget), and the partitioner
// and the fitter do work that grows with the length and line count of their
// input. The targets therefore skip inputs above these bounds to keep each
// execution fast. The asserted properties do not depend on the bounds.
const (
	fuzzNotifyMaxBytes = 16 << 10
	fuzzNotifyMaxLines = 2000
)

// FuzzPartitionLines checks the line partitioner behind the Discord and Slack
// chunking. Every chunk of a body with visible text must be valid UTF-8,
// within the rune budget, and not blank. A body with no visible text comes
// back as a single chunk.
func FuzzPartitionLines(f *testing.F) {
	f.Add(Render(goldenDigest(), FormatMarkdown), 40)
	f.Add(Render(goldenDigest(), FormatPlain), 1)
	f.Add("line one\nline two\nline three\nline four\n", 12)
	f.Add("ééé\n"+strings.Repeat("界", 20), 5)
	f.Add("   \n  ", 2)
	f.Add(strings.Repeat(strings.Repeat("x", slackSectionRunes)+"\n", 3), slackSectionRunes)
	f.Add(largeDigest(20), discordEmbedRunes)
	f.Fuzz(func(t *testing.T, body string, maxRunes int) {
		// Both production callers pass a positive budget, so the target only
		// generates positive budgets.
		if maxRunes < 1 || len(body) > fuzzNotifyMaxBytes || !utf8.ValidString(body) {
			return
		}
		chunks := partitionLines(body, maxRunes)
		if len(chunks) == 0 {
			t.Fatal("partitionLines returned no chunks")
		}
		if strings.TrimSpace(body) == "" {
			if len(chunks) != 1 || chunks[0] != body {
				t.Fatalf("blank body was partitioned as %q", chunks)
			}
			return
		}
		for _, chunk := range chunks {
			if !utf8.ValidString(chunk) {
				t.Fatalf("chunk is not valid UTF-8: %q", chunk)
			}
			if runes := utf8.RuneCountInString(chunk); runes > maxRunes {
				t.Fatalf("chunk has %d runes, budget %d", runes, maxRunes)
			}
			if strings.TrimSpace(chunk) == "" {
				t.Fatalf("blank chunk %q", chunk)
			}
		}
	})
}

// FuzzTruncate checks the rune-bounded and byte-bounded truncators. Their
// output must stay within the bound, be valid UTF-8, and be a prefix of the
// input.
func FuzzTruncate(f *testing.F) {
	f.Add("ééé", 2)
	f.Add(strings.Repeat("界", 20), 10)
	f.Add("short", 10)
	f.Add("界", 1)
	f.Add("界", 2)
	f.Fuzz(func(t *testing.T, value string, limit int) {
		// Both truncators take a non-negative bound.
		if limit < 0 || !utf8.ValidString(value) {
			return
		}
		runes := truncateRunes(value, limit)
		if count := utf8.RuneCountInString(runes); count > limit || !utf8.ValidString(runes) || !strings.HasPrefix(value, runes) {
			t.Fatalf("truncateRunes(%q, %d) = %q with %d runes", value, limit, runes, count)
		}
		clipped := truncateBytes(value, limit)
		if len(clipped) > limit || !utf8.ValidString(clipped) || !strings.HasPrefix(value, clipped) {
			t.Fatalf("truncateBytes(%q, %d) = %q", value, limit, clipped)
		}
	})
}

// FuzzFitMessage checks the budget fitter in every message format. A message
// within its budget must come back unchanged. Any other message must fit the
// byte budget and stay valid UTF-8.
func FuzzFitMessage(f *testing.F) {
	f.Add("short", 100, FormatMarkdown)
	f.Add("line one\nline two\nline three\nline four\n", 120, FormatPlain)
	f.Add("### title\n"+strings.Repeat("a line of text\n", 50), 150, FormatMarkdown)
	f.Add(Render(longLineDigest(strings.Repeat("&", 250)), FormatHTML), 4096, FormatHTML)
	f.Add(largeDigest(40), 1024, FormatMarkdown)
	f.Add("anything", 0, FormatMarkdown)
	f.Fuzz(func(t *testing.T, message string, limit int, format string) {
		if len(message) > fuzzNotifyMaxBytes || strings.Count(message, "\n") > fuzzNotifyMaxLines {
			return
		}
		fitted := FitMessageFor(message, limit, format)
		if limit <= 0 || len(message) <= limit {
			if fitted != message {
				t.Fatalf("message within budget %d was changed to %q", limit, fitted)
			}
			return
		}
		if len(fitted) > limit {
			t.Fatalf("fitted message is %d bytes, budget %d", len(fitted), limit)
		}
		if utf8.ValidString(message) && !utf8.ValidString(fitted) {
			t.Fatalf("fitted message is not valid UTF-8: %q", fitted)
		}
	})
}

// FuzzEscapeUntrusted checks the HTML and Slack escapers. The HTML output must
// contain no raw angle bracket, quote, or apostrophe, and the Slack output no
// raw angle bracket, so a value cannot open a tag, an attribute, or a Slack
// link. Untrusted Slack values must also lose the characters that start bold,
// strike, or code runs. Escaping is not idempotent (a second pass escapes the
// ampersands the first pass wrote), so no idempotence property is asserted.
func FuzzEscapeUntrusted(f *testing.F) {
	for _, value := range []string{
		"<script>alert(1)</script>",
		`<b>bold</b><a href="https://evil.example">x</a>`,
		`" onmouseover="alert(1)`,
		"&amp;lt;b&gt; &#60;i&#62; &nbsp;",
		"`code` and ~~strike~~ *bold*",
		"@channel and www.example.com",
	} {
		f.Add(value, true)
		f.Add(value, false)
	}
	f.Fuzz(func(t *testing.T, value string, untrusted bool) {
		escapedHTML := escapeHTML(value, untrusted)
		if strings.ContainsAny(escapedHTML, `<>"'`) {
			t.Fatalf("escapeHTML(%q, %v) = %q contains a raw delimiter", value, untrusted, escapedHTML)
		}
		escapedSlack := escapeSlack(value, untrusted)
		if strings.ContainsAny(escapedSlack, "<>") {
			t.Fatalf("escapeSlack(%q, %v) = %q contains a raw angle bracket", value, untrusted, escapedSlack)
		}
		if untrusted && strings.ContainsAny(escapedSlack, "*~`") {
			t.Fatalf("escapeSlack(%q, true) = %q keeps a style character", value, escapedSlack)
		}
		if utf8.ValidString(value) && !(utf8.ValidString(escapedHTML) && utf8.ValidString(escapedSlack)) {
			t.Fatalf("escaped output of %q is not valid UTF-8", value)
		}
	})
}

// FuzzRenderFlavours renders a one-line message in every format. Rendering
// must not panic, and output must be valid UTF-8 when the input is. The plain
// flavour must not let a value start a new line or a carriage return.
func FuzzRenderFlavours(f *testing.F) {
	f.Add("Tailscale changes", "lab (example.com)", SpanBold, "web_*1*<!channel>", "")
	f.Add("Batch", "", SpanLink, "History", "https://tailstate.example/history?batch=42")
	f.Add("", "", SpanCode, "`code` and ~~strike~~", "")
	f.Add("Title", "", SpanLink, "label", "https://evil.example/\nInjected")
	f.Fuzz(func(t *testing.T, title, scope, style, text, url string) {
		message := Message{Title: title, Scope: scope, Lines: []Line{
			{Kind: LineItem, Spans: []Span{{Style: style, Text: text, URL: url}, txt(" trailing text")}},
		}}
		valid := utf8.ValidString(title + scope + text + url)
		for _, format := range Formats {
			rendered := Render(message, format)
			if valid && !utf8.ValidString(rendered) {
				t.Fatalf("%s rendering is not valid UTF-8: %q", format, rendered)
			}
		}
		plain := Render(message, FormatPlain)
		if strings.ContainsRune(plain, '\r') || strings.Count(plain, "\n") > len(message.Lines) {
			t.Fatalf("plain rendering added a line break: %q", plain)
		}
	})
}

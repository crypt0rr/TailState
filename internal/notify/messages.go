package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/model"
)

// digestBudget is the default size of a rendered digest. Destinations with a
// smaller provider limit are fitted further at send time (see FitMessage).
const digestBudget = 12000

func Digest(changes []model.Change) string {
	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Kind]++
	}
	var b strings.Builder
	b.WriteString("### Tailscale inventory changed\n")
	fmt.Fprintf(&b, "**%d change(s):** %d created, %d changed, %d removed\n\n", len(changes), counts["created"], counts["changed"], counts["removed"])
	// Every line is complete Markdown on its own, so the digest is only ever
	// shortened at line boundaries and each omission is stated explicitly.
	const reserve = 200 // room for the closing omission notes
	for index, c := range changes {
		icon := map[string]string{"created": "➕", "changed": "✏️", "removed": "➖"}[c.Kind]
		line := fmt.Sprintf("%s **%s** `%s` (%s)\n", icon, escape(c.Name), c.Kind, escape(c.Collector))
		if b.Len()+len(line) > digestBudget-reserve {
			fmt.Fprintf(&b, "\n_%d more change(s) omitted; total: %d. See TailState History for the full batch._\n", len(changes)-index, len(changes))
			break
		}
		b.WriteString(line)
		omittedFields := 0
		for fieldIndex, field := range c.Fields {
			detail := fmt.Sprintf("  - `%s`: `%s` → `%s`\n", escapeCode(field.Field), short(field.Old), short(field.New))
			if b.Len()+len(detail) > digestBudget-reserve {
				omittedFields = len(c.Fields) - fieldIndex
				break
			}
			b.WriteString(detail)
		}
		if c.FieldsTruncated || omittedFields > 0 {
			total := len(c.Fields)
			if c.FieldsTruncated {
				total = max(c.TotalFields, len(c.Fields)+1)
			}
			fmt.Fprintf(&b, "  _Additional field changes omitted; total: %d._\n", total)
		}
	}
	return b.String()
}

func SourceHealth(collector string, recovered bool) string {
	if recovered {
		return fmt.Sprintf("### ✅ Tailscale API collector recovered\n`%s` is responding successfully again.", escapeCode(collector))
	}
	return fmt.Sprintf("### ⚠️ Tailscale API collector unhealthy\n`%s` failed three consecutive polls. TailState will keep retrying.", escapeCode(collector))
}

func Update(previous, current string) string {
	return fmt.Sprintf("### 🚀 TailState updated\n**Previous version:** `%s`\n**Current version:** `%s`", escapeCode(previous), escapeCode(current))
}

// escape makes value inert in bold and prose Markdown contexts. It must not
// be used inside a code span: CommonMark does not process backslash escapes
// there, so every escape would be shown literally. Use escapeCode instead.
func escape(value string) string {
	value = stripControl(value)
	// Escape Markdown syntax that can change links, emphasis, headings, HTML,
	// or block structure. Backticks are rendered as apostrophes so a value
	// cannot open a code span that swallows the rest of the line.
	value = strings.NewReplacer(
		"\\", "\\\\",
		"`", "'",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"!", "\\!",
		"{", "\\{",
		"}", "\\}",
		"<", "\\<",
		"|", "\\|",
		"~", "\\~",
		">", "\\>",
	).Replace(value)
	return truncate(value, 256)
}

// escapeCode makes value safe inside a single-backtick code span. Code span
// content is literal in CommonMark (links, emphasis, headings, and HTML are
// not interpreted), so only the characters that can end the span or the
// line are neutralised: backticks become apostrophes and control characters
// become spaces. Everything else is kept verbatim so timestamps, tags, and
// collector names stay readable and copyable.
func escapeCode(value string) string {
	return truncate(strings.ReplaceAll(stripControl(value), "`", "'"), 256)
}

// stripControl replaces control characters and Unicode line/paragraph
// separators with spaces so a value can never start a new Markdown block.
func stripControl(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, value)
}

// short renders a field value as compact JSON for a code span.
func short(value any) string {
	raw, _ := json.Marshal(value)
	text := string(raw)
	if len(text) > 180 {
		text = truncate(text, 179)
	}
	return escapeCode(text)
}

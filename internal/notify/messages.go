package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/model"
)

// digestBudget is the default size of a rendered digest. Destinations with a
// smaller provider limit are fitted further at send time (see FitMessage).
const digestBudget = 12000

// DigestInput is one rendered change digest: the changes of one batch that
// are eligible for a destination, plus the batch metadata used for context.
type DigestInput struct {
	BatchID    int64
	ObservedAt time.Time
	Changes    []model.Change
}

// DigestFunc builds the notification for one digest.
type DigestFunc func(DigestInput) Message

// TextDigest returns a DigestFunc that always produces the given
// pre-rendered Markdown text.
func TextDigest(text string) DigestFunc {
	return func(DigestInput) Message { return Text(text) }
}

var changeIcons = map[string]string{"created": "➕", "changed": "✏️", "removed": "➖"}

// Digest renders a change batch. The digest names the instance and tailnet,
// states when the batch was observed, links to the batch in History when a
// public URL is configured, and lists every change with its field diffs up to
// the default digest budget.
func (c Context) Digest(in DigestInput) Message {
	counts := map[string]int{}
	for _, change := range in.Changes {
		counts[change.Kind]++
	}
	message := c.message("", "Tailscale inventory changed",
		line(strong(fmt.Sprintf("%d change(s):", len(in.Changes))), lit(fmt.Sprintf(" %d created, %d changed, %d removed", counts["created"], counts["changed"], counts["removed"]))),
		observedLine(in.ObservedAt),
	)
	if batchURL := c.HistoryBatchURL(in.BatchID); batchURL != "" {
		message.Lines = append(message.Lines, line(link(fmt.Sprintf("View batch #%d in TailState History", in.BatchID), batchURL)))
	}
	message.Lines = append(message.Lines, blank())
	// Every line is complete on its own, so the digest is only ever shortened
	// at line boundaries and each omission is stated explicitly. The budget is
	// measured in Markdown, the most verbose rendering.
	const reserve = 200 // room for the closing omission notes
	size := markdownSize(message)
	add := func(l Line) bool {
		rendered := len(markdownLine(l)) + 1
		if size+rendered > digestBudget-reserve {
			return false
		}
		message.Lines = append(message.Lines, l)
		size += rendered
		return true
	}
	for index, change := range in.Changes {
		if !add(line(lit(changeIcons[change.Kind]+" "), bold(change.Name), lit(" "), code(change.Kind), lit(" ("), txt(change.Collector), lit(")"))) {
			message.Lines = append(message.Lines, blank(), line(emph(fmt.Sprintf("%d more change(s) omitted; total: %d. See TailState History for the full batch.", len(in.Changes)-index, len(in.Changes)))))
			break
		}
		omittedFields := 0
		for fieldIndex, field := range change.Fields {
			if !add(item(code(field.Field), lit(": "), code(shortValue(field.Old)), lit(" → "), code(shortValue(field.New)))) {
				omittedFields = len(change.Fields) - fieldIndex
				break
			}
		}
		if change.FieldsTruncated || omittedFields > 0 {
			total := len(change.Fields)
			if change.FieldsTruncated {
				total = max(change.TotalFields, len(change.Fields)+1)
			}
			message.Lines = append(message.Lines, note(fmt.Sprintf("Additional field changes omitted; total: %d.", total)))
			size += len(markdownLine(message.Lines[len(message.Lines)-1])) + 1
		}
	}
	return message
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

// shortValue renders a field value as compact JSON for a code span. The
// renderer escapes it for the destination's format.
func shortValue(value any) string {
	raw, _ := json.Marshal(value)
	text := string(raw)
	if len(text) > 180 {
		text = truncate(text, 179)
	}
	return text
}

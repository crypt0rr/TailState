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
	// MutedCount is the number of changes in the batch left out by mute
	// rules; they remain in History.
	MutedCount int
	// ResourceCounts is the number of resources each collector returned in
	// this poll, used to recognise upstream schema changes.
	ResourceCounts map[string]int
	// Attributed is set when the configuration audit log was consulted for
	// the batch: every listed change then names its actor (Change.Attribution)
	// or "actor unknown".
	Attributed bool
}

// DigestFunc builds the notification for one digest.
type DigestFunc func(DigestInput) Message

// TextDigest returns a DigestFunc that always produces the given
// pre-rendered Markdown text.
func TextDigest(text string) DigestFunc {
	return func(DigestInput) Message { return Text(text) }
}

var changeIcons = map[string]string{"created": "➕", "changed": "✏️", "removed": "➖"}

// severityIcons prefix every digest line with its built-in severity.
var severityIcons = map[model.Severity]string{model.SeverityHigh: "🔴", model.SeverityMedium: "🟠", model.SeverityLow: "⚪"}

// Digest renders a change batch. The digest names the instance and tailnet,
// states when the batch was observed, links to the batch in History when a
// public URL is configured, and lists every change with its field diffs up to
// the default digest budget.
func (c Context) Digest(in DigestInput) Message {
	counts := map[string]int{}
	severities := make([]model.Severity, len(in.Changes))
	for index, change := range in.Changes {
		counts[change.Kind]++
		severities[index] = model.Classify(change)
		counts[string(severities[index])]++
	}
	message := c.message("", "Tailscale inventory changed",
		line(strong(fmt.Sprintf("%d change(s):", len(in.Changes))), lit(fmt.Sprintf(" %d created, %d changed, %d removed", counts["created"], counts["changed"], counts["removed"]))),
		line(strong("Severity:"), lit(fmt.Sprintf(" %s %d high, %s %d medium, %s %d low", severityIcons[model.SeverityHigh], counts["high"], severityIcons[model.SeverityMedium], counts["medium"], severityIcons[model.SeverityLow], counts["low"]))),
		observedLine(in.ObservedAt),
	)
	if batchURL := c.HistoryBatchURL(in.BatchID); batchURL != "" {
		message.Lines = append(message.Lines, line(link(fmt.Sprintf("View batch #%d in TailState History", in.BatchID), batchURL)))
	}
	if in.MutedCount > 0 {
		message.Lines = append(message.Lines, line(emph(fmt.Sprintf("%d muted change(s) not shown; they are recorded in TailState History.", in.MutedCount))))
	}
	message.Lines = append(message.Lines, blank())
	schema, fleet, listed := summarize(in)
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
	// Summaries come first: they are short and stand for many resources.
	for _, change := range schema {
		add(c.schemaLine(change, in.BatchID))
	}
	for _, transition := range fleet {
		add(c.fleetLine(transition, in.BatchID))
	}
	for index, change := range listed {
		severity := model.Classify(change)
		if !add(line(lit(severityIcons[severity]+" "+changeIcons[change.Kind]+" "), bold(change.Name), lit(" "), code(change.Kind), lit(" ("), txt(change.Collector), lit(", "+string(severity)+")"))) {
			message.Lines = append(message.Lines, blank(), line(emph(fmt.Sprintf("%d more change(s) omitted; total: %d. See TailState History for the full batch.", len(listed)-index, len(in.Changes)))))
			break
		}
		if in.Attributed {
			add(changedByLine(change))
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

// changedByLine names who made a change: the audit log actor, or "actor
// unknown" when the configuration audit log had no matching entry.
func changedByLine(change model.Change) Line {
	if change.Attribution == nil || change.Attribution.IsZero() {
		return item(strong("Changed by:"), lit(" "+model.ActorUnknown))
	}
	return item(strong("Changed by:"), lit(" "), txt(change.Attribution.Display()))
}

// ExpiryLine is one resource listed in an expiry warning.
type ExpiryLine struct {
	Kind     string
	Name     string
	Tags     []string
	Expires  time.Time
	DaysLeft int
}

// ExpiryWarning builds one grouped system notification for resources that
// entered the given warning window. Like Digest, it names the instance and
// tailnet, states when the check observed the expiries, links to the Status
// page when a public URL is configured, and is shortened only at line
// boundaries with an explicit count of the omitted resources.
func (c Context) ExpiryWarning(windowDays int, lines []ExpiryLine, observedAt time.Time) Message {
	message := c.message("⏳", fmt.Sprintf("Tailscale keys expiring within %d day(s)", windowDays),
		line(strong(fmt.Sprintf("%d resource(s)", len(lines))), lit(fmt.Sprintf(" entered the %d-day expiry warning window. Re-authenticate devices or replace auth keys before they expire.", windowDays))),
		observedLine(observedAt),
	)
	if statusURL := c.StatusURL(); statusURL != "" {
		message.Lines = append(message.Lines, line(link("Open TailState status", statusURL)))
	}
	message.Lines = append(message.Lines, blank())
	const reserve = 200 // room for the closing omission note
	size := markdownSize(message)
	for index, entry := range lines {
		spans := []Span{txt(entry.Kind), lit(" "), bold(entry.Name)}
		if len(entry.Tags) > 0 {
			spans = append(spans, lit(" ("), code(strings.Join(entry.Tags, ", ")), lit(")"))
		}
		spans = append(spans, lit(" expires "), code(entry.Expires.UTC().Format("2006-01-02 15:04 UTC")), lit(fmt.Sprintf(" (%d day(s) left)", entry.DaysLeft)))
		l := item(spans...)
		rendered := len(markdownLine(l)) + 1
		if size+rendered > digestBudget-reserve {
			message.Lines = append(message.Lines, blank(), line(emph(fmt.Sprintf("%d more resource(s) omitted; total: %d. See the TailState status page for the full list.", len(lines)-index, len(lines)))))
			break
		}
		message.Lines = append(message.Lines, l)
		size += rendered
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

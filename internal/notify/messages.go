package notify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	// the batch: the header states how many changes it attributed, and every
	// change with a known actor (Change.Attribution) names it. Changes
	// without a known actor show none; History, the API, and evidence packs
	// keep their explicit "actor unknown".
	Attributed bool
	// AttributionUnavailable is set when the audit log lookup failed or ran
	// out of time, so no change could be attributed.
	AttributionUnavailable bool
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

// Digest renders a change batch. The title states how many changes the
// batch has and leads with its highest severity; the header counts them by
// kind and severity; every change follows, most severe first, with its field
// diffs up to the default digest budget; and one closing context line names
// the muted count, the observation time, and the History link (when a public
// URL is configured).
func (c Context) Digest(in DigestInput) Message {
	counts := map[string]int{}
	top := model.SeverityLow
	for _, change := range in.Changes {
		counts[change.Kind]++
		severity := model.Classify(change)
		counts[string(severity)]++
		if severityRank[severity] < severityRank[top] {
			top = severity
		}
	}
	title := plural(len(in.Changes), "Tailscale change", "Tailscale changes")
	if top != model.SeverityLow && counts[string(top)] > 0 {
		title += fmt.Sprintf(" (%d %s)", counts[string(top)], top)
	}
	message := c.message(top, severityIcons[top], title, line(lit(digestCounts(counts))))
	if header, ok := attributionHeader(in); ok {
		message.Lines = append(message.Lines, header)
	}
	message.Lines = append(message.Lines, blank())
	context := c.digestContext(in)
	entries := c.digestEntries(in)
	// Every line is complete on its own, so the digest is only ever shortened
	// at line boundaries and each omission is stated explicitly. The budget is
	// measured in Markdown, the most verbose rendering.
	reserve := 200 + len(markdownLine(context)) // room for the closing lines
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
	for index, entry := range entries {
		if !add(entry.line) {
			message.Lines = append(message.Lines, blank(), line(emph(omittedEntries(entries[index:], len(in.Changes)))))
			break
		}
		if entry.change == nil {
			continue
		}
		change := *entry.change
		if entry.actorLine != nil {
			add(*entry.actorLine)
		}
		omittedFields := 0
		for fieldIndex, field := range change.Fields {
			if !add(item(presentField(change.Collector, field)...)) {
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
	message.Lines = append(message.Lines, blank(), context)
	return message
}

// digestCounts is the digest header, for example "2 created, 17 changed ·
// 🔴 5 high, 🟠 2 medium, ⚪ 12 low". Zero counts are left out.
func digestCounts(counts map[string]int) string {
	var kinds, severities []string
	for _, kind := range []string{"created", "changed", "removed"} {
		if counts[kind] > 0 {
			kinds = append(kinds, fmt.Sprintf("%d %s", counts[kind], kind))
		}
	}
	for _, severity := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		if count := counts[string(severity)]; count > 0 {
			severities = append(severities, fmt.Sprintf("%s %d %s", severityIcons[severity], count, severity))
		}
	}
	if len(kinds) == 0 {
		return strings.Join(severities, ", ")
	}
	return strings.Join(kinds, ", ") + " · " + strings.Join(severities, ", ")
}

// digestContext is the digest's closing line: the muted count, the
// observation time, and the History link. It is a context line, so it is
// kept when the digest is shortened for a small destination.
func (c Context) digestContext(in DigestInput) Line {
	var spans []Span
	if in.MutedCount > 0 {
		spans = append(spans, lit(plural(in.MutedCount, "muted change", "muted changes")+" not shown · "))
	}
	spans = append(spans, lit(compactTime(in.ObservedAt)))
	if batchURL := c.HistoryBatchURL(in.BatchID); batchURL != "" {
		spans = append(spans, lit(" · "), link(fmt.Sprintf("Batch %d in History", in.BatchID), batchURL))
	}
	return Line{Kind: LineContext, Spans: spans}
}

// digestEntry is one top-level digest line: a schema or fleet summary, or a
// listed change (whose attribution and field lines follow it).
type digestEntry struct {
	severity model.Severity
	line     Line
	change   *model.Change
	// actorLine names the change's actor below the change line when the
	// actor does not fit on it.
	actorLine *Line
}

// severityRank orders severities from most to least important.
var severityRank = map[model.Severity]int{model.SeverityHigh: 0, model.SeverityMedium: 1, model.SeverityLow: 2}

// digestEntries returns the digest's top-level lines ordered by severity
// (high, medium, low), so a small destination budget, which drops lines from
// the end, cuts the least important changes first. Within a severity,
// summaries come first (they are short and stand for many resources), then
// changes by collector and name; the sort is stable, so ties keep the
// batch's order.
func (c Context) digestEntries(in DigestInput) []digestEntry {
	shares, schema, fleet, listed := summarize(in)
	entries := make([]digestEntry, 0, len(shares)+len(schema)+len(fleet)+len(listed))
	for _, share := range shares {
		l := share.line
		if in.Attributed {
			l.Spans = append(l.Spans, summaryActors(in.Changes, share.changes)...)
		}
		entries = append(entries, digestEntry{severity: share.severity, line: l})
	}
	for _, change := range schema {
		l := c.schemaLine(change)
		if in.Attributed {
			l.Spans = append(l.Spans, summaryActors(in.Changes, change.changes)...)
		}
		entries = append(entries, digestEntry{severity: change.severity(), line: l})
	}
	for _, transition := range fleet {
		l := c.fleetLine(transition)
		if in.Attributed {
			l.Spans = append(l.Spans, summaryActors(in.Changes, transition.changes)...)
		}
		entries = append(entries, digestEntry{severity: transition.severity(), line: l})
	}
	summaries := len(entries)
	for index := range listed {
		change := &listed[index]
		severity := model.Classify(*change)
		entry := digestEntry{severity: severity, change: change, line: changeLine(*change, severity)}
		if actor := knownActor(*change); in.Attributed && actor != "" {
			// "… changed by alice@example.com via admin console" on the
			// change's own line, or below it when the line would be long.
			byActor := append(entry.line.Spans, lit(" by "), txt(actor))
			if utf8.RuneCountInString(plainLine(line(byActor...))) <= maxInlineActorRunes {
				entry.line = line(byActor...)
			} else {
				actorLine := item(strong("Changed by:"), lit(" "), txt(actor))
				entry.actorLine = &actorLine
			}
		}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries[summaries:], func(i, j int) bool {
		a, b := entries[summaries+i].change, entries[summaries+j].change
		if a.Collector != b.Collector {
			return a.Collector < b.Collector
		}
		return a.Name < b.Name
	})
	sort.SliceStable(entries, func(i, j int) bool {
		return severityRank[entries[i].severity] < severityRank[entries[j].severity]
	})
	return entries
}

// changeKinds are the change kinds TailState records; any other kind is
// shown as an escaped value.
var changeKinds = map[string]bool{"created": true, "changed": true, "removed": true}

// changeLine is one listed change: its severity and kind icons, the name in
// bold, the resource type, and the kind as text, for example
// "🔴 ✏️ **web-02** (device) changed". The icons carry the severity and kind
// at a glance; the type and kind words keep the line clear in plain text and
// for screen readers.
func changeLine(change model.Change, severity model.Severity) Line {
	spans := []Span{lit(severityIcons[severity] + " " + changeIcons[change.Kind] + " "), bold(displayName(change.Collector, change.Name))}
	spans = append(spans, typeSpans(change.Collector)...)
	if changeKinds[change.Kind] {
		spans = append(spans, lit(" "+change.Kind))
	} else {
		spans = append(spans, lit(" "), txt(change.Kind))
	}
	return line(spans...)
}

// omittedEntries is the closing note for digest entries left out at the
// default budget. It names the omitted high-severity entries explicitly.
func omittedEntries(entries []digestEntry, total int) string {
	changes, summaries, high := 0, 0, 0
	for _, entry := range entries {
		if entry.change != nil {
			changes++
		} else {
			summaries++
		}
		if entry.severity == model.SeverityHigh {
			high++
		}
	}
	omitted := plural(changes, "more change", "more changes")
	if summaries > 0 {
		omitted += " and " + plural(summaries, "summary line", "summary lines")
	}
	omitted += " omitted"
	if high > 0 {
		omitted += fmt.Sprintf(", including %d high-severity", high)
	}
	return fmt.Sprintf("%s; total: %d. See TailState History for the full batch.", omitted, total)
}

// maxInlineActorRunes bounds a change line that also names its actor; a
// longer line names the actor on its own "Changed by" line instead.
const maxInlineActorRunes = 120

// maxSummaryActors bounds the actors named on one fleet or schema summary.
const maxSummaryActors = 3

// knownActor is the display text of a change's audit log actor, or "" when
// the configuration audit log had no matching entry. Notifications name only
// known actors; History, the API, and evidence packs keep "actor unknown".
func knownActor(change model.Change) string {
	if change.Attribution == nil || change.Attribution.IsZero() {
		return ""
	}
	return change.Attribution.Display()
}

// attributionHeader is the digest header line for an attributed batch:
// "Attributed: 3 of 7 changes", or "Attribution unavailable" when the audit
// log lookup failed. A batch whose lookup did not run (or is unsupported)
// has none.
func attributionHeader(in DigestInput) (Line, bool) {
	if !in.Attributed {
		return Line{}, false
	}
	if in.AttributionUnavailable {
		return line(lit("Attribution unavailable")), true
	}
	attributed := 0
	for _, change := range in.Changes {
		if knownActor(change) != "" {
			attributed++
		}
	}
	return line(lit(fmt.Sprintf("Attributed: %d of %s", attributed, plural(len(in.Changes), "change", "changes")))), true
}

// summaryActors names the known actors of the changes a fleet or schema
// summary stands for, for example " · by ci-bot [api key] (3 of 12)": at most
// maxSummaryActors distinct actors, and how many of the changes they made
// when not all of them were attributed.
func summaryActors(changes []model.Change, indices []int) []Span {
	var actors []string
	seen := map[string]bool{}
	attributed := 0
	for _, index := range indices {
		actor := knownActor(changes[index])
		if actor == "" {
			continue
		}
		attributed++
		if !seen[actor] {
			seen[actor] = true
			actors = append(actors, actor)
		}
	}
	if attributed == 0 {
		return nil
	}
	spans := []Span{lit(" · by ")}
	for index, actor := range actors {
		if index == maxSummaryActors {
			spans = append(spans, lit(fmt.Sprintf(" and %d more", len(actors)-index)))
			break
		}
		if index > 0 {
			spans = append(spans, lit(", "))
		}
		spans = append(spans, txt(actor))
	}
	if attributed < len(indices) {
		spans = append(spans, lit(fmt.Sprintf(" (%d of %d)", attributed, len(indices))))
	}
	return spans
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
	message := c.message(severityExpiry, "⏳", "Tailscale keys expiring within "+plural(windowDays, "day", "days"),
		line(strong(plural(len(lines), "resource", "resources")), lit(fmt.Sprintf(" entered the %d-day expiry warning window. Re-authenticate devices or replace auth keys before they expire.", windowDays))),
		observedLine(observedAt),
	)
	if statusURL := c.StatusURL(); statusURL != "" {
		message.Lines = append(message.Lines, line(link("Open TailState status", statusURL)))
	}
	message.Lines = append(message.Lines, blank())
	const reserve = 200 // room for the closing omission note
	size := markdownSize(message)
	for index, entry := range lines {
		spans := []Span{txt(entry.Kind), lit(" "), bold(shortDeviceName(entry.Name))}
		if len(entry.Tags) > 0 {
			spans = append(spans, lit(" ("), code(strings.Join(entry.Tags, ", ")), lit(")"))
		}
		spans = append(spans, lit(" expires "+compactTime(entry.Expires)+" ("+plural(entry.DaysLeft, "day", "days")+" left)"))
		l := item(spans...)
		rendered := len(markdownLine(l)) + 1
		if size+rendered > digestBudget-reserve {
			message.Lines = append(message.Lines, blank(), line(emph(fmt.Sprintf("%s omitted; total: %d. See the TailState status page for the full list.", plural(len(lines)-index, "more resource", "more resources"), len(lines)))))
			break
		}
		message.Lines = append(message.Lines, l)
		size += rendered
	}
	return message
}

// markdownInline escapes the characters that can change the meaning of text
// in an inline Markdown position: the emphasis delimiters * and _, the link
// delimiters [ and ], the code and HTML characters ` and <, the backslash
// itself, and ~ and | for the strike-through and table extensions. Other
// punctuation (# + - > ! digits) only has meaning at the start of a line or
// right after a ], and a tenant value never starts a line: every title and
// line begins with trusted text written by TailState.
var markdownInline = strings.NewReplacer(
	"\\", "\\\\",
	"*", "\\*",
	"_", "\\_",
	"[", "\\[",
	"]", "\\]",
	"`", "\\`",
	"<", "\\<",
	"~", "\\~",
	"|", "\\|",
)

// escape makes value inert in bold and prose Markdown contexts, so names,
// e-mail addresses, and labels keep their hyphens, dots, and parentheses
// without backslashes. Control characters become spaces, and the value is
// bounded before it is escaped, so an escape is never cut in half. It must
// not be used inside a code span: CommonMark does not process backslash
// escapes there, so every escape would be shown literally. Use escapeCode
// instead.
func escape(value string) string {
	return markdownInline.Replace(truncate(stripControl(value), 256))
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

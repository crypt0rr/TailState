package notify

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// serviceMessageLimits are the per-message size budgets, in bytes, that the
// pinned Shoutrrr services (or their providers) accept. Shoutrrr rejects an
// oversized Telegram, Lark, WeCom, or Zulip message before sending it, and
// providers such as Pushover reject long bodies; without fitting, a large
// digest would be retried for 24 hours and then dead-lettered.
var serviceMessageLimits = map[string]int{
	"telegram":   4096,
	"lark":       4096,
	"wecom":      4096,
	"ntfy":       4096,
	"rocketchat": 5000,
	"discord":    6000, // sent as embeds of at most 2000 characters, 6000 in total
	"zulip":      10000,
	"pushover":   1024,
	"mattermost": 16383,
}

// MessageLimit returns the message budget for a Shoutrrr service URL. Unknown
// services use the default digest budget.
func MessageLimit(serviceURL string) int {
	scheme, _, found := strings.Cut(strings.TrimSpace(serviceURL), "://")
	if !found {
		return digestBudget
	}
	scheme = strings.ToLower(scheme)
	if base, _, ok := strings.Cut(scheme, "+"); ok {
		scheme = base
	}
	if limit, ok := serviceMessageLimits[scheme]; ok {
		return limit
	}
	return digestBudget
}

const (
	shortenedNoteFormat      = "\n_Shortened for this destination: %d more line(s) omitted. See TailState History for the full batch._"
	shortenedPlainNoteFormat = "\nShortened for this destination: %d more line(s) omitted. See TailState History for the full batch."
)

// FitMessage shortens a Markdown message to at most limit bytes. It removes
// whole lines from the end so Markdown spans are never cut in half, and
// appends an explicit note saying how many lines were omitted. A single first
// line that is longer than the limit is truncated at a UTF-8 boundary.
func FitMessage(message string, limit int) string {
	return FitMessageFor(message, limit, FormatMarkdown)
}

// FitMessageFor is FitMessage with the omission note written in the given
// format, so plain-text destinations never receive Markdown emphasis.
func FitMessageFor(message string, limit int, format string) string {
	if limit <= 0 || len(message) <= limit {
		return message
	}
	noteFormat := shortenedNoteFormat
	if format == FormatPlain {
		noteFormat = shortenedPlainNoteFormat
	}
	lines := strings.SplitAfter(message, "\n")
	for kept := len(lines) - 1; kept >= 1; kept-- {
		note := fmt.Sprintf(noteFormat, countLines(lines[kept:]))
		body := strings.TrimRight(strings.Join(lines[:kept], ""), "\n")
		if len(body)+len(note) <= limit {
			return body + note
		}
	}
	return truncateBytes(lines[0], limit)
}

func countLines(lines []string) int {
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func truncateBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

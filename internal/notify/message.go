package notify

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

// Message is a format-neutral notification. Spans carry a style instead of
// pre-rendered markup, so one message can be rendered for each destination's
// service (see the renderers) without re-escaping untrusted values.
//
// Text is the escape hatch for a pre-rendered Markdown payload: a message
// whose Text is set is delivered exactly as written and its other fields are
// ignored.
type Message struct {
	Icon  string `json:"icon,omitempty"`
	Title string `json:"title,omitempty"`
	// Scope identifies the instance and tailnet and is appended to the title.
	Scope string `json:"scope,omitempty"`
	Lines []Line `json:"lines,omitempty"`
	Text  string `json:"text,omitempty"`
	// Severity is "high", "medium", or "low": the highest severity of a
	// digest, or the fixed level of a system notification. It selects the
	// destination's priority, tags, or colour (see severityParams).
	Severity string `json:"severity,omitempty"`
}

// Fixed severities of system notifications: collector failures and
// configuration changes are urgent, expiry warnings are not yet, and
// recoveries, release notices, and the Settings test are routine.
const (
	severityUnhealthy   = model.SeverityHigh
	severityAdminChange = model.SeverityHigh
	severityExpiry      = model.SeverityMedium
	severityRecovered   = model.SeverityLow
	severityUpdate      = model.SeverityLow
	severityTest        = model.SeverityLow
)

// Line kinds. A plain line is a paragraph line, an item is a bulleted detail
// below the previous line, and a note is an indented, emphasised remark. A
// context line is rendered like a plain line, but trailing context lines are
// kept when a message is shortened for a destination (see PrepareMessage).
const (
	LinePlain   = ""
	LineItem    = "item"
	LineNote    = "note"
	LineContext = "context"
)

// Line is one rendered line. Every line is complete on its own in every
// format, so a message is only ever shortened at line boundaries.
type Line struct {
	Kind  string `json:"kind,omitempty"`
	Spans []Span `json:"spans,omitempty"`
}

// Span styles. Literal and emphasis spans are trusted text written by
// TailState itself; text, bold, and code spans may contain tenant-controlled
// values and are always escaped by the renderer. Link URLs are built only from
// the validated public URL.
const (
	SpanLiteral = "lit"
	SpanText    = "text"
	SpanBold    = "bold"
	SpanCode    = "code"
	SpanEmph    = "em"
	SpanLink    = "link"
	// SpanStrong is trusted bold text such as a field label.
	SpanStrong = "strong"
)

// Span is a styled run of text within a line.
type Span struct {
	Style string `json:"s"`
	Text  string `json:"t"`
	URL   string `json:"u,omitempty"`
}

// Text returns a message that is delivered as the given pre-rendered
// Markdown, unchanged by any renderer.
func Text(markdown string) Message { return Message{Text: markdown} }

// IsText reports whether the message is a pre-rendered Markdown payload.
func (m Message) IsText() bool { return m.Text != "" || (m.Title == "" && len(m.Lines) == 0) }

func lit(text string) Span      { return Span{Style: SpanLiteral, Text: text} }
func txt(text string) Span      { return Span{Style: SpanText, Text: text} }
func bold(text string) Span     { return Span{Style: SpanBold, Text: text} }
func code(text string) Span     { return Span{Style: SpanCode, Text: text} }
func strong(text string) Span   { return Span{Style: SpanStrong, Text: text} }
func emph(text string) Span     { return Span{Style: SpanEmph, Text: text} }
func link(label, u string) Span { return Span{Style: SpanLink, Text: label, URL: u} }
func line(spans ...Span) Line   { return Line{Spans: spans} }
func item(spans ...Span) Line   { return Line{Kind: LineItem, Spans: spans} }
func note(text string) Line     { return Line{Kind: LineNote, Spans: []Span{emph(text)}} }
func blank() Line               { return Line{} }
func observedLine(at time.Time) Line {
	return line(lit("Observed at "), lit(compactTime(at)))
}

// compactTimeLayout is the notification time format, for example
// "6 Oct 2026 09:14 UTC". History and the API keep full RFC 3339 times.
const compactTimeLayout = "2 Jan 2006 15:04 UTC"

func compactTime(at time.Time) string { return at.UTC().Format(compactTimeLayout) }

// plural returns "1 change" or "3 changes".
func plural(count int, singular, pluralForm string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, pluralForm)
}

// Context is the instance identity added to every notification: the
// optional operator-chosen instance label, the monitored tailnet, the
// optional public URL used for links, and the running TailState version.
type Context struct {
	Label     string
	Tailnet   string
	PublicURL string
	Version   string
}

// TailnetDisplay is the tailnet as shown to operators. "-" (the OAuth
// credential's own tailnet) is spelled out.
func (c Context) TailnetDisplay() string {
	tailnet := strings.TrimSpace(c.Tailnet)
	if tailnet == "" || tailnet == "-" {
		return "default tailnet"
	}
	return tailnet
}

// Scope is the identity shown in every message title: the tailnet, prefixed
// by the instance label when one is configured.
func (c Context) Scope() string {
	if label := strings.TrimSpace(c.Label); label != "" {
		return label + " (" + c.TailnetDisplay() + ")"
	}
	return c.TailnetDisplay()
}

// HistoryBatchURL returns the History link for one batch, or "" when no
// public URL is configured.
func (c Context) HistoryBatchURL(batchID int64) string {
	if c.PublicURL == "" || batchID <= 0 {
		return ""
	}
	return c.PublicURL + "/history?batch=" + fmt.Sprint(batchID)
}

// StatusURL returns the Status page link, or "" when no public URL is
// configured.
func (c Context) StatusURL() string {
	if c.PublicURL == "" {
		return ""
	}
	return c.PublicURL + "/status"
}

// publicPathPattern restricts the public URL path to characters that are
// inert in every renderer's link syntax (no parentheses, pipes, brackets,
// angle brackets, quotes, or whitespace).
var (
	publicPathPattern = regexp.MustCompile(`^[A-Za-z0-9._~/-]*$`)
	publicHostPattern = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$`)
)

// ValidatePublicURL checks an operator-supplied public base URL and returns
// it without a trailing slash. Only absolute https URLs with a host and an
// optional plain path are accepted: credentials, queries, fragments, and
// characters that could break out of a link are rejected.
func ValidatePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 512 {
		return "", fmt.Errorf("public URL must be at most 512 bytes")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("public URL must be an absolute https URL with a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", fmt.Errorf("public URL must not contain credentials, a query, or a fragment")
	}
	if !publicHostPattern.MatchString(parsed.Host) {
		return "", fmt.Errorf("public URL host is invalid")
	}
	if !publicPathPattern.MatchString(parsed.Path) || parsed.RawPath != "" {
		return "", fmt.Errorf("public URL path may contain only letters, digits, and . _ ~ / -")
	}
	return strings.TrimRight(parsed.Scheme+"://"+parsed.Host+parsed.Path, "/"), nil
}

// ValidateInstanceLabel checks the optional instance label: at most 64 bytes
// of printable text.
func ValidateInstanceLabel(raw string) (string, error) {
	label := strings.TrimSpace(raw)
	if len(label) > 64 {
		return "", fmt.Errorf("instance label must be at most 64 bytes")
	}
	if stripControl(label) != label {
		return "", fmt.Errorf("instance label must not contain control characters")
	}
	return label, nil
}

func (c Context) message(severity model.Severity, icon, title string, lines ...Line) Message {
	return Message{Icon: icon, Title: title, Scope: c.Scope(), Lines: lines, Severity: string(severity)}
}

// CollectorHealth is one collector transition reported in a grouped health
// message. Reason is a bounded category, never upstream error text.
type CollectorHealth struct {
	Collector string
	Reason    string
}

// CollectorsUnhealthy groups every collector that crossed the failure
// threshold in one poll into a single message.
func (c Context) CollectorsUnhealthy(collectors []CollectorHealth, observedAt time.Time) Message {
	title := "Tailscale API collector unhealthy"
	summary := "1 collector failed three consecutive polls. TailState will keep retrying."
	if len(collectors) != 1 {
		title = "Tailscale API collectors unhealthy"
		summary = fmt.Sprintf("%d collectors failed three consecutive polls. TailState will keep retrying.", len(collectors))
	}
	lines := []Line{line(lit(summary))}
	for _, collector := range collectors {
		reason := strings.TrimSpace(collector.Reason)
		if reason == "" {
			reason = "request failed"
		}
		lines = append(lines, item(code(collector.Collector), lit(": "), txt(reason)))
	}
	lines = append(lines, observedLine(observedAt))
	if statusURL := c.StatusURL(); statusURL != "" {
		lines = append(lines, line(link("Open TailState status", statusURL)))
	}
	return c.message(severityUnhealthy, "⚠️", title, lines...)
}

// CollectorsRecovered groups every collector that recovered in one poll into
// a single message.
func (c Context) CollectorsRecovered(collectors []string, observedAt time.Time) Message {
	title := "Tailscale API collector recovered"
	summary := "1 collector is responding successfully again."
	if len(collectors) != 1 {
		title = "Tailscale API collectors recovered"
		summary = fmt.Sprintf("%d collectors are responding successfully again.", len(collectors))
	}
	lines := []Line{line(lit(summary))}
	for _, collector := range collectors {
		lines = append(lines, item(code(collector)))
	}
	lines = append(lines, observedLine(observedAt))
	if statusURL := c.StatusURL(); statusURL != "" {
		lines = append(lines, line(link("Open TailState status", statusURL)))
	}
	return c.message(severityRecovered, "✅", title, lines...)
}

// Update reports that a different TailState release started.
func (c Context) Update(previous, current string, observedAt time.Time) Message {
	return c.message(severityUpdate, "🚀", "TailState updated",
		line(strong("Previous version:"), lit(" "), code(previous)),
		line(strong("Current version:"), lit(" "), code(current)),
		observedLine(observedAt),
	)
}

// SettingsURL returns the Settings page link, or "" when no public URL is
// configured.
func (c Context) SettingsURL() string {
	if c.PublicURL == "" {
		return ""
	}
	return c.PublicURL + "/settings"
}

// AdminChange reports a security-relevant change to TailState's own
// configuration. It names the action, the changed field names (never their
// values), the affected object, and the client address the request came
// from, so a change made with a stolen session is visible to the
// destinations that were active before it.
func (c Context) AdminChange(action string, fields []string, target, client string, observedAt time.Time) Message {
	lines := []Line{line(strong("Action:"), lit(" "), txt(action))}
	if len(fields) > 0 {
		spans := []Span{strong("Changed:"), lit(" ")}
		for index, field := range fields {
			if index > 0 {
				spans = append(spans, lit(", "))
			}
			spans = append(spans, code(field))
		}
		lines = append(lines, line(spans...))
	}
	if target != "" {
		lines = append(lines, line(strong("Object:"), lit(" "), code(target)))
	}
	if client != "" {
		lines = append(lines, line(strong("Client:"), lit(" "), code(client)))
	}
	lines = append(lines, observedLine(observedAt), line(emph("If you did not make this change, sign in, review Recent administrative activity in Settings, and change the administrator password.")))
	if settingsURL := c.SettingsURL(); settingsURL != "" {
		lines = append(lines, line(link("Open TailState settings", settingsURL)))
	}
	return c.message(severityAdminChange, "🔐", "TailState configuration changed", lines...)
}

// Test is the message sent by the Settings "Send test" action. It names the
// instance, tailnet, and version so an operator can confirm which TailState
// sent it.
func (c Context) Test(observedAt time.Time) Message {
	lines := []Line{line(strong("TailState test:"), lit(" notifications are configured correctly."))}
	if label := strings.TrimSpace(c.Label); label != "" {
		lines = append(lines, line(strong("Instance:"), lit(" "), txt(label)))
	}
	lines = append(lines, line(strong("Tailnet:"), lit(" "), txt(c.TailnetDisplay())))
	version := strings.TrimSpace(c.Version)
	if version == "" {
		version = "unknown"
	}
	lines = append(lines, line(strong("Version:"), lit(" "), code(version)), observedLine(observedAt))
	return c.message(severityTest, "🧪", "TailState test", lines...)
}

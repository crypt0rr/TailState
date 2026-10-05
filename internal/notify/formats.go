package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Message formats a destination can receive.
const (
	// FormatAuto selects the format from the destination's URL scheme.
	FormatAuto = ""
	// FormatMarkdown is CommonMark, the format TailState always sent.
	FormatMarkdown = "markdown"
	// FormatSlack is Slack mrkdwn (also understood by Google Chat).
	FormatSlack = "slack"
	// FormatPlain is plain text without any markup.
	FormatPlain = "plain"
)

// Formats lists the explicit per-destination format overrides.
var Formats = []string{FormatMarkdown, FormatSlack, FormatPlain}

// Stored outbox payload kinds. Rows written before schema v14 hold
// pre-rendered Markdown and keep being delivered exactly as stored.
const (
	PayloadMarkdown = "markdown"
	PayloadMessage  = "message"
)

// schemeFormats maps Shoutrrr schemes to the format the service renders.
// Services not listed receive Markdown, the historical default.
var schemeFormats = map[string]string{
	"slack":      FormatSlack,
	"googlechat": FormatSlack,
	"mattermost": FormatMarkdown,
	"discord":    FormatMarkdown,
	"rocketchat": FormatMarkdown,
	"zulip":      FormatMarkdown,
	"teams":      FormatMarkdown,
	"generic":    FormatMarkdown,
	"telegram":   FormatPlain,
	"smtp":       FormatPlain,
	"pushover":   FormatPlain,
	"matrix":     FormatPlain,
	"ntfy":       FormatPlain,
	"gotify":     FormatPlain,
	"signal":     FormatPlain,
	"bark":       FormatPlain,
	"join":       FormatPlain,
	"lark":       FormatPlain,
	"wecom":      FormatPlain,
	"pushbullet": FormatPlain,
	"ifttt":      FormatPlain,
	"opsgenie":   FormatPlain,
	"pagerduty":  FormatPlain,
	"mqtt":       FormatPlain,
	"twilio":     FormatPlain,
	"xmpp":       FormatPlain,
	"signalgrid": FormatPlain,
	"hass":       FormatPlain,
}

// ValidateFormat accepts an explicit format override or FormatAuto.
func ValidateFormat(format string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case FormatAuto, FormatMarkdown, FormatSlack, FormatPlain:
		return format, nil
	}
	return "", fmt.Errorf("unknown message format %q", format)
}

// FormatFor returns the format used for a destination: the override when
// one is set, otherwise the format of the URL's service.
func FormatFor(serviceURL, override string) string {
	if format, err := ValidateFormat(override); err == nil && format != FormatAuto {
		return format
	}
	scheme, _, found := strings.Cut(strings.TrimSpace(serviceURL), "://")
	if !found {
		return FormatMarkdown
	}
	scheme = strings.ToLower(scheme)
	if base, _, ok := strings.Cut(scheme, "+"); ok {
		scheme = base
	}
	if format, ok := schemeFormats[scheme]; ok {
		return format
	}
	return FormatMarkdown
}

// Render renders a message in one format. A pre-rendered Text message is
// returned unchanged in every format.
func Render(m Message, format string) string {
	switch format {
	case FormatSlack:
		return Slack(m)
	case FormatPlain:
		return Plain(m)
	default:
		return Markdown(m)
	}
}

// EncodePayload converts a message into its stored outbox form. Pre-rendered
// Text is stored as Markdown; structured messages are stored as JSON so they
// can be rendered for each destination at send time.
func EncodePayload(m Message) (string, string, error) {
	if m.IsText() {
		return PayloadMarkdown, m.Text, nil
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", "", err
	}
	return PayloadMessage, string(encoded), nil
}

// ErrInvalidPayload reports a stored outbox payload that cannot be decoded.
var ErrInvalidPayload = errors.New("stored notification payload is invalid")

// Prepare renders a stored outbox payload for one destination and fits it to
// the destination's message budget, so rendering and fitting happen in one
// place. Legacy Markdown rows are returned unchanged.
func Prepare(payloadFormat, payload, serviceURL, override string) (string, error) {
	switch payloadFormat {
	case "", PayloadMarkdown:
		return payload, nil
	case PayloadMessage:
	default:
		return "", ErrInvalidPayload
	}
	var message Message
	if err := json.Unmarshal([]byte(payload), &message); err != nil {
		return "", ErrInvalidPayload
	}
	format := FormatFor(serviceURL, override)
	return FitMessageFor(Render(message, format), MessageLimit(serviceURL), format), nil
}

// Slack renders a message as Slack mrkdwn: single-asterisk bold, no
// headings, <url|label> links, and &, <, > escaped so a value cannot create
// a mention or link.
func Slack(m Message) string {
	if m.IsText() {
		return m.Text
	}
	var b strings.Builder
	title := escapeSlack(titleText(m), false)
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + escapeSlack(scope, true)
	}
	b.WriteString("*" + title + "*")
	for _, l := range m.Lines {
		b.WriteByte('\n')
		switch l.Kind {
		case LineItem:
			b.WriteString("    • ")
		case LineNote:
			b.WriteString("    ")
		}
		for _, span := range l.Spans {
			switch span.Style {
			case SpanLiteral:
				b.WriteString(escapeSlack(span.Text, false))
			case SpanBold:
				b.WriteString("*" + escapeSlack(span.Text, true) + "*")
			case SpanStrong:
				b.WriteString("*" + escapeSlack(span.Text, false) + "*")
			case SpanCode:
				b.WriteString("`" + truncate(strings.ReplaceAll(escapeSlack(span.Text, false), "`", "'"), 256) + "`")
			case SpanEmph:
				b.WriteString("_" + escapeSlack(span.Text, false) + "_")
			case SpanLink:
				if safeLinkURL(span.URL) {
					b.WriteString("<" + span.URL + "|" + escapeSlack(span.Text, true) + ">")
				} else {
					b.WriteString(escapeSlack(span.Text, true))
				}
			default:
				b.WriteString(escapeSlack(span.Text, true))
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// escapeSlack applies Slack's required entity escaping. Untrusted values
// additionally lose the characters that open or close bold, strike, and code
// formatting, so they cannot restyle the rest of the line.
func escapeSlack(value string, untrusted bool) string {
	value = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(stripControl(value))
	if untrusted {
		value = strings.NewReplacer("*", "∗", "~", "∼", "`", "'").Replace(value)
		value = truncate(value, 256)
	}
	return value
}

// Plain renders a message as plain text without any markup, for services
// that show text verbatim (email, SMS, push, Matrix, Telegram by default).
func Plain(m Message) string {
	if m.IsText() {
		return m.Text
	}
	var b strings.Builder
	b.WriteString(stripControl(titleText(m)))
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		b.WriteString(" · " + truncate(stripControl(scope), 256))
	}
	for _, l := range m.Lines {
		b.WriteByte('\n')
		switch l.Kind {
		case LineItem:
			b.WriteString("  • ")
		case LineNote:
			b.WriteString("  ")
		}
		for _, span := range l.Spans {
			text := stripControl(span.Text)
			switch span.Style {
			case SpanLiteral, SpanStrong, SpanEmph:
				b.WriteString(text)
			case SpanLink:
				if safeLinkURL(span.URL) {
					b.WriteString(text + ": " + span.URL)
				} else {
					b.WriteString(truncate(text, 256))
				}
			default:
				b.WriteString(truncate(text, 256))
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

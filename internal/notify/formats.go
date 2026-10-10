package notify

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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
	// FormatTeams is the Markdown subset of Microsoft Teams Adaptive Card
	// text blocks: no headings or code spans, **bold**, - lists, and links.
	FormatTeams = "teams"
	// FormatHTML is Telegram's HTML subset (<b>, <i>, <code>, <a href>).
	FormatHTML = "html"
)

// Formats lists the explicit per-destination format overrides.
var Formats = []string{FormatMarkdown, FormatSlack, FormatPlain, FormatTeams, FormatHTML}

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
	"teams":      FormatTeams,
	"generic":    FormatMarkdown,
	"telegram":   FormatHTML,
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
	case FormatAuto, FormatMarkdown, FormatSlack, FormatPlain, FormatTeams, FormatHTML:
		return format, nil
	}
	return "", fmt.Errorf("unknown message format %q", format)
}

// FormatFor returns the format used for a destination: the override when
// one is set, otherwise the format of the URL's service. An ntfy URL with
// markdown=yes always receives Markdown, the only rendering that escapes
// values for a Markdown display.
func FormatFor(serviceURL, override string) string {
	if destination := parseDestination(serviceURL); destination.scheme == "ntfy" && truthy(destination.query[paramMarkdown]) {
		return FormatMarkdown
	}
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

// flavourFor returns the renderer of a format; unknown formats render as
// Markdown, the historical default.
func flavourFor(format string) flavour {
	switch format {
	case FormatSlack:
		return slackFlavour
	case FormatPlain:
		return plainFlavour
	case FormatTeams:
		return teamsFlavour
	case FormatHTML:
		return htmlFlavour
	default:
		return markdownFlavour
	}
}

// Render renders a message in one format. A pre-rendered Text message is
// returned unchanged in every format.
func Render(m Message, format string) string {
	return flavourFor(format).render(m)
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

// Prepared is one notification rendered and fitted for one destination.
type Prepared struct {
	// Text is the complete message, title line included, fitted to the
	// destination's budget. It is what a sender without title support
	// receives, and it is the whole payload of a legacy row.
	Text string
	// Title is the plain-text title when the destination receives it as a
	// separate field (see serviceParams), otherwise "".
	Title string
	// Body is the message without its title line, fitted to the budget left
	// after the title. It is set exactly when Title is.
	Body string
	// Format is the rendering format of Text and Body.
	Format string
	// Severity is the message's severity ("high", "medium", or "low"),
	// mapped to the destination's priority, tags, or colour (see
	// severityParams). It is "" for a legacy row, which gets none.
	Severity string
}

// Message returns what is sent as the message body: Body when the title is
// sent separately, otherwise Text.
func (p Prepared) Message() string {
	if p.Title != "" {
		return p.Body
	}
	return p.Text
}

// Prepare renders a stored outbox payload for one destination and fits it to
// the destination's message budget, so rendering and fitting happen in one
// place. Legacy Markdown rows are returned unchanged. It returns the complete
// message including its title line; see PrepareFor for the form senders use.
func Prepare(payloadFormat, payload, serviceURL, override string) (string, error) {
	prepared, err := PrepareFor(payloadFormat, payload, serviceURL, override)
	return prepared.Text, err
}

// PrepareFor renders a stored outbox payload for one destination. Legacy
// Markdown rows are delivered exactly as stored, without a separate title.
func PrepareFor(payloadFormat, payload, serviceURL, override string) (Prepared, error) {
	switch payloadFormat {
	case "", PayloadMarkdown:
		return Prepared{Text: payload, Format: FormatMarkdown}, nil
	case PayloadMessage:
	default:
		return Prepared{}, ErrInvalidPayload
	}
	var message Message
	if err := json.Unmarshal([]byte(payload), &message); err != nil {
		return Prepared{}, ErrInvalidPayload
	}
	return PrepareMessage(message, serviceURL, override), nil
}

// PrepareMessage renders a message for one destination: in the destination's
// format, fitted to its budget, and with the title split from the body when
// the destination receives the title as a separate field. A digest's
// trailing context line (time, muted count, History link) is kept when the
// message is shortened: change lines are dropped before it.
func PrepareMessage(message Message, serviceURL, override string) Prepared {
	format := FormatFor(serviceURL, override)
	limit := MessageLimit(serviceURL)
	render := flavourFor(format)
	destination := parseDestination(serviceURL)
	htmlBody, lineBreaks := false, false
	switch {
	case destination.scheme == "telegram" && destination.operatorSet([]string{paramParseMode}):
		// Telegram's Markdown modes reject unescaped reserved characters,
		// which every value may contain, so a parse mode set in the URL is
		// replaced with HTML (see params).
		noteParseModeOverride(serviceURL, destination.query[paramParseMode])
		htmlBody = true
	case destination.scheme == "smtp" && truthy(destination.query[paramUseHTML]):
		// Shoutrrr writes the body into the e-mail's HTML part as it is.
		htmlBody, lineBreaks = true, true
	case destination.scheme == "ntfy" && truthy(destination.query[paramMarkdown]):
		// FormatFor selected Markdown. ntfy's Markdown display joins
		// consecutive lines into one paragraph unless each ends in a hard
		// line break.
		render = render.hardBreaks()
	}
	if htmlBody && format != FormatHTML {
		// The destination displays HTML, but its format is another one:
		// escape the rendering so its text is shown as written and a value
		// cannot add markup.
		render = render.htmlEscaped()
		format = FormatHTML
	}
	head, context := splitContext(message)
	rendered := render.render(head)
	footer := ""
	if len(context) > 0 {
		footer = render.lines(context)
	}
	shorten := func(text string, limit int) string {
		if footer == "" {
			return FitMessageFor(text, limit, format)
		}
		if whole := text + "\n" + footer; len(whole) <= limit || limit <= 0 {
			return whole
		}
		if room := limit - len(footer) - 1; room > len(footer) {
			return FitMessageFor(text, room, format) + "\n" + footer
		}
		return FitMessageFor(text+"\n"+footer, limit, format)
	}
	fit := func(text string, limit int) string {
		text = shorten(text, limit)
		if lineBreaks {
			// An HTML e-mail collapses line breaks. E-mail has no provider
			// size limit, so the bytes added after fitting are harmless.
			text = strings.ReplaceAll(text, "\n", "<br>\n")
		}
		return text
	}
	prepared := Prepared{Text: fit(rendered, limit), Format: format, Severity: message.Severity}
	if message.IsText() || !destination.sendsTitleSeparately() {
		return prepared
	}
	title := plainTitle(message)
	// Every renderer writes the title as the first line, and a title never
	// contains a line break (control characters become spaces).
	_, body, _ := strings.Cut(rendered, "\n")
	body = strings.TrimLeft(body, "\n")
	if title == "" || strings.TrimSpace(body) == "" {
		return prepared
	}
	// Discord counts embed titles and Telegram counts the title line
	// against the same limit as the body, so the title's size is reserved
	// for every service.
	prepared.Title = title
	prepared.Body = fit(body, limit-len(title)-1)
	return prepared
}

// parseModeNotices holds a hash of every Telegram destination URL whose
// parse mode was reported as overridden, so the notice is logged once per
// destination and process instead of on every send.
var parseModeNotices sync.Map

// noteParseModeOverride logs, once per destination, that a parse mode set in
// a Telegram URL is replaced with HTML. HTML is TailState's own mode and needs
// no notice. Only a known mode name is logged, never other URL text.
func noteParseModeOverride(serviceURL, mode string) {
	if strings.EqualFold(mode, parseModeHTML) {
		return
	}
	if _, seen := parseModeNotices.LoadOrStore(sha256.Sum256([]byte(strings.TrimSpace(serviceURL))), struct{}{}); seen {
		return
	}
	logged := "other"
	for _, known := range []string{"None", "Markdown", "MarkdownV2"} {
		if strings.EqualFold(mode, known) {
			logged = known
		}
	}
	slog.Info("Telegram destination URL sets a parse mode; TailState overrides it with HTML and sends its escaped HTML rendering", "destination", RedactURL(serviceURL), "parse_mode", logged)
}

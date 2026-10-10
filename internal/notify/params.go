package notify

import (
	"mime"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/nicholas-fedor/shoutrrr/pkg/format"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"

	"github.com/crypt0rr/tailstate/internal/model"
)

// Shoutrrr parameters TailState may set when it sends a message.
const (
	paramTitle      = "title"
	paramSplitLines = "splitlines"
	paramPriority   = "priority"
	paramTags       = "tags"
	paramColor      = "color"
	paramParseMode  = "parsemode"

	// Shoutrrr URL options TailState reads but never passes: an SMTP URL's
	// HTML body and an ntfy URL's Markdown display.
	paramUseHTML  = "usehtml"
	paramMarkdown = "markdown"

	// parseModeHTML is the Telegram parse mode of the HTML rendering.
	parseModeHTML = "HTML"
)

// serviceParams is the per-service allowlist of Shoutrrr config keys
// TailState passes with a message, derived from the pinned Shoutrrr release
// (v0.21.3-0.20261007063105-f3d2cba35d35). Shoutrrr fails a send when a
// parameter is not a config key of the service, so nothing outside this list
// is ever passed, and
// TestServiceParamAllowlistMatchesShoutrrrKeys fails when a dependency update
// drops or renames a listed key.
//
// Each parameter lists every key that sets the same config field, primary key
// first: TailState passes the first key, and a destination URL whose query
// sets any of them keeps the operator's value. Services that are not listed
// (for example Google Chat, Rocket.Chat, WeCom, and PagerDuty, which have no
// title key) receive no parameters, and their messages keep the title as the
// first line of the body. Mattermost, Matrix, and Zulip have a title key but
// are deliberately not listed: Mattermost and Matrix only prepend it to the
// body as unformatted text, and Zulip uses it as the stream topic. Opsgenie
// is listed for its priority only (see severityParams).
var serviceParams = map[string]map[string][]string{
	"discord":    {paramTitle: {"title"}, paramSplitLines: {"splitlines"}, paramColor: {"color"}},
	"gotify":     {paramTitle: {"title"}, paramPriority: {"priority"}},
	"ntfy":       {paramTitle: {"title"}, paramPriority: {"priority"}, paramTags: {"tags"}},
	"opsgenie":   {paramPriority: {"priority"}},
	"pushbullet": {paramTitle: {"title"}},
	"pushover":   {paramTitle: {"title"}, paramPriority: {"priority"}},
	"slack":      {paramTitle: {"title"}, paramColor: {"color"}},
	"smtp":       {paramTitle: {"subject", "title"}},
	"teams":      {paramTitle: {"title"}, paramColor: {"color"}},
	"telegram":   {paramTitle: {"title"}, paramParseMode: {"parsemode"}},
}

// severityParams maps a message's severity (the highest severity of a
// digest, or the fixed level of a system notification) to provider
// priority, tags, and colour. Every parameter is on the service's
// allowlist, so a value set in the destination URL wins. No mapping uses a
// priority that needs acknowledgement, such as Pushover's emergency 2.
// Slack is sent natively: its colour is applied to the payload's
// attachment (see slackPayloadFor).
var severityParams = map[string]map[string]map[model.Severity]string{
	"ntfy": {
		paramPriority: {model.SeverityHigh: "4", model.SeverityMedium: "3", model.SeverityLow: "2"},
		paramTags:     {model.SeverityHigh: "rotating_light", model.SeverityMedium: "warning", model.SeverityLow: "information_source"},
	},
	"pushover": {paramPriority: {model.SeverityHigh: "1", model.SeverityMedium: "0", model.SeverityLow: "-1"}},
	"gotify":   {paramPriority: {model.SeverityHigh: "8", model.SeverityMedium: "5", model.SeverityLow: "2"}},
	"opsgenie": {paramPriority: {model.SeverityHigh: "P2", model.SeverityMedium: "P3", model.SeverityLow: "P5"}},
	"discord":  {paramColor: {model.SeverityHigh: "0xd60510", model.SeverityMedium: "0xff8c00", model.SeverityLow: "0x95a5a6"}},
	"slack":    {paramColor: {model.SeverityHigh: "#d60510", model.SeverityMedium: "#ff8c00", model.SeverityLow: "#95a5a6"}},
	"teams":    {paramColor: {model.SeverityHigh: "attention", model.SeverityMedium: "warning", model.SeverityLow: "default"}},
}

// severityParam returns the value TailState passes for a severity-mapped
// parameter, or "" when the service has no mapping, the severity is unknown
// (a legacy row), or the destination URL sets the parameter itself.
func (d destination) severityParam(param, severity string) string {
	if d.paramKey(param) == "" {
		return ""
	}
	return severityParams[d.scheme][param][model.Severity(severity)]
}

// serviceDefaults are fixed parameter values TailState passes unless the
// destination URL sets the parameter itself.
//
// Discord defaults to splitlines=yes in Shoutrrr. TailState sends whole-line
// embeds by default and preserves an operator's explicit splitlines setting.
var serviceDefaults = map[string]map[string]string{
	"discord": {paramSplitLines: "no"},
}

// maxTitleBytes bounds a title passed as a parameter. It stays below the
// smallest provider title limit TailState sends to (Pushover's 250
// characters, Discord's 256-character embed title).
const maxTitleBytes = 200

// destination is the parsed part of a destination URL that decides which
// parameters TailState may pass. It never leaves this package and is never
// logged.
type destination struct {
	scheme string
	query  map[string]string
}

func parseDestination(serviceURL string) destination {
	parsed, err := url.Parse(strings.TrimSpace(serviceURL))
	if err != nil {
		return destination{}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if base, _, ok := strings.Cut(scheme, "+"); ok {
		scheme = base
	}
	query := map[string]string{}
	for key, values := range parsed.Query() {
		value := ""
		if len(values) > 0 {
			value = values[0]
		}
		query[strings.ToLower(key)] = value
	}
	return destination{scheme: scheme, query: query}
}

// operatorSet reports whether the destination URL sets any of keys.
func (d destination) operatorSet(keys []string) bool {
	for _, key := range keys {
		if _, ok := d.query[key]; ok {
			return true
		}
	}
	return false
}

// paramKey returns the Shoutrrr key TailState passes for a parameter, or ""
// when the service does not accept it or the operator already set it in the
// destination URL.
func (d destination) paramKey(param string) string {
	keys := serviceParams[d.scheme][param]
	if len(keys) == 0 || d.operatorSet(keys) {
		return ""
	}
	return keys[0]
}

// sendsTitleSeparately reports whether TailState passes the message title as
// a parameter to this destination, so the body must not repeat it.
func (d destination) sendsTitleSeparately() bool {
	if d.paramKey(paramTitle) == "" {
		return false
	}
	// Shoutrrr shows a Telegram title only in its HTML parse mode, which
	// every Telegram message uses: TailState passes it with its HTML
	// rendering and in place of any parse mode the URL sets, and Shoutrrr
	// selects it (escaping a plain body) when no parse mode is set.
	if d.scheme == "discord" {
		// In JSON mode Discord sends the body as a raw payload and ignores
		// every parameter.
		return !truthy(d.query["json"])
	}
	return true
}

// truthy parses a boolean query value the way Shoutrrr does.
func truthy(value string) bool {
	enabled, _ := format.ParseBool(strings.TrimSpace(value), false)
	return enabled
}

// params returns the Shoutrrr parameters for one send, or nil when the
// destination accepts none: the plain-text title when the message carries
// it separately, the severity's priority, tags, and colour, and the
// service's fixed defaults, each only when the URL does not set it.
func (d destination) params(message Prepared) *types.Params {
	params := types.Params{}
	if message.Title != "" {
		if key := d.paramKey(paramTitle); key != "" {
			params[key] = encodeTitle(d.scheme, message.Title)
		}
	}
	if message.Format == FormatHTML && d.scheme == "telegram" {
		// The HTML rendering is only shown as such in Telegram's HTML parse
		// mode; Shoutrrr's own HTML mode would escape it. It replaces a parse
		// mode set in the URL, whose Markdown modes would reject the text.
		params[paramParseMode] = parseModeHTML
	}
	for param := range severityParams[d.scheme] {
		if value := d.severityParam(param, message.Severity); value != "" {
			params[d.paramKey(param)] = value
		}
	}
	for param, value := range serviceDefaults[d.scheme] {
		if key := d.paramKey(param); key != "" {
			params[key] = value
		}
	}
	if len(params) == 0 {
		return nil
	}
	return &params
}

// plainTitle is the title a destination receives as a parameter: the icon,
// title, and scope as one line of plain text without control characters,
// bounded to maxTitleBytes. The scope cannot form a bare URL or a broadcast
// mention (see neutralize).
func plainTitle(m Message) string {
	title := stripControl(titleText(m))
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + neutralize(stripControl(scope))
	}
	return truncate(strings.TrimSpace(title), maxTitleBytes)
}

// encodeTitle applies the escaping a service needs for a title parameter.
// Slack shows its title as mrkdwn text, so &, <, and > are escaped and a
// scope cannot create a mention or link. ntfy carries the title in an HTTP
// header, so non-ASCII text is RFC 2047 encoded, which ntfy decodes.
func encodeTitle(scheme, title string) string {
	switch scheme {
	case "slack":
		return escapeSlack(title, false)
	case "ntfy":
		if !isASCII(title) {
			return mime.QEncoding.Encode("utf-8", title)
		}
	}
	return title
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

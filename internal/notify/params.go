package notify

import (
	"mime"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// Shoutrrr parameters TailState may set when it sends a message.
const (
	paramTitle = "title"
)

// serviceParams is the per-service allowlist of Shoutrrr config keys
// TailState passes with a message, derived from the pinned Shoutrrr release
// (v0.21.1). Shoutrrr fails a send when a parameter is not a config key of the
// service, so nothing outside this list is ever passed, and
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
// body as unformatted text, and Zulip uses it as the stream topic.
var serviceParams = map[string]map[string][]string{
	"discord":    {paramTitle: {"title"}},
	"gotify":     {paramTitle: {"title"}},
	"ntfy":       {paramTitle: {"title"}},
	"pushbullet": {paramTitle: {"title"}},
	"pushover":   {paramTitle: {"title"}},
	"slack":      {paramTitle: {"title"}},
	"smtp":       {paramTitle: {"subject", "title"}},
	"teams":      {paramTitle: {"title"}},
	"telegram":   {paramTitle: {"title"}},
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
	switch d.scheme {
	case "telegram":
		// Shoutrrr shows a Telegram title only in its HTML parse mode, which
		// it selects (escaping the body) when no parse mode is set. With an
		// explicit Markdown parse mode the title would be dropped.
		mode := strings.ToLower(d.query["parsemode"])
		return mode == "" || mode == "none"
	case "discord":
		// In JSON mode Discord sends the body as a raw payload and ignores
		// every parameter.
		return !truthy(d.query["json"])
	}
	return true
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

// params returns the Shoutrrr parameters for one send, or nil when the
// destination accepts none. title is the plain-text title, or "" when the
// title is part of the body.
func (d destination) params(title string) *types.Params {
	params := types.Params{}
	if title != "" {
		if key := d.paramKey(paramTitle); key != "" {
			params[key] = encodeTitle(d.scheme, title)
		}
	}
	if len(params) == 0 {
		return nil
	}
	return &params
}

// plainTitle is the title a destination receives as a parameter: the icon,
// title, and scope as one line of plain text without control characters,
// bounded to maxTitleBytes.
func plainTitle(m Message) string {
	title := stripControl(titleText(m))
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + stripControl(scope)
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

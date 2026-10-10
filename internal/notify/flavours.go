package notify

import "strings"

// Slack renders a message as Slack mrkdwn: single-asterisk bold, no
// headings, <url|label> links, and &, <, > escaped so a value cannot create
// a mention or link.
func Slack(m Message) string { return slackFlavour.render(m) }

var slackFlavour = flavour{title: slackTitle, line: slackLine}

func slackTitle(m Message) string {
	title := escapeSlack(titleText(m), false)
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + escapeSlack(scope, true)
	}
	return "*" + title + "*"
}

func slackLine(l Line) string {
	var b strings.Builder
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
			b.WriteString("`" + escapeSlack(neutralize(strings.ReplaceAll(truncate(span.Text, 256), "`", "'")), false) + "`")
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
	return b.String()
}

// escapeSlack applies Slack's required entity escaping. Untrusted values
// additionally lose the characters that open or close bold, strike, and code
// formatting, so they cannot restyle the rest of the line, and cannot form a
// bare URL or a broadcast mention (see neutralize). A value is bounded before
// it is escaped, so an entity is never cut in half.
func escapeSlack(value string, untrusted bool) string {
	value = stripControl(value)
	if untrusted {
		value = neutralize(strings.NewReplacer("*", "∗", "~", "∼", "`", "'").Replace(truncate(value, 256)))
	}
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
}

// Plain renders a message as plain text without any markup, for services
// that show text verbatim (email, SMS, push, Matrix). Values are shown as
// they are, except that they cannot form a bare URL or a broadcast mention
// (see neutralize).
func Plain(m Message) string { return plainFlavour.render(m) }

var plainFlavour = flavour{title: plainTitleLine, line: plainLine}

func plainTitleLine(m Message) string {
	title := stripControl(titleText(m))
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + neutralize(truncate(stripControl(scope), 256))
	}
	return title
}

func plainLine(l Line) string {
	var b strings.Builder
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
				b.WriteString(neutralize(truncate(text, 256)))
			}
		default:
			b.WriteString(neutralize(truncate(text, 256)))
		}
	}
	return b.String()
}

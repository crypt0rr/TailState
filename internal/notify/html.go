package notify

import (
	"html"
	"strings"
)

// HTML renders a message in Telegram's HTML subset: <b> for names and
// labels, <i> for remarks, <code> for values, and <a href> only for the
// links TailState builds from its validated public URL. Every value, and
// every trusted text, is HTML-escaped (&, <, >, ", '), so a value cannot add
// a tag, an attribute, or an entity. Telegram receives it with
// parsemode=HTML (see serviceParams).
func HTML(m Message) string { return htmlFlavour.render(m) }

var htmlFlavour = flavour{title: htmlTitle, line: htmlLine}

func htmlTitle(m Message) string {
	title := escapeHTML(titleText(m), false)
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + escapeHTML(scope, true)
	}
	return "<b>" + title + "</b>"
}

func htmlLine(l Line) string {
	var b strings.Builder
	switch l.Kind {
	case LineItem:
		b.WriteString("  • ")
	case LineNote:
		b.WriteString("  ")
	}
	for _, span := range l.Spans {
		switch span.Style {
		case SpanLiteral:
			b.WriteString(escapeHTML(span.Text, false))
		case SpanBold:
			b.WriteString("<b>" + escapeHTML(span.Text, true) + "</b>")
		case SpanStrong:
			b.WriteString("<b>" + escapeHTML(span.Text, false) + "</b>")
		case SpanCode:
			b.WriteString("<code>" + escapeHTML(span.Text, true) + "</code>")
		case SpanEmph:
			b.WriteString("<i>" + escapeHTML(span.Text, false) + "</i>")
		case SpanLink:
			if safeLinkURL(span.URL) {
				b.WriteString(`<a href="` + html.EscapeString(span.URL) + `">` + escapeHTML(span.Text, true) + "</a>")
			} else {
				b.WriteString(escapeHTML(span.Text, true))
			}
		default:
			b.WriteString(escapeHTML(span.Text, true))
		}
	}
	return b.String()
}

// htmlEscaped returns the flavour with every rendered title and line
// HTML-escaped, for a destination whose URL forces an HTML parse mode on
// another format.
func (f flavour) htmlEscaped() flavour {
	return flavour{
		title: func(m Message) string { return html.EscapeString(f.title(m)) },
		line:  func(l Line) string { return html.EscapeString(f.line(l)) },
	}
}

// escapeHTML replaces control characters with spaces and escapes &, <, >,
// ", and '. An untrusted value is bounded first, so an entity is never cut
// in half.
func escapeHTML(value string, untrusted bool) string {
	value = stripControl(value)
	if untrusted {
		value = truncate(value, 256)
	}
	return html.EscapeString(value)
}

package notify

import "strings"

// Markdown renders a message as CommonMark, the format TailState has always
// sent. Untrusted values are escaped for their context; a pre-rendered Text
// message is returned unchanged.
func Markdown(m Message) string {
	if m.IsText() {
		return m.Text
	}
	var b strings.Builder
	b.WriteString(markdownTitle(m))
	for _, l := range m.Lines {
		b.WriteByte('\n')
		b.WriteString(markdownLine(l))
	}
	return strings.TrimRight(b.String(), "\n")
}

func markdownSize(m Message) int {
	size := len(markdownTitle(m))
	for _, l := range m.Lines {
		size += len(markdownLine(l)) + 1
	}
	return size
}

func titleText(m Message) string {
	title := m.Title
	if m.Icon != "" {
		title = m.Icon + " " + title
	}
	return title
}

func markdownTitle(m Message) string {
	title := "### " + titleText(m)
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + escape(scope)
	}
	return title
}

func markdownLine(l Line) string {
	var b strings.Builder
	switch l.Kind {
	case LineItem:
		b.WriteString("  - ")
	case LineNote:
		b.WriteString("  ")
	}
	for _, span := range l.Spans {
		switch span.Style {
		case SpanLiteral:
			b.WriteString(stripControl(span.Text))
		case SpanBold:
			b.WriteString("**" + escape(span.Text) + "**")
		case SpanStrong:
			b.WriteString("**" + stripControl(span.Text) + "**")
		case SpanCode:
			b.WriteString("`" + escapeCode(span.Text) + "`")
		case SpanEmph:
			b.WriteString("_" + stripControl(span.Text) + "_")
		case SpanLink:
			if safeLinkURL(span.URL) {
				b.WriteString("[" + escape(span.Text) + "](" + span.URL + ")")
			} else {
				b.WriteString(escape(span.Text))
			}
		default:
			b.WriteString(escape(span.Text))
		}
	}
	return b.String()
}

// safeLinkURL accepts only the https links TailState builds from its
// validated public URL. A stored payload is trusted data, but checking again
// keeps a damaged row from producing active markup.
func safeLinkURL(value string) bool {
	if !strings.HasPrefix(value, "https://") || len(value) > 1024 {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("()<>[]|\"'`\\{}", r) {
			return false
		}
	}
	return true
}

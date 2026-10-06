package notify

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Teams renders a message for Microsoft Teams. Shoutrrr sends every line as
// its own Adaptive Card TextBlock, whose Markdown subset has bold, italic,
// bulleted lists, and links, but no headings, code spans, or backslash
// escapes. So the title is a bold line (when it is not the card title),
// values are plain text, list items use "- ", links use [label](url), and
// values are escaped for that subset only.
func Teams(m Message) string { return teamsFlavour.render(m) }

var teamsFlavour = flavour{title: teamsTitle, line: teamsLine}

func teamsTitle(m Message) string {
	title := escapeTeams(titleText(m))
	if scope := strings.TrimSpace(m.Scope); scope != "" {
		title += " · " + escapeTeams(scope)
	}
	return "**" + title + "**"
}

func teamsLine(l Line) string {
	var pieces []string
	if l.Kind == LineItem {
		pieces = append(pieces, "- ")
	}
	// valueEnd marks a piece that ends with a value, whose closing bracket
	// must not meet a following "(" and form a link.
	valueEnd := map[int]bool{}
	for _, span := range l.Spans {
		switch span.Style {
		case SpanLiteral:
			pieces = append(pieces, stripControl(span.Text))
		case SpanBold:
			pieces = append(pieces, "**"+escapeTeams(span.Text)+"**")
		case SpanStrong:
			pieces = append(pieces, "**"+stripControl(span.Text)+"**")
		case SpanEmph:
			pieces = append(pieces, "_"+stripControl(span.Text)+"_")
		case SpanLink:
			if safeLinkURL(span.URL) {
				pieces = append(pieces, "["+escapeTeams(span.Text)+"]("+span.URL+")")
			} else {
				valueEnd[len(pieces)] = true
				pieces = append(pieces, escapeTeams(span.Text))
			}
		default:
			// Text and code values alike: TextBlocks have no code spans.
			valueEnd[len(pieces)] = true
			pieces = append(pieces, escapeTeams(span.Text))
		}
	}
	for index := range pieces {
		if valueEnd[index] && index+1 < len(pieces) && strings.HasSuffix(pieces[index], "]") && strings.HasPrefix(pieces[index+1], "(") {
			pieces[index] = strings.TrimSuffix(pieces[index], "]") + "］"
		}
	}
	return strings.Join(pieces, "")
}

// escapeTeams makes a value inert in the TextBlock Markdown subset without
// backslashes, which TextBlocks show literally. An asterisk becomes a
// look-alike (∗); an underscore that could open or close emphasis (one not
// between two letters or digits) becomes a fullwidth low line (＿), while
// one inside a word such as tag:prod_db is kept; and a closing bracket
// followed by "(" becomes a fullwidth bracket (］), so the value cannot form
// a link (teamsLine does the same when the "(" follows the value). Control
// characters become spaces.
func escapeTeams(value string) string {
	value = truncate(stripControl(value), 256)
	var b strings.Builder
	for index, r := range value {
		switch r {
		case '*':
			b.WriteRune('∗')
		case '_':
			before, _ := utf8.DecodeLastRuneInString(value[:index])
			after, _ := utf8.DecodeRuneInString(value[index+1:])
			if wordRune(before) && wordRune(after) {
				b.WriteRune(r)
			} else {
				b.WriteRune('＿')
			}
		case ']':
			if strings.HasPrefix(value[index+1:], "(") {
				b.WriteRune('］')
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func wordRune(r rune) bool {
	return r != utf8.RuneError && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

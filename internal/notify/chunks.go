package notify

import (
	"strings"
	"unicode/utf8"
)

// partitionLines splits body into chunks of whole lines, each at most
// maxRunes long, in order. A single longer line is split at a rune boundary.
// Blank lines at the edge of a chunk are dropped, and an all-blank body
// yields one chunk with the body as is.
func partitionLines(body string, maxRunes int) []string {
	var chunks []string
	var current strings.Builder
	currentRunes := 0
	flush := func() {
		if text := strings.Trim(current.String(), "\n"); strings.TrimSpace(text) != "" {
			chunks = append(chunks, text)
		}
		current.Reset()
		currentRunes = 0
	}
	for _, text := range strings.Split(body, "\n") {
		for utf8.RuneCountInString(text) > maxRunes {
			flush()
			cut := len(truncateRunes(text, maxRunes))
			current.WriteString(text[:cut])
			flush()
			text = text[cut:]
		}
		runes := utf8.RuneCountInString(text)
		separator := 0
		if current.Len() > 0 {
			separator = 1
		}
		if currentRunes+separator+runes > maxRunes {
			flush()
			separator = 0
		}
		if separator == 1 {
			current.WriteByte('\n')
		}
		current.WriteString(text)
		currentRunes += separator + runes
	}
	flush()
	if len(chunks) == 0 {
		chunks = append(chunks, body)
	}
	return chunks
}

// truncateRunes returns at most maxRunes runes of value, cut at a rune
// boundary.
func truncateRunes(value string, maxRunes int) string {
	count := 0
	for index := range value {
		if count == maxRunes {
			return value[:index]
		}
		count++
	}
	return value
}

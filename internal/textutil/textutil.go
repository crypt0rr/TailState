// Package textutil contains small helpers shared by safety-sensitive text
// boundaries. Keeping truncation here prevents callers from slicing UTF-8 by
// byte offset and emitting invalid operator-facing or notification text.
package textutil

import "unicode/utf8"

// Truncate returns value unchanged when it fits within maxBytes. Longer text
// is shortened at a UTF-8 rune boundary and receives a Unicode ellipsis. The
// returned string is no longer than maxBytes when maxBytes can hold the
// ellipsis; all production callers use limits well above that minimum.
func Truncate(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	const ellipsis = "…"
	if maxBytes <= len(ellipsis) {
		return ellipsis
	}
	cut := maxBytes - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut] + ellipsis
}

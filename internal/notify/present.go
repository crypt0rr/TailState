package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/crypt0rr/tailstate/internal/model"
)

// The value presenter turns one field change into readable notification
// spans. History, the API, and evidence packs keep the full normalized
// values; only notifications are presented this way. Every value is placed in
// a code or text span, so each renderer still escapes it for its format.

const (
	// fingerprintChars is the length of a shortened SHA-256 fingerprint.
	fingerprintChars = 8
	// maxListItems bounds the elements shown for one side of a list change.
	maxListItems = 10
	// notSet is shown for an absent or null value.
	notSet = "(not set)"
)

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// fieldValue is one side of a field change, decoded into plain JSON types.
type fieldValue struct {
	set   bool
	value any
}

func valueOf(value any, present bool) fieldValue {
	if value == nil && !present {
		return fieldValue{}
	}
	value = plainJSON(value)
	if value == nil {
		return fieldValue{}
	}
	return fieldValue{set: true, value: value}
}

// plainJSON converts a value (including json.RawMessage and typed slices)
// into the types encoding/json decodes to.
func plainJSON(value any) any {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	var out any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&out) != nil {
		return string(raw)
	}
	return out
}

// presentField returns the spans describing one field change, for example
// "`role`: `member` → `admin`", "`tags`: +`tag:db`", "section `ssh` added",
// or "`endpointUrl`: secret changed (fingerprint `aa11bb22` → `99887766`)".
func presentField(collector string, field model.FieldChange) []Span {
	return presentFieldWith(collector, field, ": ")
}

// presentFieldInline is presentField for a field listed inside a sentence,
// such as a fleet summary: "`clientVersion` `1.80.2` → `1.82.1`".
func presentFieldInline(collector string, field model.FieldChange) []Span {
	return presentFieldWith(collector, field, " ")
}

func presentFieldWith(collector string, field model.FieldChange, separator string) []Span {
	old, current := valueOf(field.Old, field.OldPresent), valueOf(field.New, field.NewPresent)
	if collector == "policy" {
		if spans, ok := presentPolicySection(field.Field, old, current); ok {
			return spans
		}
	}
	if spans, ok := presentElement(field.Field, old, current, separator); ok {
		return spans
	}
	label := []Span{code(field.Field), lit(separator)}
	if spans, ok := presentSecret(old, current); ok {
		return append(label, spans...)
	}
	if spans, ok := presentList(orderedList(collector, field.Field), old, current); ok {
		return append(label, spans...)
	}
	return append(label, presentScalar(old), lit(" → "), presentScalar(current))
}

// presentElement shows an identified list element that was added or
// removed, recorded at a path such as "splitDNS.corp[10.0.0.53]", like a
// list difference: "`splitDNS.corp`: +`10.0.0.53`". History keeps the
// element's full value.
func presentElement(path string, old, current fieldValue, separator string) ([]Span, bool) {
	list, id, ok := model.ElementPathParts(path)
	if !ok || old.set == current.set {
		return nil, false
	}
	prefix := "+"
	if old.set {
		prefix = "−"
	}
	return []Span{code(list), lit(separator + prefix), code(id)}, true
}

// presentPolicySection shows a policy section, which TailState stores only
// as a SHA-256 fingerprint of its content (never the policy text), as added,
// removed, or changed with short fingerprints.
func presentPolicySection(section string, old, current fieldValue) ([]Span, bool) {
	oldPrint, oldOK := fingerprintOf(old)
	newPrint, newOK := fingerprintOf(current)
	switch {
	case oldOK && newOK:
		return []Span{lit("section "), code(section), lit(" changed ("), code(oldPrint), lit(" → "), code(newPrint), lit(")")}, true
	case !old.set && newOK:
		return []Span{lit("section "), code(section), lit(" added ("), code(newPrint), lit(")")}, true
	case oldOK && !current.set:
		return []Span{lit("section "), code(section), lit(" removed")}, true
	}
	return nil, false
}

func fingerprintOf(value fieldValue) (string, bool) {
	text, ok := value.value.(string)
	if !value.set || !ok || !sha256Hex.MatchString(text) {
		return "", false
	}
	return strings.ToLower(text[:fingerprintChars]), true
}

// redactedOf returns the short fingerprint of a redacted secret, stored as
// {"redacted_sha256": "<64 hex>"}.
func redactedOf(value fieldValue) (string, bool) {
	object, ok := value.value.(map[string]any)
	if !value.set || !ok || len(object) != 1 {
		return "", false
	}
	return fingerprintOf(fieldValue{set: true, value: object["redacted_sha256"]})
}

// presentSecret shows a redacted secret as set, removed, or changed with
// short fingerprints of the old and new values.
func presentSecret(old, current fieldValue) ([]Span, bool) {
	oldPrint, oldOK := redactedOf(old)
	newPrint, newOK := redactedOf(current)
	switch {
	case oldOK && newOK:
		return []Span{lit("secret changed (fingerprint "), code(oldPrint), lit(" → "), code(newPrint), lit(")")}, true
	case !old.set && newOK:
		return []Span{lit("secret set")}, true
	case oldOK && !current.set:
		return []Span{lit("secret removed")}, true
	}
	return nil, false
}

// orderedList reports the DNS lists whose order matters (resolvers are
// tried in order); TailState's normalization keeps their order too.
func orderedList(collector, field string) bool {
	if collector != "dns" {
		return false
	}
	compact := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(field))
	for _, segment := range strings.Split(compact, ".") {
		if segment == "nameservers" || segment == "searchpaths" {
			return true
		}
	}
	return false
}

// listItems returns the display text of a list of scalars (or of DNS
// resolver objects, by address). An absent value is an empty list.
func listItems(value fieldValue) ([]string, bool) {
	if !value.set {
		return nil, true
	}
	list, ok := value.value.([]any)
	if !ok {
		return nil, false
	}
	items := make([]string, 0, len(list))
	for _, element := range list {
		if object, isObject := element.(map[string]any); isObject {
			address, hasAddress := object["address"].(string)
			if !hasAddress {
				return nil, false
			}
			element = address
		}
		text, scalar := scalarText(element)
		if !scalar {
			return nil, false
		}
		items = append(items, text)
	}
	return items, true
}

// presentList shows a list change as the elements added and removed
// ("+tag:db, −tag:old"), or, for an ordered list, as its new order plus the
// elements added and removed. It falls back to the generic form when the
// shown elements do not differ (for example a resolver option change).
func presentList(ordered bool, old, current fieldValue) ([]Span, bool) {
	if !old.set && !current.set {
		return nil, false
	}
	oldItems, oldOK := listItems(old)
	newItems, newOK := listItems(current)
	if !oldOK || !newOK {
		return nil, false
	}
	added, removed := setDifference(newItems, oldItems), setDifference(oldItems, newItems)
	diff := diffSpans(added, removed)
	if !ordered {
		if len(diff) == 0 {
			return nil, false
		}
		return diff, true
	}
	if strings.Join(oldItems, "\x00") == strings.Join(newItems, "\x00") && old.set == current.set {
		return nil, false
	}
	spans := []Span{lit("now ")}
	switch {
	case !current.set:
		spans = []Span{lit(notSet)}
	case len(newItems) == 0:
		spans = append(spans, lit("(empty)"))
	default:
		spans = append(spans, joinedCodes(newItems, "")...)
	}
	if len(diff) > 0 && old.set && current.set {
		spans = append(spans, lit(" ("))
		spans = append(spans, diff...)
		spans = append(spans, lit(")"))
	}
	return spans, true
}

// setDifference returns the elements of a not in b, in a's order, counting
// duplicates.
func setDifference(a, b []string) []string {
	remaining := map[string]int{}
	for _, item := range b {
		remaining[item]++
	}
	var out []string
	for _, item := range a {
		if remaining[item] > 0 {
			remaining[item]--
			continue
		}
		out = append(out, item)
	}
	return out
}

func diffSpans(added, removed []string) []Span {
	spans := joinedCodes(added, "+")
	if len(removed) > 0 {
		if len(spans) > 0 {
			spans = append(spans, lit(", "))
		}
		spans = append(spans, joinedCodes(removed, "−")...)
	}
	return spans
}

// joinedCodes renders items as prefixed code spans separated by commas, at
// most maxListItems of them.
func joinedCodes(items []string, prefix string) []Span {
	var spans []Span
	for index, item := range items {
		if index == maxListItems {
			spans = append(spans, lit(fmt.Sprintf(", %d more", len(items)-index)))
			break
		}
		if index > 0 {
			spans = append(spans, lit(", "))
		}
		spans = append(spans, lit(prefix), code(item))
	}
	return spans
}

// scalarText returns the display text of a string, number, or boolean.
// Strings lose their JSON quotes, and a SHA-256 fingerprint is shortened.
func scalarText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		if sha256Hex.MatchString(v) {
			return strings.ToLower(v[:fingerprintChars]) + "…", true
		}
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

// presentScalar shows one side of a generic change: a scalar as text, an
// absent value as "(not set)", an empty string as "(empty)", and anything
// else as bounded compact JSON with fingerprints shortened.
func presentScalar(value fieldValue) Span {
	if !value.set {
		return lit(notSet)
	}
	if text, ok := scalarText(value.value); ok {
		if text == "" {
			return lit("(empty)")
		}
		return code(text)
	}
	if print, ok := redactedOf(value); ok {
		return code("secret " + print)
	}
	return code(shortValue(shortenFingerprints(value.value)))
}

// shortenFingerprints replaces redacted secrets and SHA-256 fingerprints
// inside a JSON value with their short forms.
func shortenFingerprints(value any) any {
	switch v := value.(type) {
	case map[string]any:
		if print, ok := redactedOf(fieldValue{set: true, value: v}); ok {
			return "secret " + print
		}
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[key] = shortenFingerprints(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, child := range v {
			out[index] = shortenFingerprints(child)
		}
		return out
	case string:
		if sha256Hex.MatchString(v) {
			return strings.ToLower(v[:fingerprintChars]) + "…"
		}
	}
	return value
}

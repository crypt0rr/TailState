package notify

import (
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

func TestDigestRendersEscapedChangesAndCounts(t *testing.T) {
	message := Digest([]model.Change{
		{Kind: "created", Collector: "de`vices", Name: "new\nserver"},
		{Kind: "changed", Collector: "users", Name: "alice", Fields: []model.FieldChange{{Field: "role", Old: "viewer", New: "admin"}}},
		{Kind: "removed", Collector: "dns", Name: "resolver"},
	})

	for _, want := range []string{
		"**3 change(s):** 1 created, 1 changed, 1 removed",
		"new server",
		"de'vices",
		"`role`: `\"viewer\"` → `\"admin\"`",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("digest missing %q: %s", want, message)
		}
	}
	if strings.Contains(message, "new\nserver") {
		t.Fatal("digest retained a raw newline")
	}
}

func TestDigestBoundsLargePayload(t *testing.T) {
	changes := make([]model.Change, 0, 500)
	for i := 0; i < cap(changes); i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", Name: strings.Repeat("x", 40), Fields: []model.FieldChange{{Field: "description", Old: strings.Repeat("o", 180), New: strings.Repeat("n", 180)}}})
	}
	message := Digest(changes)
	if len(message) > 12000 {
		t.Fatalf("digest exceeded size limit: %d", len(message))
	}
	if !strings.Contains(message, "more change(s) omitted; total: 500") {
		t.Fatal("large digest did not report omitted changes")
	}
}

func TestHealthAndUpdateMessagesEscapeInput(t *testing.T) {
	if got := SourceHealth("devices\nprod", false); !strings.Contains(got, "devices prod") || !strings.Contains(got, "unhealthy") {
		t.Fatalf("unexpected unhealthy message: %s", got)
	}
	if got := SourceHealth("devices", true); !strings.Contains(got, "recovered") {
		t.Fatalf("unexpected recovery message: %s", got)
	}
	if got := Update("v1`", "v2\n"); strings.Contains(got, "v1`") || strings.Contains(got, "v2\n") {
		t.Fatalf("update message did not escape input: %s", got)
	}
	got := Digest([]model.Change{{Kind: "created", Collector: "devices", Name: "[URGENT](https://evil.example)"}})
	if strings.Contains(got, "[URGENT](https://evil.example)") || !strings.Contains(got, `\[URGENT\]`) {
		t.Fatalf("device name retained active Markdown: %s", got)
	}
	got = Digest([]model.Change{{Kind: "created", Collector: "devices", Name: "!<img src=x> a+b-c"}})
	if strings.Contains(got, "!<img src=x>") || !strings.Contains(got, `\!\<img src=x\>`) {
		t.Fatalf("device name retained HTML or image syntax: %s", got)
	}
	got = Digest([]model.Change{{Kind: "created", Collector: "devices", Name: "prod\x00\x07\tserver"}})
	if strings.ContainsAny(got, "\x00\x07\t") {
		t.Fatalf("device name retained control characters: %q", got)
	}
	if !strings.Contains(got, "prod   server") {
		t.Fatalf("control characters were not replaced with inert spaces: %q", got)
	}
}

func TestDigestStopsAddingFieldsNearBound(t *testing.T) {
	fields := make([]model.FieldChange, 100)
	for i := range fields {
		fields[i] = model.FieldChange{Field: "field", Old: strings.Repeat("o", 180), New: strings.Repeat("n", 180)}
	}
	message := Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: fields}})
	if len(message) > 12000 {
		t.Fatalf("bounded digest length=%d", len(message))
	}
}

func TestDigestMarksTruncatedFieldDiffs(t *testing.T) {
	message := Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: make([]model.FieldChange, 24), FieldsTruncated: true, TotalFields: 40}})
	if !strings.Contains(message, "Additional field changes omitted; total: 40") {
		t.Fatalf("truncated field metadata was not surfaced: %s", message)
	}
}

// TestCodeSpansRenderValuesWithoutMarkdownEscapes is a golden test for the
// code-span escaper. CommonMark shows backslashes inside code spans
// literally, so values placed in backticks must not be backslash-escaped.
func TestCodeSpansRenderValuesWithoutMarkdownEscapes(t *testing.T) {
	digest := Digest([]model.Change{{
		Kind:      "changed",
		Collector: "device_details",
		Name:      "db-1",
		Fields: []model.FieldChange{
			{Field: "last_seen", Old: "2026-10-05T12:00:00Z", New: "2026-10-05T13:00:00Z"},
			{Field: "tags", Old: []string{"tag:prod-db"}, New: []string{"tag:prod-db", "tag:#ops"}},
		},
	}})
	for _, want := range []string{
		"  - `last_seen`: `\"2026-10-05T12:00:00Z\"` → `\"2026-10-05T13:00:00Z\"`\n",
		"  - `tags`: `[\"tag:prod-db\"]` → `[\"tag:prod-db\",\"tag:#ops\"]`\n",
		// Bold and prose contexts keep their Markdown escapes.
		"✏️ **db\\-1** `changed` (device\\_details)\n",
	} {
		if !strings.Contains(digest, want) {
			t.Fatalf("digest missing %q:\n%s", want, digest)
		}
	}
	if got, want := SourceHealth("device_details", false), "### ⚠️ Tailscale API collector unhealthy\n`device_details` failed three consecutive polls. TailState will keep retrying."; got != want {
		t.Fatalf("source health message=%q, want %q", got, want)
	}
	if got, want := SourceHealth("device_details", true), "### ✅ Tailscale API collector recovered\n`device_details` is responding successfully again."; got != want {
		t.Fatalf("source recovery message=%q, want %q", got, want)
	}
	if got, want := Update("v1.2.0-rc.1", "v1.3.0_beta#2"), "### 🚀 TailState updated\n**Previous version:** `v1.2.0-rc.1`\n**Current version:** `v1.3.0_beta#2`"; got != want {
		t.Fatalf("update message=%q, want %q", got, want)
	}
}

// TestCodeSpansCannotBeClosedOrBrokenByValues keeps the code-span escaper's
// injection guarantees: a value cannot end its span with a backtick, start
// a new block with a line break, or exceed the per-value bound.
func TestCodeSpansCannotBeClosedOrBrokenByValues(t *testing.T) {
	got := Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: []model.FieldChange{{
		Field: "na`me\n# heading",
		Old:   "x` [click](https://evil.example) <img src=x>",
		New:   "line\u2028break\rreturn",
	}}}})
	if strings.Count(got, "`") != 8 {
		t.Fatalf("value changed the number of code-span fences: %s", got)
	}
	for _, unwanted := range []string{"\n# heading", "\u2028", "\r"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("value broke out of its code span with %q: %q", unwanted, got)
		}
	}
	if !strings.Contains(got, "`\"x' [click](https://evil.example) \\u003cimg src=x\\u003e\"`") {
		t.Fatalf("code span did not keep inert link text verbatim: %s", got)
	}
	if long := escapeCode(strings.Repeat("a", 400)); len(long) > 256 {
		t.Fatalf("code value was not bounded: %d bytes", len(long))
	}
	if strings.Contains(Update("`", "x"), "``") {
		t.Fatal("a backtick value produced an empty or double fence")
	}
}

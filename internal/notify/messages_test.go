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
	if !strings.Contains(message, "Additional changes omitted") && !strings.HasSuffix(message, "…") {
		t.Fatal("large digest did not report omitted changes or truncate")
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

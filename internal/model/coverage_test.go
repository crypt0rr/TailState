package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeAndHealthEdgeCases(t *testing.T) {
	value := map[string]any{
		"detail": map[string]any{"hostname": "duplicate"},
		"routes": map[string]any{"enabledRoutes": []any{"10.0.0.0/24"}},
		"status": "unknown",
	}
	normalized := Normalize(value)
	if normalized == nil {
		t.Fatal("Normalize returned nil")
	}
	details := NormalizeFor("device_details", value).(map[string]any)
	if _, ok := details["detail"]; ok {
		t.Fatal("device detail duplicate was retained")
	}
	if _, ok := details["routes"]; !ok {
		t.Fatal("device detail routes were removed")
	}
	posture := NormalizeFor("posture", map[string]any{"status": "unknown"}).(map[string]any)
	if posture["status"] != "unknown" {
		t.Fatalf("non-map health status changed: %#v", posture)
	}
	if fingerprint, ok := redactedFingerprint(map[string]any{"redacted_sha256": strings.Repeat("AB", 32)}); !ok || fingerprint != strings.Repeat("ab", 32) {
		t.Fatalf("valid fingerprint=%q ok=%v", fingerprint, ok)
	}
	nested := NormalizeFor("device_details", map[string]any{"routes": map[string]any{"detail": "duplicate", "enabled": true}}).(map[string]any)
	if routes := nested["routes"].(map[string]any); routes["detail"] != nil {
		t.Fatalf("nested device detail duplicate was retained: %#v", routes)
	}
	for _, invalid := range []any{nil, map[string]any{}, map[string]any{"redacted_sha256": "short"}, map[string]any{"redacted_sha256": strings.Repeat("gg", 32)}, map[string]any{"redacted_sha256": strings.Repeat("aa", 32), "extra": true}} {
		if got, ok := redactedFingerprint(invalid); ok || got != "" {
			t.Fatalf("invalid fingerprint accepted: %#v -> %q,%v", invalid, got, ok)
		}
	}
}

func TestDiffAndCanonicalErrorBranches(t *testing.T) {
	if changes := Diff([]byte(`1`), []byte(`2`)); len(changes) != 1 || changes[0].Field != "value" {
		t.Fatalf("root scalar diff=%#v", changes)
	}
	if changes := Diff([]byte(`{"nested":{"old":1}}`), []byte(`{"nested":{"old":2}}`)); len(changes) != 1 || changes[0].Field != "nested.old" {
		t.Fatalf("nested diff=%#v", changes)
	}
	if changes := Diff([]byte("not-json"), []byte(`{"value":true}`)); len(changes) != 1 || changes[0].Field != "value" {
		t.Fatalf("invalid JSON diff=%#v", changes)
	}
	oldValue := map[string]any{}
	newValue := map[string]any{}
	for i := 0; i < 30; i++ {
		oldValue["field"+string(rune('a'+i))] = i
		newValue["field"+string(rune('a'+i))] = i + 1
	}
	changes := Diff(mustJSON(t, oldValue), mustJSON(t, newValue))
	if len(changes) != 24 {
		t.Fatalf("diff change cap=%d, want 24", len(changes))
	}
	detailed := DiffDetailed(mustJSON(t, oldValue), mustJSON(t, newValue))
	if !detailed.FieldsTruncated || detailed.TotalFields != 30 || len(detailed.Fields) != 24 {
		t.Fatalf("detailed diff metadata=%+v", detailed)
	}
	long := strings.Repeat("x", 300)
	changes = Diff([]byte(`{"message":"`+long+`"}`), []byte(`{"message":"`+long+`y"}`))
	if len(changes) != 1 || len(changes[0].Old.(string)) > 240 || !strings.HasSuffix(changes[0].Old.(string), "…") {
		t.Fatalf("long diff was not compacted: %#v", changes)
	}
	if _, _, err := Canonical(map[string]any{"unsupported": func() {}}); err == nil {
		t.Fatal("unsupported canonical value was accepted")
	}
	if got := compact(long); !strings.HasSuffix(got.(string), "…") {
		t.Fatalf("compact output=%q", got)
	}
}

func TestDiffPreservesMissingVersusExplicitNull(t *testing.T) {
	changes := Diff([]byte(`{"value":null}`), []byte(`{}`))
	if len(changes) != 1 || changes[0].Field != "value" || !changes[0].OldPresent || changes[0].NewPresent {
		t.Fatalf("null-to-missing diff=%#v", changes)
	}
	if got, ok := changes[0].Old.(json.RawMessage); !ok || string(got) != "null" {
		t.Fatalf("explicit null was not preserved: %#v", changes[0].Old)
	}
	encoded, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip []FieldChange
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if len(roundTrip) != 1 || !roundTrip[0].OldPresent || roundTrip[0].NewPresent || roundTrip[0].Old != nil {
		t.Fatalf("presence metadata did not survive persistence: %s -> %#v", encoded, roundTrip)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, _, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

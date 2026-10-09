package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestFleetTransitionsOnTheSameResourcesShareOneLine is E-036's merged fleet
// line: a client rollout that also flips updateAvailable on the same devices
// is one summary, while a transition on a different set stays separate.
func TestFleetTransitionsOnTheSameResourcesShareOneLine(t *testing.T) {
	var changes []model.Change
	for i := 0; i < 12; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("d%d", i), Name: fmt.Sprintf("node-%02d.tail1234.ts.net", i), Fields: []model.FieldChange{
			{Field: "updateAvailable", Old: true, New: false, OldPresent: true, NewPresent: true},
			{Field: "clientVersion", Old: "1.80.2", New: "1.82.0", OldPresent: true, NewPresent: true},
		}})
	}
	for i := 0; i < 5; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "users", ResourceID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("user-%d", i), Fields: []model.FieldChange{
			{Field: "status", Old: "idle", New: "active", OldPresent: true, NewPresent: true},
		}})
	}
	got := Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes}))
	if !strings.Contains(got, "\n⚪ 📦 12 devices: clientVersion 1.80.2 → 1.82.0, updateAvailable true → false\n") || strings.Count(got, "📦") != 2 {
		t.Fatalf("transitions on the same devices were not merged:\n%s", got)
	}
	if !strings.Contains(got, "\n🟠 📦 5 users: status idle → active\n") {
		t.Fatalf("a transition on other resources was merged:\n%s", got)
	}
	// One more device with only the version change: the two transitions now
	// cover different devices and stay separate lines.
	changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: "extra", Name: "extra", Fields: []model.FieldChange{
		{Field: "clientVersion", Old: "1.80.2", New: "1.82.0", OldPresent: true, NewPresent: true},
	}})
	got = Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes}))
	if !strings.Contains(got, "13 devices: clientVersion 1.80.2 → 1.82.0\n") || !strings.Contains(got, "12 devices: updateAvailable true → false\n") {
		t.Fatalf("transitions on different devices were merged:\n%s", got)
	}
}

// TestCompactDigestLayout covers E-036's title, plurals, collector nouns,
// short device names, compact time, and closing context line.
func TestCompactDigestLayout(t *testing.T) {
	one := Context{Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
		{Kind: "removed", Collector: "devices", Name: "db-01.tail1234.ts.net"},
	}, MutedCount: 1})
	if got, want := Plain(one), "🟠 1 Tailscale change (1 medium) · example.com\n\n🟠 ➖ db-01 (device) removed\n\n1 muted change not shown · 5 Oct 2026 12:00 UTC"; got != want {
		t.Fatalf("single change digest:\n got: %q\nwant: %q", got, want)
	}
	low := Context{Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: rollout(2)})
	if title := plainTitle(low); title != "⚪ 2 Tailscale changes · example.com" {
		t.Fatalf("low-only title=%q", title)
	}
	// The counts line appears only when it adds to the title: a batch that
	// mixes change kinds or severities.
	if got := Plain(low); strings.Contains(got, "2 changed") {
		t.Fatalf("single kind and severity digest repeats its title:\n%s", got)
	}
	mixedKinds := Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: append(rollout(1), model.Change{Kind: "created", Collector: "devices", Name: "new"})})
	mixedSeverities := Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: append(rollout(1), model.Change{Kind: "changed", Collector: "devices", Name: "tagged", Fields: []model.FieldChange{set("tags", []any{"tag:a"}, []any{"tag:b"})}})})
	for name, message := range map[string]Message{"kinds": mixedKinds, "severities": mixedSeverities} {
		if got := Plain(message); !strings.Contains(got, ", ⚪ 1 low\n") {
			t.Fatalf("mixed %s digest has no counts line:\n%s", name, got)
		}
	}
	for collector, want := range map[string]string{"users": " (user)", "oauth_apps": " (OAuth app)", "policy": "", "unknown_thing": " (unknown_thing)"} {
		if got := Plain(Message{Title: "t", Lines: []Line{line(append([]Span{lit("x")}, typeSpans(collector)...)...)}}); got != "t\nx"+want {
			t.Errorf("%s noun=%q", collector, got)
		}
	}
	for count, want := range map[int]string{1: "1 key", 3: "3 keys"} {
		if got := Plain(Message{Title: "t", Lines: []Line{line(countSpans("keys", count)...)}}); got != "t\n"+want {
			t.Errorf("count %d=%q", count, got)
		}
	}
	if got := Plain(Message{Title: "t", Lines: []Line{line(countSpans("other", 1)...), line(countSpans("other", 2)...)}}); got != "t\n1 other resource\n2 other resources" {
		t.Errorf("unknown collector count=%q", got)
	}
	for name, want := range map[string]string{
		"web-02.tail1234.ts.net":  "web-02",
		"web-02.tail1234.ts.net.": "web-02",
		"web-02.example.com":      "web-02.example.com",
		"tail1234.ts.net":         "tail1234.ts.net",
		"web-02":                  "web-02",
	} {
		if got := shortDeviceName(name); got != want {
			t.Errorf("shortDeviceName(%q)=%q, want %q", name, got, want)
		}
	}
	if got := displayName("users", "alice.tail1234.ts.net"); got != "alice.tail1234.ts.net" {
		t.Fatalf("non-device name was shortened: %q", got)
	}
	odd := Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{{Kind: "renamed", Collector: "devices", Name: "x"}}}))
	if !strings.Contains(odd, " x (device) renamed") {
		t.Fatalf("unknown kind was not shown: %s", odd)
	}
	if empty := Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, MutedCount: 2})); !strings.HasPrefix(empty, "⚪ 0 Tailscale changes") {
		t.Fatalf("empty digest: %s", empty)
	}
	expiry := Plain(Context{}.ExpiryWarning(1, []ExpiryLine{{Kind: "Device node key", Name: "web-02.tail1234.ts.net", Expires: testObservedAt, DaysLeft: 1}}, testObservedAt))
	if !strings.Contains(expiry, "within 1 day ·") || !strings.Contains(expiry, "1 resource entered") || !strings.Contains(expiry, "Device node key web-02 expires 5 Oct 2026 12:00 UTC (1 day left)") {
		t.Fatalf("expiry warning:\n%s", expiry)
	}
}

// TestShortenedDigestKeepsItsContextLine covers fitting with the closing
// context line: change lines are dropped before it, so the time and History
// link survive the smallest budget, with and without a separate title.
func TestShortenedDigestKeepsItsContextLine(t *testing.T) {
	message := Context{Tailnet: "example.com", PublicURL: "https://tailstate.example"}.Digest(DigestInput{BatchID: 5, ObservedAt: testObservedAt, Changes: largeChanges(200), MutedCount: 2})
	context := "2 muted changes not shown · 5 Oct 2026 12:00 UTC · Batch 5 in History: https://tailstate.example/history?batch=5"
	for _, serviceURL := range []string{pushoverURL, pushoverURL + "?title=Ops", "pushover://shoutrrr:token@user/?title=x"} {
		prepared := PrepareMessage(message, serviceURL, "")
		for _, sent := range []string{prepared.Text, prepared.Message()} {
			if len(sent) > 1024 || !strings.HasSuffix(sent, "\n\n"+context) || !strings.Contains(sent, "Shortened for this destination") {
				t.Fatalf("%s: context line lost (%d bytes):\n%s", serviceURL, len(sent), sent)
			}
		}
	}
	// A budget too small for the context line and a change still fits.
	tiny := FitMessageFor(Plain(message), 60, FormatPlain)
	if len(tiny) > 60 {
		t.Fatalf("tiny fit=%d bytes", len(tiny))
	}
	head, context2 := splitContext(Message{Title: "t", Lines: []Line{line(lit("a"))}})
	if len(context2) != 0 || len(head.Lines) != 1 {
		t.Fatal("message without context lines was split")
	}
}

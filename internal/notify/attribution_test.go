package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestDigestNamesActorInEveryRenderer is E-033's guarantee: in every format
// a digest names each known actor on its change line (escaped like any
// tenant value), never shows "actor unknown" or a "Changed by" line for an
// unmatched change, and states the attributed count in its header.
// Unsupported attribution (no lookup) adds nothing.
func TestDigestNamesActorInEveryRenderer(t *testing.T) {
	changes := []model.Change{
		{Kind: "changed", Collector: "devices", Name: "db-01", Fields: []model.FieldChange{{Field: "tags", Old: []any{"tag:dev"}, New: []any{"tag:prod"}, OldPresent: true, NewPresent: true}},
			Attribution: &model.Attribution{ActorLogin: "alice@example.com", ActorName: "<!channel> *Alice*", ActorType: "USER", Origin: "ADMIN_CONSOLE", Action: "NODE.UPDATE.ACL_TAGS"}},
		{Kind: "changed", Collector: "devices", Name: "web-01", Fields: []model.FieldChange{{Field: "clientVersion", Old: "1.80", New: "1.82", OldPresent: true, NewPresent: true}}},
	}
	attributed := Context{Tailnet: "example.com"}.Digest(DigestInput{BatchID: 1, ObservedAt: testObservedAt, Changes: changes, Attributed: true})
	for format, want := range map[string][]string{
		FormatMarkdown: {"\nAttributed: 1 of 2 changes\n", "**db-01** (device) changed by alice@example.com (\\<!channel> \\*Alice\\*) via admin console\n", "**web-01** (device) changed\n"},
		FormatSlack:    {"\nAttributed: 1 of 2 changes\n", "*db-01* (device) changed by alice@example.com (&lt;!channel&gt; ∗Alice∗) via admin console\n", "*web-01* (device) changed\n"},
		FormatPlain:    {"\nAttributed: 1 of 2 changes\n", "db-01 (device) changed by alice@example.com (<!channel> *Alice*) via admin console\n", "web-01 (device) changed\n"},
	} {
		rendered := Render(attributed, format)
		for _, text := range want {
			if !strings.Contains(rendered, text) {
				t.Fatalf("%s digest is missing %q:\n%s", format, text, rendered)
			}
		}
		if strings.Contains(rendered, model.ActorUnknown) || strings.Contains(rendered, "Changed by") {
			t.Fatalf("%s digest shows an unknown actor:\n%s", format, rendered)
		}
	}
	failed := Context{Tailnet: "example.com"}.Digest(DigestInput{BatchID: 1, ObservedAt: testObservedAt, Changes: changes[1:], Attributed: true, AttributionUnavailable: true})
	silent := Context{Tailnet: "example.com"}.Digest(DigestInput{BatchID: 1, ObservedAt: testObservedAt, Changes: changes})
	for _, format := range Formats {
		if rendered := Render(failed, format); !strings.Contains(rendered, "\nAttribution unavailable\n") || strings.Contains(rendered, model.ActorUnknown) || strings.Contains(rendered, " by ") {
			t.Fatalf("%s digest after a failed lookup:\n%s", format, rendered)
		}
		if rendered := Render(silent, format); strings.Contains(rendered, "Attribut") || strings.Contains(rendered, "alice") {
			t.Fatalf("%s digest without a lookup names an actor:\n%s", format, rendered)
		}
	}
}

// TestKnownActorsSurviveLongLinesAndSummaries covers the remaining places
// an attributed change can appear: a change line too long for its actor
// names it on its own "Changed by" line, and fleet and schema summaries name
// the actors of the changes they stand for.
func TestKnownActorsSurviveLongLinesAndSummaries(t *testing.T) {
	ci := &model.Attribution{ActorLogin: "ci-bot", ActorType: "API_KEY"}
	long := model.Change{Kind: "changed", Collector: "users", Name: strings.Repeat("n", 90), Attribution: &model.Attribution{ActorLogin: "alice@example.com", ActorName: "Alice Admin", Origin: "ADMIN_CONSOLE"}, Fields: []model.FieldChange{set("role", "member", "admin")}}
	var changes []model.Change
	changes = append(changes, long)
	for i := 0; i < 6; i++ {
		var attribution *model.Attribution
		if i < 4 {
			attribution = ci
		}
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("d%d", i), Name: fmt.Sprintf("d%d", i), Attribution: attribution, Fields: []model.FieldChange{set("tags", []any{"tag:a"}, []any{"tag:a", "tag:b"})}})
	}
	for i := 0; i < 3; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "keys", ResourceID: fmt.Sprintf("k%d", i), Name: fmt.Sprintf("k%d", i), Attribution: &model.Attribution{ActorLogin: fmt.Sprintf("user%d@example.com", i)}, Fields: []model.FieldChange{{Field: "audience", New: "x", NewPresent: true}}})
	}
	got := Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes, Attributed: true, ResourceCounts: map[string]int{"keys": 3}}))
	for _, want := range []string{
		"\nAttributed: 8 of 10 changes\n",
		strings.Repeat("n", 90) + " (user) changed\n  • Changed by: alice@example.com (Alice Admin) via admin console\n  • role: member → admin\n",
		"🔴 📦 6 devices: tags +tag:b · by ci-bot [api key] (4 of 6)\n",
		"🟠 🧩 Upstream schema change: audience newly present on all 3 keys · by user0@example.com, user1@example.com, user2@example.com\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("digest is missing %q:\n%s", want, got)
		}
	}
	many := make([]model.Change, 5)
	for i := range many {
		many[i] = model.Change{Attribution: &model.Attribution{ActorLogin: fmt.Sprintf("u%d", i)}}
	}
	if got := Plain(Message{Title: "t", Lines: []Line{line(summaryActors(many, []int{0, 1, 2, 3, 4})...)}}); got != "t\n · by u0, u1, u2 and 2 more" {
		t.Fatalf("bounded actors=%q", got)
	}
}

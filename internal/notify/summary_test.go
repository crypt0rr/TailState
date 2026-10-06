package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

func rollout(count int) []model.Change {
	changes := make([]model.Change, 0, count)
	for i := 0; i < count; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("d%d", i), Name: fmt.Sprintf("host-%03d", i), Fields: []model.FieldChange{
			{Field: "updateAvailable", Old: false, New: true, OldPresent: true, NewPresent: true},
		}})
	}
	return changes
}

// TestFleetRolloutCollapsesToOneSummaryLine is the E-009 rollout guarantee:
// the same field transition on many devices is one digest line.
func TestFleetRolloutCollapsesToOneSummaryLine(t *testing.T) {
	changes := rollout(143)
	changes = append(changes, model.Change{Kind: "changed", Collector: "devices", Name: "odd-one", Fields: []model.FieldChange{
		{Field: "updateAvailable", Old: false, New: true, OldPresent: true, NewPresent: true},
		{Field: "name", Old: "a", New: "b", OldPresent: true, NewPresent: true},
	}})
	got := Markdown(Context{PublicURL: "https://tailstate.example"}.Digest(DigestInput{BatchID: 9, ObservedAt: testObservedAt, Changes: changes}))
	if strings.Count(got, "updateAvailable") != 1 || !strings.Contains(got, "\n⚪ 📦 144 devices: `updateAvailable` `false` → `true`\n") {
		t.Fatalf("rollout was not summarised in one line:\n%s", got)
	}
	if strings.Contains(got, "host\\-001") {
		t.Fatalf("summarised devices are still listed individually:\n%s", got)
	}
	if !strings.Contains(got, "**odd\\-one**") || !strings.Contains(got, "`name`: `a` → `b`") || !strings.Contains(got, "144 changed · 🟠 1 medium, ⚪ 143 low") {
		t.Fatalf("remaining field or header counts were lost:\n%s", got)
	}
	// Below the threshold every device is listed.
	small := Markdown(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: rollout(FleetSummaryMinimum - 1)}))
	if strings.Contains(small, "📦") || strings.Count(small, "updateAvailable") != FleetSummaryMinimum-1 {
		t.Fatalf("a transition below the threshold was summarised:\n%s", small)
	}
}

// TestUpstreamFieldAdditionProducesOneSchemaChangeLine covers the E-009
// schema-change guarantee: a field newly present on every resource of a
// collector is one line, not one diff per resource.
func TestUpstreamFieldAdditionProducesOneSchemaChangeLine(t *testing.T) {
	keys := func(count int) []model.Change {
		out := make([]model.Change, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, model.Change{Kind: "changed", Collector: "keys", Name: fmt.Sprintf("key-%d", i), Fields: []model.FieldChange{
				{Field: "audience", New: fmt.Sprintf("aud-%d", i), NewPresent: true},
			}})
		}
		return out
	}
	got := Markdown(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: keys(12), ResourceCounts: map[string]int{"keys": 12}}))
	if strings.Count(got, "Upstream schema change") != 1 || !strings.Contains(got, "🟠 🧩 Upstream schema change: `audience` newly present on all 12 keys\n") || strings.Contains(got, "key\\-3") {
		t.Fatalf("schema addition was not one line:\n%s", got)
	}
	removed := []model.Change{
		{Kind: "changed", Collector: "keys", Name: "a", Fields: []model.FieldChange{{Field: "legacy", Old: 1, OldPresent: true}}},
		{Kind: "changed", Collector: "keys", Name: "b", Fields: []model.FieldChange{{Field: "legacy", Old: 2, OldPresent: true}}},
	}
	if got := Markdown(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: removed, ResourceCounts: map[string]int{"keys": 2}})); !strings.Contains(got, "`legacy` no longer present on any of the 2 keys\n") {
		t.Fatalf("schema removal was not summarised:\n%s", got)
	}
	// A field added on only some resources is ordinary drift.
	partial := Markdown(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: keys(3), ResourceCounts: map[string]int{"keys": 10}}))
	if strings.Contains(partial, "Upstream schema change") || strings.Count(partial, "audience") != 3 {
		t.Fatalf("partial field addition was summarised:\n%s", partial)
	}
}

func TestDigestReportsMutedCount(t *testing.T) {
	got := Markdown(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: rollout(1), MutedCount: 4}))
	if !strings.Contains(got, "4 muted changes not shown · 5 Oct 2026 12:00 UTC") {
		t.Fatalf("muted count missing:\n%s", got)
	}
}

package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestListElementPathsArePresentedAndSummarised covers R-049's
// presentation: an added or removed list element reads like a list
// difference, a field inside an element keeps its element path, and fleet
// and schema summaries group the same field of different elements by its
// generic path.
func TestListElementPathsArePresentedAndSummarised(t *testing.T) {
	added := model.FieldChange{Field: "splitDNS.corp[10.0.0.53]", New: map[string]any{"address": "10.0.0.53"}, NewPresent: true}
	removedField := model.FieldChange{Field: "splitDNS.corp[10.0.0.54]", Old: map[string]any{"address": "10.0.0.54"}, OldPresent: true}
	inner := set("splitDNS.corp[10.0.0.53].useWithExitNode", false, true)
	for field, want := range map[*model.FieldChange]string{
		&added:        "`splitDNS.corp`: +`10.0.0.53`",
		&removedField: "`splitDNS.corp`: −`10.0.0.54`",
		&inner:        "`splitDNS.corp[10.0.0.53].useWithExitNode`: `false` → `true`",
	} {
		if got := markdownLine(line(presentField("dns", *field)...)); got != want {
			t.Fatalf("presented %q, want %q", got, want)
		}
	}

	var changes []model.Change
	counts := map[string]int{"services": 6}
	for index := 0; index < 6; index++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "services", Name: fmt.Sprintf("svc-%d", index), Fields: []model.FieldChange{
			set(fmt.Sprintf("backends[b%d].weight", index), 1.0, 2.0),
			{Field: fmt.Sprintf("backends[b%d].zone", index), New: "eu", NewPresent: true},
			{Field: fmt.Sprintf("backends[x%d]", index), New: map[string]any{"id": "x"}, NewPresent: true},
		}})
	}
	got := Render(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes, ResourceCounts: counts}), FormatPlain)
	for _, want := range []string{
		"Upstream schema change: backends[].zone newly present on all 6 services",
		"📦 6 services: backends[].weight 1 → 2",
		"backends: +x0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("digest lacks %q:\n%s", want, got)
		}
	}
}

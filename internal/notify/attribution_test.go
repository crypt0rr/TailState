package notify

import (
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestDigestNamesActorInEveryRenderer renders "Changed by" for an attributed
// batch in Markdown, Slack, and plain text, escapes a hostile actor name like
// any tenant value, shows "actor unknown" for an unmatched change, and adds
// nothing when the audit log was not consulted.
func TestDigestNamesActorInEveryRenderer(t *testing.T) {
	changes := []model.Change{
		{Kind: "changed", Collector: "devices", Name: "db-01", Fields: []model.FieldChange{{Field: "tags", Old: []any{"tag:dev"}, New: []any{"tag:prod"}, OldPresent: true, NewPresent: true}},
			Attribution: &model.Attribution{ActorLogin: "alice@example.com", ActorName: "<!channel> *Alice*", ActorType: "USER", Origin: "ADMIN_CONSOLE", Action: "NODE.UPDATE.ACL_TAGS"}},
		{Kind: "changed", Collector: "devices", Name: "web-01", Fields: []model.FieldChange{{Field: "clientVersion", Old: "1.80", New: "1.82", OldPresent: true, NewPresent: true}}},
	}
	attributed := Context{Tailnet: "example.com"}.Digest(DigestInput{BatchID: 1, ObservedAt: testObservedAt, Changes: changes, Attributed: true})
	for format, want := range map[string][]string{
		FormatMarkdown: {"**Changed by:** alice@example.com \\(\\<\\!channel\\> \\*Alice\\*\\) via admin console", "**Changed by:** actor unknown"},
		FormatSlack:    {"*Changed by:* alice@example.com (&lt;!channel&gt; ∗Alice∗) via admin console", "*Changed by:* actor unknown"},
		FormatPlain:    {"Changed by: alice@example.com (<!channel> *Alice*) via admin console", "Changed by: actor unknown"},
	} {
		rendered := Render(attributed, format)
		for _, text := range want {
			if !strings.Contains(rendered, text) {
				t.Fatalf("%s digest is missing %q:\n%s", format, text, rendered)
			}
		}
		if strings.Index(rendered, "Changed by") > strings.Index(rendered, "tags") {
			t.Fatalf("%s digest lists fields before the actor:\n%s", format, rendered)
		}
	}
	silent := Context{Tailnet: "example.com"}.Digest(DigestInput{BatchID: 1, ObservedAt: testObservedAt, Changes: changes})
	for _, format := range []string{FormatMarkdown, FormatSlack, FormatPlain} {
		if rendered := Render(silent, format); strings.Contains(rendered, "Changed by") || strings.Contains(rendered, "alice") {
			t.Fatalf("%s digest without a lookup names an actor:\n%s", format, rendered)
		}
	}
}

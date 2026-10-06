package notify

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// severityOfLine returns the rank of a digest line that starts with a
// severity icon, or -1 for other lines.
func severityOfLine(text string) int {
	for severity, icon := range severityIcons {
		if strings.HasPrefix(text, icon) {
			return severityRank[severity]
		}
	}
	return -1
}

// assertSeverityOrder fails when a lower-severity line precedes a higher one.
func assertSeverityOrder(t *testing.T, label, text string) {
	t.Helper()
	last := 0
	for _, current := range strings.Split(text, "\n") {
		rank := severityOfLine(current)
		if rank < 0 {
			continue
		}
		if rank < last {
			t.Fatalf("%s: %q follows a lower-severity line\n%s", label, current, text)
		}
		last = rank
	}
}

// mixedBatch is a busy batch in collection order: many medium device
// creations, a low client rollout (a fleet summary), a high tag rollout (a
// high fleet summary), and individual high changes listed last.
func mixedBatch(newDevices, highKeys int) DigestInput {
	var changes []model.Change
	for i := 0; i < newDevices; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "devices", ResourceID: fmt.Sprintf("n%d", i), Name: fmt.Sprintf("ephemeral-ci-runner-%02d.tail1234.ts.net", i)})
	}
	for i := 0; i < 6; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("node-%02d", i), Fields: []model.FieldChange{
			{Field: "clientVersion", Old: "1.80.2", New: "1.82.1", OldPresent: true, NewPresent: true},
		}})
	}
	for i := 0; i < 5; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("t%d", i), Name: fmt.Sprintf("db-%02d", i), Fields: []model.FieldChange{
			{Field: "tags", Old: []any{"tag:prod"}, New: []any{"tag:db", "tag:prod"}, OldPresent: true, NewPresent: true},
		}})
	}
	for i := 0; i < highKeys; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "keys", ResourceID: fmt.Sprintf("k%d", i), Name: fmt.Sprintf("authkey%02d", i)})
	}
	changes = append(changes, model.Change{Kind: "changed", Collector: "policy", ResourceID: "policy", Name: "Tailnet policy", Fields: []model.FieldChange{
		{Field: "acls", Old: "a", New: "b", OldPresent: true, NewPresent: true},
	}})
	return DigestInput{BatchID: 7, ObservedAt: testObservedAt, Changes: changes}
}

// TestDigestSeverityOrderingSurvivesSmallestBudget is the R-043 invariant:
// high-severity lines (changes and summaries) precede medium and low ones in
// every format, so fitting a busy digest to the smallest service budget
// (Pushover, 1,024 bytes) keeps the high-severity changes, and a footer
// names any high-severity changes that still had to be omitted.
func TestDigestSeverityOrderingSurvivesSmallestBudget(t *testing.T) {
	smallest := digestBudget
	smallestScheme := ""
	for scheme, limit := range serviceMessageLimits {
		if limit < smallest {
			smallest, smallestScheme = limit, scheme
		}
	}
	if smallestScheme != "pushover" || smallest != 1024 {
		t.Fatalf("smallest budget is %s (%d)", smallestScheme, smallest)
	}
	serviceURL := "pushover://shoutrrr:token@user"
	context := Context{Tailnet: "example.com", PublicURL: "https://tailstate.example"}
	for _, format := range Formats {
		// A few high changes behind many medium ones: all of them fit.
		batch := context.Digest(mixedBatch(70, 2))
		assertSeverityOrder(t, format+" full", Render(batch, format))
		prepared := PrepareMessage(batch, serviceURL, format)
		for _, sent := range []string{prepared.Text, prepared.Message()} {
			if len(sent) > smallest {
				t.Fatalf("%s: %d bytes", format, len(sent))
			}
			assertSeverityOrder(t, format+" fitted", sent)
			for _, want := range []string{"Tailnet policy", "authkey00", "authkey01", "tags"} {
				if !strings.Contains(sent, want) {
					t.Fatalf("%s: high-severity %q was cut:\n%s", format, want, sent)
				}
			}
			if strings.Contains(sent, "high-severity") {
				t.Fatalf("%s: footer claims omitted high-severity changes:\n%s", format, sent)
			}
		}
		// More high changes than fit: the footer states how many were cut.
		crowded := context.Digest(mixedBatch(5, 40))
		prepared = PrepareMessage(crowded, serviceURL, format)
		sent := prepared.Message()
		assertSeverityOrder(t, format+" crowded", sent)
		kept := 0
		for _, current := range strings.Split(sent, "\n") {
			if strings.HasPrefix(current, severityIcons[model.SeverityHigh]) {
				kept++
			}
		}
		match := regexp.MustCompile(`including (\d+) high-severity changes?`).FindStringSubmatch(sent)
		if match == nil {
			t.Fatalf("%s: footer does not name omitted high-severity changes:\n%s", format, sent)
		}
		omitted, _ := strconv.Atoi(match[1])
		// 40 keys, the policy change, and the tag rollout summary.
		if kept+omitted != 42 {
			t.Fatalf("%s: kept %d + omitted %d high-severity lines, want 42", format, kept, omitted)
		}
	}
}

// TestBusyTelegramDigestKeepsPolicyChange is R-043's reproduction: 150 new
// devices (medium) collected before one policy change (high), fitted to
// Telegram's 4,096 bytes.
func TestBusyTelegramDigestKeepsPolicyChange(t *testing.T) {
	var changes []model.Change
	for i := 1; i <= 150; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "devices", Name: fmt.Sprintf("ephemeral-ci-runner-%d.tail1234.ts.net", i)})
	}
	changes = append(changes, model.Change{Kind: "changed", Collector: "policy", Name: "Tailnet policy", Fields: []model.FieldChange{{Field: "acls", Old: "a", New: "b", OldPresent: true, NewPresent: true}}})
	prepared := PrepareMessage(Context{Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes}), telegramURL, "")
	if len(prepared.Message()) > 4096 || !strings.Contains(prepared.Message(), "🔴 ✏️ Tailnet policy changed\n") || !strings.Contains(prepared.Message(), "Shortened for this destination") {
		t.Fatalf("telegram digest lost the policy change:\n%s", prepared.Message())
	}
}

// TestChangesAreOrderedByCollectorAndNameWithinSeverity pins the stable
// order inside one severity and the placement of summaries.
func TestChangesAreOrderedByCollectorAndNameWithinSeverity(t *testing.T) {
	changes := []model.Change{
		{Kind: "created", Collector: "users", Name: "zed"},
		{Kind: "created", Collector: "devices", Name: "b-host"},
		{Kind: "created", Collector: "devices", Name: "a-host"},
		{Kind: "created", Collector: "keys", Name: "key"},
	}
	changes = append(changes, rollout(5)...)
	got := Plain(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes}))
	var order []string
	for _, current := range strings.Split(got, "\n")[1:] { // after the title
		if severityOfLine(current) >= 0 {
			order = append(order, current)
		}
	}
	want := []string{
		"🔴 ➕ key (key) created",
		"🟠 ➕ a-host (device) created",
		"🟠 ➕ b-host (device) created",
		"🟠 ➕ zed (user) created",
		"⚪ 📦 5 devices: updateAvailable false → true",
	}
	if strings.Join(order, "\n") != strings.Join(want, "\n") {
		t.Fatalf("order:\n%s", strings.Join(order, "\n"))
	}
}

// TestDigestOmissionNoteNamesHighSeverity covers the digest's own budget:
// changes left out are counted, high-severity ones explicitly, and a send
// that drops that note carries its count into the shortening footer.
func TestDigestOmissionNoteNamesHighSeverity(t *testing.T) {
	var changes []model.Change
	for i := 0; i < 400; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "keys", Name: fmt.Sprintf("%s-%03d", strings.Repeat("k", 40), i)})
	}
	message := Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes})
	text := Plain(message)
	match := regexp.MustCompile(`(\d+) more changes omitted, including (\d+) high-severity; total: 400\.`).FindStringSubmatch(text)
	if match == nil || match[1] != match[2] {
		t.Fatalf("digest omission note: %s", text[len(text)-300:])
	}
	if got := omittedEntries([]digestEntry{{severity: model.SeverityLow}, {severity: model.SeverityHigh, change: &model.Change{}}}, 9); got != "1 more change and 1 summary line omitted, including 1 high-severity; total: 9. See TailState History for the full batch." {
		t.Fatalf("note=%q", got)
	}
	dropped := []string{"🔴 a\n", "  • detail\n", "🟠 b\n", "\n", "_12 more changes omitted, including 5 high-severity; total: 20._\n", "🟠 x omitted, including 7 high-severity;\n"}
	if got := countHighSeverity(dropped); got != 6 {
		t.Fatalf("high-severity count=%d", got)
	}
}

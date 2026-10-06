package notify

import (
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestEveryNotificationIncludesTailnetAndObservedTime is the operator
// guarantee from E-010: every message type names the tailnet (and instance
// label) in its title and states when it was observed.
func TestEveryNotificationIncludesTailnetAndObservedTime(t *testing.T) {
	messages := Context{Label: "prod-eu", Tailnet: "example.com", Version: "1.2.3"}
	cases := map[string]Message{
		"digest":    messages.Digest(DigestInput{BatchID: 7, ObservedAt: testObservedAt, Changes: []model.Change{{Kind: "created", Collector: "devices", Name: "server"}}}),
		"unhealthy": messages.CollectorsUnhealthy([]CollectorHealth{{Collector: "devices", Reason: "auth rejected"}}, testObservedAt),
		"recovered": messages.CollectorsRecovered([]string{"devices"}, testObservedAt),
		"update":    messages.Update("1.2.2", "1.2.3", testObservedAt),
		"test":      messages.Test(testObservedAt),
	}
	for name, message := range cases {
		rendered := Markdown(message)
		title, _, _ := strings.Cut(rendered, "\n")
		if !strings.Contains(title, `prod\-eu \(example.com\)`) {
			t.Fatalf("%s title does not name the instance and tailnet: %q", name, title)
		}
		// Digests state the time on their closing context line, every other
		// message on an "Observed at" line.
		observed := "\nObserved at 5 Oct 2026 12:00 UTC"
		if name == "digest" {
			observed = "\n5 Oct 2026 12:00 UTC"
		}
		if !strings.Contains(rendered, observed) {
			t.Fatalf("%s message has no observation time:\n%s", name, rendered)
		}
	}
	// Without a label the tailnet alone is the scope, and "-" is spelled out.
	if got := Markdown(Context{Tailnet: "-"}.Update("1", "2", testObservedAt)); !strings.HasPrefix(got, "### 🚀 TailState updated · default tailnet\n") {
		t.Fatalf("default tailnet title=%q", got)
	}
}

func TestDigestLinksBatchOnlyWithPublicURL(t *testing.T) {
	changes := []model.Change{{Kind: "created", Collector: "devices", Name: "server"}}
	without := Markdown(Context{Tailnet: "example.com"}.Digest(DigestInput{BatchID: 42, ObservedAt: testObservedAt, Changes: changes}))
	if strings.Contains(without, "http") || strings.Contains(without, "History](") {
		t.Fatalf("digest without a public URL contains a link:\n%s", without)
	}
	with := Markdown(Context{Tailnet: "example.com", PublicURL: "https://tailstate.example/base"}.Digest(DigestInput{BatchID: 42, ObservedAt: testObservedAt, Changes: changes}))
	if !strings.Contains(with, "[Batch 42 in History](https://tailstate.example/base/history?batch=42)") {
		t.Fatalf("digest does not link the batch:\n%s", with)
	}
	health := Markdown(Context{PublicURL: "https://tailstate.example"}.CollectorsUnhealthy([]CollectorHealth{{Collector: "devices"}}, testObservedAt))
	if !strings.Contains(health, "(https://tailstate.example/status)") || !strings.Contains(health, "request failed") {
		t.Fatalf("health alert does not link the status page:\n%s", health)
	}
	if Markdown(Context{}.CollectorsRecovered([]string{"devices", "users"}, testObservedAt)) == "" {
		t.Fatal("recovery message is empty")
	}
}

func TestTestMessageNamesInstanceTailnetVersionAndTime(t *testing.T) {
	got := Markdown(Context{Label: "lab", Tailnet: "corp.example", Version: "v1.4.0"}.Test(testObservedAt))
	for _, want := range []string{"TailState test", "**Instance:** lab", "**Tailnet:** corp.example", "**Version:** `v1.4.0`", "Observed at 5 Oct 2026 12:00 UTC"} {
		if !strings.Contains(got, want) {
			t.Fatalf("test message missing %q:\n%s", want, got)
		}
	}
	if got := Markdown(Context{}.Test(testObservedAt)); !strings.Contains(got, "**Version:** `unknown`") || strings.Contains(got, "Instance:") {
		t.Fatalf("unlabelled test message=%s", got)
	}
}

func TestValidatePublicURL(t *testing.T) {
	for raw, want := range map[string]string{
		"":                                     "",
		"https://tailstate.example":            "https://tailstate.example",
		"https://tailstate.example/":           "https://tailstate.example",
		" https://tailstate.example:8443/ts/ ": "https://tailstate.example:8443/ts",
		"https://[2001:db8::1]/app":            "https://[2001:db8::1]/app",
	} {
		got, err := ValidatePublicURL(raw)
		if err != nil || got != want {
			t.Fatalf("ValidatePublicURL(%q)=%q,%v want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"http://tailstate.example",
		"tailstate.example",
		"https://user:pass@tailstate.example",
		"https://tailstate.example/?x=1",
		"https://tailstate.example/?",
		"https://tailstate.example/#frag",
		"https://tailstate.example/a(b)",
		"https://tailstate.example/a%20b",
		"https:opaque",
		"https:///path",
		"https://" + strings.Repeat("a", 520),
	} {
		if got, err := ValidatePublicURL(raw); err == nil {
			t.Fatalf("ValidatePublicURL(%q) accepted %q", raw, got)
		}
	}
}

func TestValidateInstanceLabel(t *testing.T) {
	if got, err := ValidateInstanceLabel("  prod eu  "); err != nil || got != "prod eu" {
		t.Fatalf("label=%q err=%v", got, err)
	}
	for _, raw := range []string{strings.Repeat("x", 65), "bad\nlabel", "tab\there"} {
		if _, err := ValidateInstanceLabel(raw); err == nil {
			t.Fatalf("label %q was accepted", raw)
		}
	}
}

func TestMarkdownRendersOnlySafeLinksAndTextPayloads(t *testing.T) {
	message := Message{Title: "t", Lines: []Line{
		line(link("bad", "javascript:alert(1)")),
		line(link("paren", "https://x.example/a)b")),
		line(Span{Style: "unknown", Text: "*x*"}),
	}}
	got := Markdown(message)
	if strings.Contains(got, "](") || !strings.Contains(got, `\*x\*`) {
		t.Fatalf("unsafe link or unknown span rendered actively:\n%s", got)
	}
	if got := Markdown(Text("**legacy**")); got != "**legacy**" {
		t.Fatalf("text payload changed: %q", got)
	}
	if got := Markdown(Message{}); got != "" {
		t.Fatalf("empty message=%q", got)
	}
	if !(Message{}).IsText() || (Message{Title: "x"}).IsText() {
		t.Fatal("IsText classification is wrong")
	}
}

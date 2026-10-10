package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// TestTeamsFlavourHasNoUnsupportedMarkup is R-047's first acceptance
// criterion: the Teams rendering of every message type has no headings, no
// code spans, and no CommonMark backslash escapes, and uses **bold**, "- "
// list items, and [label](url) links.
func TestTeamsFlavourHasNoUnsupportedMarkup(t *testing.T) {
	context := Context{Label: "prod-eu", Tailnet: "example.com", PublicURL: "https://tailstate.example", Version: "1.2.3"}
	messages := []Message{
		sampleDigest(), presenterDigest(), goldenDigest(),
		context.CollectorsUnhealthy([]CollectorHealth{{Collector: "device_details", Reason: "auth rejected"}}, testObservedAt),
		context.Update("v1.2.0-rc.1", "v1.3.0_beta#2", testObservedAt),
		context.Test(testObservedAt),
		context.ExpiryWarning(3, []ExpiryLine{{Kind: "Device node key", Name: "web_01", Tags: []string{"tag:prod_db"}, Expires: testObservedAt, DaysLeft: 2}}, testObservedAt),
	}
	for _, message := range messages {
		got := Render(message, FormatTeams)
		if Teams(message) != got {
			t.Fatal("Teams and Render disagree")
		}
		for _, syntax := range []string{"###", "`", "\\", "  - ", "•"} {
			if strings.Contains(got, syntax) {
				t.Fatalf("teams rendering contains %q:\n%s", syntax, got)
			}
		}
		if !strings.HasPrefix(got, "**") {
			t.Fatalf("teams title is not bold:\n%s", got)
		}
	}
	sample := Render(sampleDigest(), FormatTeams)
	for _, want := range []string{"\n🔴 ✏️ **web-02** (device) changed by ci-bot [api key]\n- tags: +tag:db\n", "\n- role: member → admin\n", "[Batch 1842 in History](https://tailstate.example/history?batch=1842)"} {
		if !strings.Contains(sample, want) {
			t.Fatalf("teams sample is missing %q:\n%s", want, sample)
		}
	}
	if got := Render(messages[6], FormatTeams); !strings.Contains(got, "- Device node key **web_01** (tag:prod_db) expires") {
		t.Fatalf("intraword underscores were changed:\n%s", got)
	}
}

// TestTeamsValuesCannotFormLinksOrEmphasis is R-047's injection criterion:
// link, image, and emphasis syntax inside values is inert in Teams without
// backslashes, including a bracket that meets a following parenthesis.
func TestTeamsValuesCannotFormLinksOrEmphasis(t *testing.T) {
	for value, want := range map[string]string{
		"[click](https://evil.example)":    "[click］(https:" + wordJoiner + "//evil.example)",
		"![x](https://evil.example/i.png)": "![x］(https:" + wordJoiner + "//evil.example/i.png)",
		"*bold* **strong**":                "∗bold∗ ∗∗strong∗∗",
		"_it_ __u__ snake_case":            "＿it＿ ＿＿u＿＿ snake_case",
		"a]":                               "a]",
	} {
		if got := escapeTeams(value); got != want {
			t.Errorf("escapeTeams(%q)=%q, want %q", value, got, want)
		}
	}
	// A value ending in "]" followed by a value or literal starting with "("
	// cannot form a link either.
	got := teamsLine(line(txt("[click]"), txt("(https://evil.example)"), lit(" "), txt("[x]"), lit("(y)"), lit(" "), link("bad", "javascript:x")))
	if strings.Contains(got, "](") || got != "[click］(https:"+wordJoiner+"//evil.example) [x］(y) bad" {
		t.Fatalf("teams line=%q", got)
	}
	message := Context{Tailnet: "[t](https://evil.example)"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
		{Kind: "created", Collector: "devices", Name: "[URGENT](https://evil.example)", Attribution: &model.Attribution{ActorLogin: "[me](https://evil.example)"}},
	}, Attributed: true})
	if rendered := Render(message, FormatTeams); strings.Contains(rendered, "](https://evil") {
		t.Fatalf("a value formed a Teams link:\n%s", rendered)
	}
}

// TestTeamsReceivesTitleAndReadableBody is R-047's second acceptance
// criterion: a Teams workflow receives the title as the card title and a
// readable body, one TextBlock per line, without unsupported markup.
func TestTeamsReceivesTitleAndReadableBody(t *testing.T) {
	if FormatFor(teamsURL, "") != FormatTeams || FormatFor("slack://a", "teams") != FormatTeams {
		t.Fatal("teams is not the automatic format for Teams or not an override")
	}
	if format, err := ValidateFormat(" Teams "); err != nil || format != FormatTeams {
		t.Fatalf("teams override=%q err=%v", format, err)
	}
	message := sampleDigest()
	prepared := PrepareMessage(message, teamsURL, "")
	mock := &mockProviders{}
	if err := senderWithTransport(mock).SendPrepared(context.Background(), teamsURL, prepared); err != nil {
		t.Fatal(err)
	}
	requests := mock.all()
	if len(requests) != 1 {
		t.Fatalf("requests=%d", len(requests))
	}
	title, body := sentTitle(t, "teams", requests[0])
	if title != plainTitle(message) || title != "🔴 19 Tailscale changes (5 high) · prod (example.com)" {
		t.Fatalf("card title=%q", title)
	}
	for _, syntax := range []string{"###", "`", "\\"} {
		if strings.Contains(body, syntax) {
			t.Fatalf("teams body contains %q:\n%s", syntax, body)
		}
	}
	if !strings.Contains(body, "🔴 ✏️ **Tailnet policy** changed by alice@example.com\n- section acls changed (3f9a1c0e → c41b7e2a)\n") {
		t.Fatalf("teams body is not the Teams rendering:\n%s", body)
	}
}

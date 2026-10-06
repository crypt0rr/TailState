package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// severityDigests are one digest per top severity: a policy change (high),
// a new device (medium), and a client upgrade (low).
func severityDigests() map[model.Severity]Message {
	context := Context{Tailnet: "example.com"}
	return map[model.Severity]Message{
		model.SeverityHigh:   context.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{{Kind: "changed", Collector: "policy", Name: "Tailnet policy", Fields: []model.FieldChange{set("acls", "a", "b")}}, {Kind: "created", Collector: "devices", Name: "new"}}}),
		model.SeverityMedium: context.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{{Kind: "created", Collector: "devices", Name: "new"}}}),
		model.SeverityLow:    context.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{{Kind: "changed", Collector: "devices", Name: "old", Fields: []model.FieldChange{set("clientVersion", "1", "2")}}}}),
	}
}

const opsgenieURL = "opsgenie://api.opsgenie.com/eb243592-faa2-4ba2-a551q-1afdf565c889"

// receivedSeverity extracts the priority, tags, or colour a provider
// received.
func receivedSeverity(t *testing.T, scheme string, request captured) string {
	t.Helper()
	switch scheme {
	case "ntfy":
		return request.header.Get("Priority") + "|" + request.header.Get("Tags")
	case "pushover":
		form, _ := url.ParseQuery(request.body)
		return form.Get("priority")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(request.body), &payload); err != nil {
		t.Fatalf("%s payload: %v", scheme, err)
	}
	switch scheme {
	case "gotify", "opsgenie":
		return fmt.Sprint(payload["priority"])
	case "discord":
		embeds, _ := payload["embeds"].([]any)
		var colors []string
		for _, raw := range embeds {
			embed, _ := raw.(map[string]any)
			colors = append(colors, fmt.Sprintf("%06x", int(embed["color"].(float64))))
		}
		return strings.Join(colors, ",")
	case "teams":
		attachments, _ := payload["attachments"].([]any)
		attachment, _ := attachments[0].(map[string]any)
		content, _ := attachment["content"].(map[string]any)
		blocks, _ := content["body"].([]any)
		block, _ := blocks[0].(map[string]any)
		return fmt.Sprint(block["color"])
	case "slack":
		var decoded slackPayload
		_ = json.Unmarshal([]byte(request.body), &decoded)
		if len(decoded.Attachments) == 0 {
			return ""
		}
		return decoded.Attachments[0].Color
	}
	t.Fatalf("no severity extractor for %s", scheme)
	return ""
}

// TestSeverityMapsToProviderPriorityAndColour is E-034's first acceptance
// criterion: mock endpoints receive the mapped priority, tags, or colour
// for high, medium, and low digests.
func TestSeverityMapsToProviderPriorityAndColour(t *testing.T) {
	want := map[string]map[model.Severity]string{
		"ntfy":     {model.SeverityHigh: "High|rotating_light", model.SeverityMedium: "Default|warning", model.SeverityLow: "Low|information_source"},
		"pushover": {model.SeverityHigh: "1", model.SeverityMedium: "0", model.SeverityLow: "-1"},
		"gotify":   {model.SeverityHigh: "8", model.SeverityMedium: "5", model.SeverityLow: "2"},
		"opsgenie": {model.SeverityHigh: "P2", model.SeverityMedium: "P3", model.SeverityLow: "P5"},
		"discord":  {model.SeverityHigh: "d60510", model.SeverityMedium: "ff8c00", model.SeverityLow: "95a5a6"},
		"teams":    {model.SeverityHigh: "attention", model.SeverityMedium: "warning", model.SeverityLow: "default"},
		"slack":    {model.SeverityHigh: "#d60510", model.SeverityMedium: "#ff8c00", model.SeverityLow: "#95a5a6"},
	}
	urls := map[string]string{"ntfy": ntfyURL, "pushover": pushoverURL, "gotify": gotifyURL, "opsgenie": opsgenieURL, "discord": discordURL, "teams": teamsURL, "slack": slackURL}
	for severity, message := range severityDigests() {
		if message.Severity != string(severity) {
			t.Fatalf("digest severity=%q, want %q", message.Severity, severity)
		}
		for scheme, serviceURL := range urls {
			mock := &mockProviders{}
			if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, PrepareMessage(message, serviceURL, "")); err != nil {
				t.Fatalf("%s %s: %v", scheme, severity, err)
			}
			requests := mock.all()
			if len(requests) != 1 {
				t.Fatalf("%s requests=%d", scheme, len(requests))
			}
			if got := receivedSeverity(t, scheme, requests[0]); !strings.HasPrefix(got, want[scheme][severity]) || (scheme == "discord" && strings.Trim(strings.ReplaceAll(got, want[scheme][severity], ""), ",") != "") {
				t.Errorf("%s %s received %q, want %q", scheme, severity, got, want[scheme][severity])
			}
		}
	}
	// System notifications use fixed levels.
	context := Context{Tailnet: "example.com"}
	for message, severity := range map[*Message]model.Severity{
		ptr(context.CollectorsUnhealthy([]CollectorHealth{{Collector: "devices"}}, testObservedAt)):                         model.SeverityHigh,
		ptr(context.AdminChange("Signed in", nil, "", "", testObservedAt)):                                                  model.SeverityHigh,
		ptr(context.ExpiryWarning(3, []ExpiryLine{{Kind: "Auth key", Name: "k", Expires: testObservedAt}}, testObservedAt)): model.SeverityMedium,
		ptr(context.CollectorsRecovered([]string{"devices"}, testObservedAt)):                                               model.SeverityLow,
		ptr(context.Update("1", "2", testObservedAt)):                                                                       model.SeverityLow,
		ptr(context.Test(testObservedAt)):                                                                                   model.SeverityLow,
	} {
		if message.Severity != string(severity) {
			t.Errorf("%q severity=%q, want %q", message.Title, message.Severity, severity)
		}
	}
}

func ptr(message Message) *Message { return &message }

// TestURLSuppliedPriorityAndColourWin is E-034's second acceptance
// criterion: a priority, tag, or colour set in the destination URL is kept.
func TestURLSuppliedPriorityAndColourWin(t *testing.T) {
	high := severityDigests()[model.SeverityHigh]
	for scheme, tc := range map[string]struct{ serviceURL, want string }{
		"ntfy":     {ntfyURL + "?priority=5&tags=robot", "Max|robot"},
		"pushover": {pushoverURL + "?priority=-2", "-2"},
		"gotify":   {gotifyURL + "?priority=10", "10"},
		"opsgenie": {opsgenieURL + "?priority=P1", "P1"},
		"discord":  {discordURL + "?color=0x00ff00", "00ff00"},
		"teams":    {teamsURL + "&color=good", "good"},
		"slack":    {slackURL + "?color=good", "good"},
	} {
		mock := &mockProviders{}
		if err := senderWithTransport(mock).SendPrepared(context.Background(), tc.serviceURL, PrepareMessage(high, tc.serviceURL, "")); err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if got := receivedSeverity(t, scheme, mock.all()[0]); !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s received %q, want the URL's %q", scheme, got, tc.want)
		}
	}
	// Only the parameter the URL sets is kept; the others are still mapped.
	if params := parseDestination(ntfyURL + "?priority=5").params(Prepared{Severity: "high"}); params == nil || (*params)["priority"] != "" || (*params)["tags"] != "rotating_light" {
		t.Fatalf("ntfy params=%v", params)
	}
}

// TestServicesWithoutSeverityKeysReceiveNone is E-034's third acceptance
// criterion: services without priority or colour keys receive no such
// parameter and their sends succeed, and a legacy row without a severity
// gets no mapped value anywhere.
func TestServicesWithoutSeverityKeysReceiveNone(t *testing.T) {
	high := severityDigests()[model.SeverityHigh]
	for _, serviceURL := range []string{wecomURL, googleChatURL, pushbulletURL, telegramURL, "smtp://mail.example:25/?from=a@example.com&to=b@example.com"} {
		if params := parseDestination(serviceURL).params(Prepared{Title: "t", Severity: "high"}); params != nil {
			for key := range *params {
				if key == "priority" || key == "color" || key == "tags" {
					t.Fatalf("%s receives %s", serviceURL, key)
				}
			}
		}
	}
	for _, serviceURL := range []string{wecomURL, googleChatURL, pushbulletURL, telegramURL} {
		mock := &mockProviders{}
		if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, PrepareMessage(high, serviceURL, "")); err != nil || len(mock.all()) != 1 {
			t.Fatalf("%s: %v", serviceURL, err)
		}
	}
	for scheme := range severityParams {
		if params := (destination{scheme: scheme, query: map[string]string{}}).params(Prepared{}); params != nil {
			for key := range *params {
				if key != paramSplitLines {
					t.Fatalf("%s legacy row receives %s", scheme, key)
				}
			}
		}
	}
	if prepared, err := PrepareFor(PayloadMarkdown, "legacy", ntfyURL, ""); err != nil || prepared.Severity != "" {
		t.Fatalf("legacy row severity=%q err=%v", prepared.Severity, err)
	}
}

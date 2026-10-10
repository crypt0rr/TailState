package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/slack"

	"github.com/crypt0rr/tailstate/internal/model"
)

// slackMock answers like Slack's webhook and Web API endpoints.
type slackMock struct {
	mu       sync.Mutex
	requests []captured
	status   int
	body     string
	header   http.Header
}

func (m *slackMock) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, captured{host: r.URL.Host, path: r.URL.Path, header: r.Header.Clone(), body: string(raw)})
	status, body := m.status, m.body
	if status == 0 {
		status = http.StatusOK
		body = "ok"
		if r.URL.Host == "slack.com" {
			body = `{"ok":true}`
		}
	}
	header := http.Header{}
	for key, values := range m.header {
		header[key] = values
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (m *slackMock) payloads(t *testing.T) []slackPayload {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]slackPayload, 0, len(m.requests))
	for _, request := range m.requests {
		var payload slackPayload
		if err := json.Unmarshal([]byte(request.body), &payload); err != nil {
			t.Fatalf("slack payload: %v\n%s", err, request.body)
		}
		out = append(out, payload)
	}
	return out
}

// allBlocks returns the message blocks, which a colour (from the URL or the
// severity) wraps in one attachment.
func (p slackPayload) allBlocks() []slackBlock {
	if len(p.Attachments) > 0 {
		return p.Attachments[0].Blocks
	}
	return p.Blocks
}

func sectionsOf(blocks []slackBlock) (header string, sections []string, types []string) {
	for _, block := range blocks {
		if block.Type == "header" {
			header = block.Text.Text
			continue
		}
		sections = append(sections, block.Text.Text)
		types = append(types, block.Text.Type)
	}
	return header, sections, types
}

// fakeSlackToken is assembled at runtime so the source never contains a
// literal that secret scanners treat as a real Slack token.
var fakeSlackToken = strings.Join([]string{"123456789", "123456789", "abcdefghijklmnopqrstuvwx"}, "-")

var slackTokenURL = "slack://" + "xo" + "xb:" + fakeSlackToken + "@C0123456"

// TestSlackDigestArrivesAsOneMessage is R-045's main acceptance criterion: a
// Slack digest is one message with a non-empty summary text and readable
// sections, not one attachment per line.
func TestSlackDigestArrivesAsOneMessage(t *testing.T) {
	message := sampleDigest()
	prepared := PrepareMessage(message, slackURL, "")
	mock := &slackMock{}
	if err := senderWithTransport(mock).SendPrepared(context.Background(), slackURL, prepared); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(mock.requests) != 1 || mock.requests[0].host != "hooks.slack.com" || mock.requests[0].path != "/services/AAAAAAAAA/BBBBBBBBB/CCCCCCCCCCCCCCCCCCCCCCCC" || !strings.HasPrefix(mock.requests[0].header.Get("Content-Type"), "application/json") {
		t.Fatalf("requests=%+v", mock.requests)
	}
	payload := mock.payloads(t)[0]
	if payload.Text != "🔴 19 Tailscale changes (5 high) · prod (example.com)" || len(payload.Attachments) != 1 || payload.Attachments[0].Color != "#d60510" || payload.Channel != "" {
		t.Fatalf("payload text=%q attachments=%d channel=%q", payload.Text, len(payload.Attachments), payload.Channel)
	}
	header, sections, types := sectionsOf(payload.allBlocks())
	if header != plainTitle(message) || strings.Join(sections, "\n") != prepared.Body || types[0] != "mrkdwn" {
		t.Fatalf("header=%q sections=%q", header, sections)
	}
	if strings.Contains(prepared.Body, "Tailscale changes") {
		t.Fatal("the title is repeated in the body")
	}

	// A digest at the full budget is still one message, in sections within
	// Slack's limits.
	large := PrepareMessage(Context{Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: largeChanges(400)}), slackURL, "")
	mock = &slackMock{}
	if err := senderWithTransport(mock).SendPrepared(context.Background(), slackURL, large); err != nil {
		t.Fatal(err)
	}
	payload = mock.payloads(t)[0]
	_, sections, _ = sectionsOf(payload.allBlocks())
	if len(mock.requests) != 1 || len(sections) < 4 || len(payload.allBlocks()) > slackMaxBlocks || strings.Join(sections, "\n") != large.Body {
		t.Fatalf("large digest: requests=%d sections=%d", len(mock.requests), len(sections))
	}
	for _, section := range sections {
		if utf8.RuneCountInString(section) > slackSectionRunes {
			t.Fatalf("section of %d characters", utf8.RuneCountInString(section))
		}
	}
}

// TestSlackTokenURLUsesTheWebAPI covers the bot-token form Shoutrrr
// supports: chat.postMessage with the bearer token and the channel.
func TestSlackTokenURLUsesTheWebAPI(t *testing.T) {
	mock := &slackMock{}
	sender := senderWithTransport(mock)
	if err := sender.SendPrepared(context.Background(), slackTokenURL, PrepareMessage(Context{Tailnet: "example.com"}.Test(testObservedAt), slackTokenURL, "")); err != nil {
		t.Fatalf("send: %v", err)
	}
	request := mock.requests[0]
	if request.host != "slack.com" || request.path != "/api/chat.postMessage" || request.header.Get("Authorization") != "Bearer "+"xo"+"xb-"+fakeSlackToken {
		t.Fatalf("request=%+v", request)
	}
	if payload := mock.payloads(t)[0]; payload.Channel != "C0123456" || payload.Text == "" {
		t.Fatalf("payload=%+v", payload)
	}
	// An API rejection reported in a 200 response is a permanent failure
	// with a specific reason (R-061).
	rejected := &slackMock{status: http.StatusOK, body: `{"ok":false,"error":"channel_not_found"}`}
	err := senderWithTransport(rejected).Send(context.Background(), slackTokenURL, "hello")
	if err == nil || !IsPermanent(err) || SafeDeliveryError(err) != "notification rejected by Slack (channel_not_found)" || strings.Contains(err.Error(), "abcdefghijklmnopqrstuvwx") {
		t.Fatalf("API rejection err=%v", err)
	}
	for _, body := range []string{"not json", ""} {
		if err := senderWithTransport(&slackMock{status: http.StatusOK, body: body}).Send(context.Background(), slackTokenURL, "hello"); err == nil {
			t.Fatalf("API body %q accepted", body)
		}
	}
	if err := senderWithTransport(&slackMock{status: http.StatusInternalServerError, body: `{"ok":false}`}).Send(context.Background(), slackTokenURL, "hello"); err == nil || IsPermanent(err) || SafeDeliveryError(err) != "notification delivery failed with HTTP 500" {
		t.Fatalf("API 500 err=%v", err)
	}
}

// TestSlackURLOptionsAreKept covers the Slack URL parameters Shoutrrr
// supports: bot name, icon, thread, colour, and an operator title.
func TestSlackURLOptionsAreKept(t *testing.T) {
	serviceURL := slackURL + "?botname=TailState&icon=https%3A%2F%2Ficons.example%2Fts.png&thread_ts=1700000000.000100&color=%23ff0000&title=Ops+alerts"
	message := Context{Tailnet: "example.com"}.Test(testObservedAt)
	prepared := PrepareMessage(message, serviceURL, "")
	if prepared.Title != "" {
		t.Fatalf("operator title overridden: %+v", prepared)
	}
	mock := &slackMock{}
	if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, prepared); err != nil {
		t.Fatal(err)
	}
	payload := mock.payloads(t)[0]
	if payload.Text != "Ops alerts" || payload.Username != "TailState" || payload.IconURL != "https://icons.example/ts.png" || payload.IconEmoji != "" || payload.ThreadTS != "1700000000.000100" {
		t.Fatalf("payload=%+v", payload)
	}
	if len(payload.Blocks) != 0 || len(payload.Attachments) != 1 || payload.Attachments[0].Color != "#ff0000" {
		t.Fatalf("colour attachment=%+v blocks=%d", payload.Attachments, len(payload.Blocks))
	}
	header, sections, _ := sectionsOf(payload.Attachments[0].Blocks)
	if header != "" || !strings.HasPrefix(sections[0], "*🧪 TailState test · example.com*") {
		t.Fatalf("operator-titled body lost the TailState title: %q", sections)
	}
	emoji := slackURL + "?icon=ghost"
	mock = &slackMock{}
	if err := senderWithTransport(mock).Send(context.Background(), emoji, "### legacy title\nlegacy body"); err != nil {
		t.Fatal(err)
	}
	payload = mock.payloads(t)[0]
	if payload.IconEmoji != "ghost" || payload.Text != "legacy title" {
		t.Fatalf("legacy payload=%+v", payload)
	}
	if _, sections, _ := sectionsOf(payload.allBlocks()); len(sections) != 1 || sections[0] != "### legacy title\nlegacy body" {
		t.Fatalf("legacy row changed: %q", sections)
	}
	if err := New().Send(context.Background(), "slack://hook:short@webhook", "x"); err == nil || !strings.HasPrefix(err.Error(), "invalid notification URL") {
		t.Fatalf("invalid token err=%v", err)
	}
}

// TestSlackNativePayloadBlocksMentionsAndLinks keeps R-045's injection
// guarantees: tenant values cannot mention a channel or create a link in
// the summary, header, or sections, and a plain-text override is sent as
// plain_text, which Slack never parses.
func TestSlackNativePayloadBlocksMentionsAndLinks(t *testing.T) {
	hostile := "<!channel> <https://evil.example|click> & *bold*"
	message := Context{Label: "<!here>", Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{
		{Kind: "created", Collector: "devices", Name: hostile},
		{Kind: "changed", Collector: "users", Name: "bob", Fields: []model.FieldChange{{Field: "role", Old: hostile, New: "admin", OldPresent: true, NewPresent: true}}},
	}})
	for _, override := range []string{"", FormatPlain, FormatMarkdown} {
		mock := &slackMock{}
		if err := senderWithTransport(mock).SendPrepared(context.Background(), slackURL, PrepareMessage(message, slackURL, override)); err != nil {
			t.Fatal(err)
		}
		payload := mock.payloads(t)[0]
		header, sections, types := sectionsOf(payload.allBlocks())
		if strings.Contains(payload.Text, "<!") || strings.Contains(payload.Text, "<https") {
			t.Fatalf("%q summary is active: %q", override, payload.Text)
		}
		for index, section := range sections {
			if types[index] == "plain_text" {
				continue
			}
			if strings.Contains(section, "<!") || strings.Contains(section, "<https://evil") {
				t.Fatalf("%q section is active: %q", override, section)
			}
		}
		if override == FormatPlain && types[0] != "plain_text" {
			t.Fatalf("plain override sent as %s", types[0])
		}
		if !strings.Contains(header, "<!here>") {
			t.Fatalf("header is plain text and keeps the label verbatim: %q", header)
		}
	}
}

// TestSlackDeliveryErrorsKeepTheirClassification is R-045's transport
// criterion: permanent 4xx, Retry-After, redirects, and redaction behave as
// they do for every other service.
func TestSlackDeliveryErrorsKeepTheirClassification(t *testing.T) {
	cases := []struct {
		name      string
		mock      *slackMock
		permanent bool
		reason    string
		retry     time.Duration
	}{
		{"deleted webhook", &slackMock{status: http.StatusNotFound, body: "no_service"}, true, "notification rejected by provider (HTTP 404)", 0},
		{"invalid payload", &slackMock{status: http.StatusBadRequest, body: "invalid_payload"}, true, "notification rejected by provider (HTTP 400)", 0},
		{"too large", &slackMock{status: http.StatusRequestEntityTooLarge, body: "too large"}, true, messageTooLargeReason, 0},
		{"rate limited", &slackMock{status: http.StatusTooManyRequests, body: "rate_limited", header: http.Header{"Retry-After": {"30"}}}, false, "notification delivery failed with HTTP 429", 30 * time.Second},
		{"server error", &slackMock{status: http.StatusInternalServerError, body: "oops"}, false, "notification delivery failed with HTTP 500", 0},
		{"archived channel", &slackMock{status: http.StatusGone, body: "channel_is_archived"}, true, "notification rejected by provider (HTTP 410)", 0},
		{"archived channel in a 200", &slackMock{status: http.StatusOK, body: "channel_is_archived"}, true, "notification rejected by Slack (channel_is_archived)", 0},
		{"unknown 200 body", &slackMock{status: http.StatusOK, body: "<html>proxy</html>"}, false, "notification delivery failed", 0},
		{"redirect", &slackMock{status: http.StatusFound, body: ""}, false, "notification delivery failed with HTTP 302", 0},
	}
	for _, tc := range cases {
		err := senderWithTransport(tc.mock).SendPrepared(context.Background(), slackURL, PrepareMessage(Context{}.Test(testObservedAt), slackURL, ""))
		var delivery *DeliveryError
		if err == nil || !errors.As(err, &delivery) {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
		if IsPermanent(err) != tc.permanent || SafeDeliveryError(err) != tc.reason || SafeDeliveryMessage(tc.reason) != tc.reason || delivery.RetryAfter != tc.retry {
			t.Fatalf("%s: permanent=%t reason=%q retry=%s", tc.name, IsPermanent(err), SafeDeliveryError(err), delivery.RetryAfter)
		}
		if strings.Contains(err.Error(), "CCCCCCCCCCCCCCCCCCCCCCCC") {
			t.Fatalf("%s: token leaked: %v", tc.name, err)
		}
	}
	// An empty 200 response is accepted, as Shoutrrr accepts it.
	if err := senderWithTransport(&slackMock{status: http.StatusOK, body: ""}).Send(context.Background(), slackURL, "x"); err != nil {
		t.Fatalf("empty 200: %v", err)
	}
	// A connection failure is a plain retryable failure.
	failing := roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("dial tcp: connection refused") })
	if err := senderWithTransport(failing).Send(context.Background(), slackURL, "x"); err == nil || IsPermanent(err) {
		t.Fatalf("connection failure err=%v", err)
	}
}

// TestSlackAPIErrorsAreClassifiedByCode is R-061's acceptance criterion:
// Slack API errors that no retry can fix dead-letter at once with a specific
// reason that survives the persistence boundary, temporary ones are
// retried, and the Settings test names a revoked token.
func TestSlackAPIErrorsAreClassifiedByCode(t *testing.T) {
	for code, reason := range map[string]string{
		"invalid_auth":      "notification rejected by Slack (invalid_auth)",
		"token_revoked":     "notification rejected by Slack (token_revoked)",
		"channel_not_found": "notification rejected by Slack (channel_not_found)",
		"not_in_channel":    "notification rejected by Slack (not_in_channel)",
		"msg_too_long":      messageTooLargeReason,
		"invalid_blocks":    "notification rejected by Slack (invalid_blocks)",
		"some_new_error":    "notification rejected by Slack",
		"":                  "notification rejected by Slack",
	} {
		mock := &slackMock{status: http.StatusOK, body: `{"ok":false,"error":"` + code + `"}`}
		err := senderWithTransport(mock).SendPrepared(context.Background(), slackTokenURL, PrepareMessage(Context{}.Test(testObservedAt), slackTokenURL, ""))
		if !IsPermanent(err) || SafeDeliveryError(err) != reason || SafeDeliveryMessage(reason) != reason {
			t.Fatalf("%q: permanent=%t reason=%q", code, IsPermanent(err), SafeDeliveryError(err))
		}
	}
	for _, code := range []string{"ratelimited", "internal_error", "service_unavailable", "fatal_error", "request_timeout"} {
		mock := &slackMock{status: http.StatusOK, body: `{"ok":false,"error":"` + code + `"}`}
		err := senderWithTransport(mock).Send(context.Background(), slackTokenURL, "hello")
		if err == nil || IsPermanent(err) || strings.HasPrefix(SafeDeliveryError(err), "notification rejected") {
			t.Fatalf("%q: err=%v permanent=%t", code, err, IsPermanent(err))
		}
	}
	revoked := &slackMock{status: http.StatusOK, body: `{"ok":false,"error":"token_revoked"}`}
	if got := SafeTestError(senderWithTransport(revoked).Test(context.Background(), slackTokenURL), slackTokenURL); got != "notification rejected by Slack (token_revoked)" {
		t.Fatalf("Settings test reason=%q", got)
	}
	// A reason outside the allowlist is never persisted.
	if got := SafeDeliveryError(&DeliveryError{Message: "x", Permanent: true, Reason: "secret response text"}); got != "notification delivery failed" {
		t.Fatalf("unlisted reason persisted: %q", got)
	}
	if got := SafeDeliveryMessage("notification rejected by Slack (secret)"); got != "notification delivery failed" {
		t.Fatalf("unlisted reason accepted: %q", got)
	}
}

func TestSlackPayloadEdges(t *testing.T) {
	long := Prepared{Title: strings.Repeat("t", 400), Body: strings.Repeat("line\n", 2000), Format: FormatSlack}
	payload := slackPayloadFor(long, &slackConfigForTest)
	header, sections, _ := sectionsOf(payload.allBlocks())
	if utf8.RuneCountInString(header) != slackHeaderRunes || len(payload.allBlocks()) > slackMaxBlocks || len(sections) == 0 {
		t.Fatalf("header=%d blocks=%d", utf8.RuneCountInString(header), len(payload.allBlocks()))
	}
	many := Prepared{Text: strings.Repeat(strings.Repeat("x", slackSectionRunes)+"\n", 60), Format: FormatSlack}
	if payload := slackPayloadFor(many, &slackConfigForTest); len(payload.Blocks) != slackMaxBlocks {
		t.Fatalf("blocks=%d", len(payload.Blocks))
	}
	if got := truncateRunes("ééé", 2); got != "éé" {
		t.Fatalf("truncateRunes=%q", got)
	}
}

var slackConfigForTest = slack.Config{Channel: "webhook"}

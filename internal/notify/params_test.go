package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nicholas-fedor/shoutrrr"
	"github.com/nicholas-fedor/shoutrrr/pkg/format"
	"github.com/nicholas-fedor/shoutrrr/pkg/router"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"

	"github.com/crypt0rr/tailstate/internal/model"
)

// shoutrrrConfig returns a zero config of the service registered for scheme
// by the pinned Shoutrrr module.
func shoutrrrConfig(t *testing.T, scheme string) types.ServiceConfig {
	t.Helper()
	service, err := (&router.ServiceRouter{}).NewService(scheme)
	if err != nil {
		t.Fatalf("%s is not a registered Shoutrrr service: %v", scheme, err)
	}
	field := reflect.ValueOf(service).Elem().FieldByName("Config")
	if !field.IsValid() || field.Kind() != reflect.Pointer {
		t.Fatalf("%s service has no Config pointer", scheme)
	}
	config, ok := reflect.New(field.Type().Elem()).Interface().(types.ServiceConfig)
	if !ok {
		t.Fatalf("%s config is not a ServiceConfig", scheme)
	}
	return config
}

// TestServiceParamAllowlistMatchesShoutrrrKeys enumerates the config keys of
// every allowlisted service in the pinned Shoutrrr release through its
// PropKeyResolver. Shoutrrr fails a send on an unknown key, so a dependency
// update that drops or renames a key TailState passes must fail here instead
// of failing deliveries. Each parameter must also list every alias of its
// config field, primary key first, so an operator's value under any alias is
// recognised.
func TestServiceParamAllowlistMatchesShoutrrrKeys(t *testing.T) {
	if len(serviceParams) == 0 {
		t.Fatal("empty allowlist")
	}
	for scheme, params := range serviceParams {
		config := shoutrrrConfig(t, scheme)
		resolver := format.NewPropKeyResolver(config)
		queryFields := resolver.QueryFields()
		fieldKeys := map[string][]string{}
		for _, node := range format.GetConfigFormat(config).Items {
			keys := node.Field().Keys
			for _, key := range keys {
				fieldKeys[strings.ToLower(key)] = keys
			}
		}
		for param, keys := range params {
			if len(keys) == 0 {
				t.Fatalf("%s %s lists no keys", scheme, param)
			}
			for _, key := range keys {
				if !slices.Contains(queryFields, key) {
					t.Errorf("%s: key %q of parameter %q is not a config key of the pinned Shoutrrr (keys: %v)", scheme, key, param, queryFields)
				}
			}
			if !resolver.KeyIsPrimary(keys[0]) {
				t.Errorf("%s: %q is not the primary key of its field", scheme, keys[0])
			}
			if want := fieldKeys[keys[0]]; !slices.Equal(keys, want) {
				t.Errorf("%s: parameter %q lists keys %v, Shoutrrr field has %v", scheme, param, keys, want)
			}
			// Every value TailState passes must be accepted by the field.
			values := []string{"TailState title"}
			if fixed, ok := serviceDefaults[scheme][param]; ok {
				values = []string{fixed}
			} else if mapped, ok := severityParams[scheme][param]; ok {
				values = values[:0]
				for _, severity := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
					if mapped[severity] == "" {
						t.Errorf("%s %s has no value for %s", scheme, param, severity)
					}
					values = append(values, mapped[severity])
				}
			}
			for _, value := range values {
				if err := resolver.Set(keys[0], value); err != nil {
					t.Errorf("%s: setting %q to %q failed: %v", scheme, keys[0], value, err)
				}
			}
		}
	}
	for scheme, params := range severityParams {
		for param := range params {
			if len(serviceParams[scheme][param]) == 0 {
				t.Errorf("%s severity parameter %q is not on the allowlist", scheme, param)
			}
		}
	}
	// Pushover's priority 2 requires acknowledgement and is never used.
	for _, value := range severityParams["pushover"][paramPriority] {
		if value == "2" {
			t.Fatal("a severity maps to Pushover's emergency priority")
		}
	}
	for scheme, defaults := range serviceDefaults {
		for param := range defaults {
			if len(serviceParams[scheme][param]) == 0 {
				t.Errorf("%s default %q is not on the allowlist", scheme, param)
			}
		}
	}
}

// captured is one request seen by a mock provider.
type captured struct {
	host, path string
	header     http.Header
	body       string
}

// mockProviders is a transport that answers like each provider's API, so a
// production sender can deliver to fixed provider hosts without a network.
type mockProviders struct {
	mu       sync.Mutex
	requests []captured
}

func (m *mockProviders) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.requests = append(m.requests, captured{host: r.URL.Host, path: r.URL.Path, header: r.Header.Clone(), body: string(raw)})
	m.mu.Unlock()
	body := `{"ok":true}`
	switch {
	case r.URL.Host == "hooks.slack.com":
		body = "ok"
	case strings.Contains(r.URL.Host, "gotify"):
		body = `{"id":1,"appid":1,"message":"m","title":"t","priority":0}`
	case r.URL.Host == "api.pushbullet.com":
		var push map[string]any
		_ = json.Unmarshal(raw, &push)
		echo, _ := json.Marshal(map[string]any{"type": "note", "title": push["title"], "body": push["body"], "active": true})
		body = string(echo)
	case r.URL.Host == "api.pushover.net":
		body = `{"status":1,"request":"r"}`
	case r.URL.Host == "api.telegram.org":
		body = `{"ok":true,"result":{"message_id":1}}`
	case r.URL.Host == "qyapi.weixin.qq.com":
		body = `{"errcode":0,"errmsg":"ok"}`
	case r.URL.Host == "ntfy.sh":
		body = `{"id":"1","event":"message"}`
	}
	if strings.HasSuffix(r.URL.Host, "logic.azure.com") {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	}
	if r.URL.Host == "discord.com" || r.URL.Host == "chat.googleapis.com" {
		return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (m *mockProviders) all() []captured {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]captured(nil), m.requests...)
}

// Destination URLs for the services the title tests cover. Each provider
// host is answered by mockProviders.
const (
	discordURL    = "discord://token@123456789"
	slackURL      = "slack://hook:AAAAAAAAA-BBBBBBBBB-CCCCCCCCCCCCCCCCCCCCCCCC@webhook"
	telegramURL   = "telegram://123456:ABCdef@telegram?chats=-100123"
	gotifyURL     = "gotify://gotify.example/Aabcdefghijklmn"
	pushoverURL   = "pushover://shoutrrr:apitoken@userkey"
	ntfyURL       = "ntfy://ntfy.sh/tailstate"
	pushbulletURL = "pushbullet://o.tokentokentokentokentokentokent1"
	teamsURL      = "teams://?host=https%3A%2F%2Fprod-00.westus.logic.azure.com%2Fworkflows%2Fabc%2Ftriggers%2Fmanual%2Fpaths%2Finvoke"
	googleChatURL = "googlechat://chat.googleapis.com/v1/spaces/FOO/messages?key=bar&token=baz"
	wecomURL      = "wecom://abc-123"
)

// sentTitle extracts the title a provider received, and the body.
func sentTitle(t *testing.T, scheme string, request captured) (title, body string) {
	t.Helper()
	var payload map[string]any
	switch scheme {
	case "pushover":
		form, _ := url.ParseQuery(request.body)
		return form.Get("title"), form.Get("message")
	case "ntfy":
		// ntfy posts the message as plain text and the title as a header.
		message := request.body
		decoded, err := new(mime.WordDecoder).DecodeHeader(request.header.Get("Title"))
		if err != nil {
			t.Fatalf("ntfy title header %q: %v", request.header.Get("Title"), err)
		}
		return decoded, message
	}
	if err := json.Unmarshal([]byte(request.body), &payload); err != nil {
		t.Fatalf("%s payload is not JSON: %v\n%s", scheme, err, request.body)
	}
	switch scheme {
	case "discord":
		embeds, _ := payload["embeds"].([]any)
		var descriptions []string
		for index, raw := range embeds {
			embed, _ := raw.(map[string]any)
			if index == 0 {
				title, _ = embed["title"].(string)
			}
			description, _ := embed["description"].(string)
			descriptions = append(descriptions, description)
		}
		return title, strings.Join(descriptions, "\n")
	case "slack":
		title, _ = payload["text"].(string)
		var decoded slackPayload
		_ = json.Unmarshal([]byte(request.body), &decoded)
		var sections []string
		for _, block := range decoded.allBlocks() {
			if block.Type == "section" {
				sections = append(sections, block.Text.Text)
			}
		}
		return title, strings.Join(sections, "\n")
	case "telegram":
		text, _ := payload["text"].(string)
		title, body, _ = strings.Cut(text, "\n")
		return strings.TrimSuffix(strings.TrimPrefix(title, "<b>"), "</b>"), body
	case "teams":
		attachments, _ := payload["attachments"].([]any)
		attachment, _ := attachments[0].(map[string]any)
		content, _ := attachment["content"].(map[string]any)
		blocks, _ := content["body"].([]any)
		var lines []string
		for index, raw := range blocks {
			block, _ := raw.(map[string]any)
			text, _ := block["text"].(string)
			if index == 0 {
				title = text
				continue
			}
			lines = append(lines, text)
		}
		return title, strings.Join(lines, "\n")
	case "pushbullet", "gotify":
		title, _ = payload["title"].(string)
		key := "body"
		if scheme == "gotify" {
			key = "message"
		}
		body, _ = payload[key].(string)
		return title, body
	}
	t.Fatalf("no title extractor for %s", scheme)
	return "", ""
}

// TestServicesReceiveTheTailStateTitle is R-044's first and fourth
// acceptance criteria: every service with a title field receives
// TailState's title there, and the body does not repeat it.
func TestServicesReceiveTheTailStateTitle(t *testing.T) {
	message := Context{Label: "lab", Tailnet: "example.com"}.Test(testObservedAt)
	wantTitle := "🧪 TailState test · lab (example.com)"
	for scheme, serviceURL := range map[string]string{
		"discord": discordURL, "slack": slackURL, "telegram": telegramURL, "gotify": gotifyURL,
		"pushover": pushoverURL, "ntfy": ntfyURL, "pushbullet": pushbulletURL, "teams": teamsURL,
	} {
		t.Run(scheme, func(t *testing.T) {
			mock := &mockProviders{}
			prepared := PrepareMessage(message, serviceURL, "")
			if prepared.Title != wantTitle {
				t.Fatalf("prepared title=%q", prepared.Title)
			}
			if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, prepared); err != nil {
				t.Fatalf("send: %v", err)
			}
			requests := mock.all()
			if len(requests) != 1 {
				t.Fatalf("requests=%d", len(requests))
			}
			title, body := sentTitle(t, scheme, requests[0])
			if title != wantTitle {
				t.Fatalf("title=%q, want %q", title, wantTitle)
			}
			if strings.Contains(body, "TailState test ·") || !strings.Contains(body, "notifications are configured correctly") {
				t.Fatalf("body repeats or lost content: %q", body)
			}
		})
	}
}

// TestShoutrrrDefaultTitlesAreReplaced guards the "Shoutrrr notification"
// title that Gotify and Pushbullet showed for every alert.
func TestShoutrrrDefaultTitlesAreReplaced(t *testing.T) {
	for _, serviceURL := range []string{gotifyURL, pushbulletURL} {
		mock := &mockProviders{}
		if err := senderWithTransport(mock).Test(context.Background(), serviceURL); err != nil {
			t.Fatalf("%s: %v", serviceURL, err)
		}
		if requests := mock.all(); len(requests) != 1 || strings.Contains(requests[0].body, "Shoutrrr notification") || !strings.Contains(requests[0].body, "TailState test") {
			t.Fatalf("%s request=%v", serviceURL, requests)
		}
	}
}

// TestServicesWithoutTitleKeyReceiveNoParams is R-044's second acceptance
// criterion. WeCom rejects any parameter it does not know, so passing a
// title would fail the send; TailState passes none and keeps the title in
// the body.
func TestServicesWithoutTitleKeyReceiveNoParams(t *testing.T) {
	message := Context{Tailnet: "example.com"}.Test(testObservedAt)
	for _, serviceURL := range []string{wecomURL, googleChatURL, "rocketchat://rocketchat.example/token/token2", "mattermost://mattermost.example/hooktoken", "zulip://bot%40example.com:key@zulip.example/?stream=ops"} {
		if params := parseDestination(serviceURL).params(Prepared{Title: "a title", Severity: "high"}); params != nil {
			t.Fatalf("%s receives params %v", serviceURL, *params)
		}
		if prepared := PrepareMessage(message, serviceURL, ""); prepared.Title != "" || !strings.HasPrefix(prepared.Message(), prepared.Text) || !strings.Contains(prepared.Text, "TailState test ·") {
			t.Fatalf("%s prepared=%+v", serviceURL, prepared)
		}
	}
	for _, serviceURL := range []string{wecomURL, googleChatURL} {
		mock := &mockProviders{}
		if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, PrepareMessage(message, serviceURL, "")); err != nil {
			t.Fatalf("%s: %v", serviceURL, err)
		}
		if requests := mock.all(); len(requests) != 1 || !strings.Contains(requests[0].body, "TailState test ·") {
			t.Fatalf("%s did not receive the title in the body: %v", serviceURL, requests)
		}
	}
	// The control: Shoutrrr fails a WeCom send that carries a title.
	sender, err := shoutrrr.CreateSenderWithOptions(types.SenderOptions{HTTPClient: &http.Client{Transport: &mockProviders{}}, Timeout: time.Second}, wecomURL)
	if err != nil {
		t.Fatal(err)
	}
	if errs := sender.Send("x", &types.Params{"title": "t"}); errs[0] == nil {
		t.Fatal("Shoutrrr accepted an unknown WeCom parameter; the allowlist premise changed")
	}
}

// TestOperatorTitleInURLWins is R-044's third acceptance criterion: a title
// set in the destination URL is kept, and TailState's title then stays in the
// body.
func TestOperatorTitleInURLWins(t *testing.T) {
	message := Context{Tailnet: "example.com"}.Test(testObservedAt)
	for _, serviceURL := range []string{discordURL + "?title=Ops+alerts", gotifyURL + "?Title=Ops+alerts", "smtp://mail.example:25/?from=a@example.com&to=b@example.com&subject=Ops+alerts"} {
		prepared := PrepareMessage(message, serviceURL, "")
		if prepared.Title != "" || prepared.Message() != prepared.Text || !strings.Contains(prepared.Text, "TailState test ·") {
			t.Fatalf("%s prepared=%+v", serviceURL, prepared)
		}
		if params := parseDestination(serviceURL).params(Prepared{Title: "TailState"}); params != nil && ((*params)["title"] != "" || (*params)["subject"] != "") {
			t.Fatalf("%s overrides the operator title: %v", serviceURL, *params)
		}
	}
	mock := &mockProviders{}
	serviceURL := discordURL + "?title=Ops+alerts"
	if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, PrepareMessage(message, serviceURL, "")); err != nil {
		t.Fatal(err)
	}
	title, body := sentTitle(t, "discord", mock.all()[0])
	if title != "Ops alerts" || !strings.Contains(body, "TailState test ·") {
		t.Fatalf("title=%q body=%q", title, body)
	}
}

// TestTitleParameterRules covers the per-service conditions and encodings.
func TestTitleParameterRules(t *testing.T) {
	message := Message{Icon: "🧪", Title: "Title with\x00control", Scope: strings.Repeat("s", 300), Lines: []Line{line(lit("body"))}}
	title := plainTitle(message)
	if len(title) > maxTitleBytes || strings.ContainsAny(title, "\x00 \n") || !strings.HasPrefix(title, "🧪 Title with control · s") {
		t.Fatalf("plain title=%q", title)
	}
	if got := encodeTitle("slack", "a <!channel> & b"); got != "a &lt;!channel&gt; &amp; b" {
		t.Fatalf("slack title=%q", got)
	}
	if got := encodeTitle("ntfy", "plain"); got != "plain" {
		t.Fatalf("ascii ntfy title encoded: %q", got)
	}
	for serviceURL, want := range map[string]bool{
		telegramURL:                                                   true,
		telegramURL + "&parsemode=None":                               true,
		telegramURL + "&parsemode=Markdown":                           false,
		telegramURL + "&ParseMode=HTML":                               false,
		discordURL + "?json=yes":                                      false,
		discordURL + "?json=no":                                       true,
		"smtp://mail.example:25/?from=a@example.com&to=b@example.com": true,
		"generic+https://hooks.example/x":                             false,
		"%%invalid":                                                   false,
	} {
		if got := parseDestination(serviceURL).sendsTitleSeparately(); got != want {
			t.Errorf("%s separate=%t, want %t", serviceURL, got, want)
		}
	}
	if got := parseDestination("smtp://mail.example:25/?from=a@example.com&to=b@example.com").paramKey(paramTitle); got != "subject" {
		t.Fatalf("smtp title key=%q", got)
	}
	if prepared := PrepareMessage(Text("### legacy\nbody"), discordURL, ""); prepared.Title != "" || prepared.Message() != "### legacy\nbody" {
		t.Fatalf("pre-rendered text was split: %+v", prepared)
	}
	if prepared := PrepareMessage(Message{Title: "only a title"}, discordURL, ""); prepared.Title != "" {
		t.Fatalf("message without body lost its only line: %+v", prepared)
	}
	// A legacy row is delivered unchanged, with no separate title.
	if prepared, err := PrepareFor(PayloadMarkdown, "### legacy", discordURL, ""); err != nil || prepared.Title != "" || prepared.Message() != "### legacy" {
		t.Fatalf("legacy row prepared=%+v err=%v", prepared, err)
	}
}

// TestDeliverFallsBackToTheCompleteText keeps injected senders without title
// support receiving the whole message.
func TestDeliverFallsBackToTheCompleteText(t *testing.T) {
	prepared := PrepareMessage(Context{Tailnet: "example.com"}.Test(testObservedAt), discordURL, "")
	recorder := &textRecorder{}
	if err := Deliver(context.Background(), recorder, discordURL, prepared); err != nil || recorder.message != prepared.Text || !strings.HasPrefix(recorder.message, "### 🧪 TailState test") {
		t.Fatalf("fallback message=%q err=%v", recorder.message, err)
	}
}

type textRecorder struct{ message string }

func (r *textRecorder) Send(_ context.Context, _ string, message string) error {
	r.message = message
	return nil
}
func (r *textRecorder) Test(context.Context, string) error { return nil }

// smtpServer is a minimal SMTP server that records the DATA of one message.
type smtpServer struct {
	listener net.Listener
	mu       sync.Mutex
	data     []string
}

func newSMTPServer(t *testing.T) *smtpServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &smtpServer{listener: listener}
	go server.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (s *smtpServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *smtpServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	write := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	write("220 mock ESMTP")
	for {
		command, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.Fields(command + " x")[0])
		switch verb {
		case "EHLO", "HELO":
			write("250-mock")
			write("250 8BITMIME")
		case "DATA":
			write("354 go ahead")
			var data strings.Builder
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == ".\r\n" {
					break
				}
				data.WriteString(line)
			}
			s.mu.Lock()
			s.data = append(s.data, data.String())
			s.mu.Unlock()
			write("250 queued")
		case "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func (s *smtpServer) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.data...)
}

// TestSMTPReceivesSubject is R-044's SMTP acceptance criterion: e-mail gets
// the TailState title as its subject instead of an empty one.
func TestSMTPReceivesSubject(t *testing.T) {
	server := newSMTPServer(t)
	base := "smtp://" + server.listener.Addr().String() + "/?from=tailstate@example.com&to=ops@example.com&encryption=None&usestarttls=No&auth=None"
	message := Context{Tailnet: "example.com"}.Test(testObservedAt)
	if err := New().SendPrepared(context.Background(), base, PrepareMessage(message, base, "")); err != nil {
		t.Fatalf("send: %v", err)
	}
	operator := base + "&subject=Ops"
	if err := New().SendPrepared(context.Background(), operator, PrepareMessage(message, operator, "")); err != nil {
		t.Fatalf("send with operator subject: %v", err)
	}
	messages := server.messages()
	if len(messages) != 2 {
		t.Fatalf("messages=%d", len(messages))
	}
	subjects := make([]string, 0, 2)
	for _, data := range messages {
		for _, header := range strings.Split(data, "\r\n") {
			if value, ok := strings.CutPrefix(header, "Subject: "); ok {
				decoded, err := new(mime.WordDecoder).DecodeHeader(value)
				if err != nil {
					t.Fatal(err)
				}
				subjects = append(subjects, decoded)
			}
		}
	}
	sort.Strings(subjects)
	if !slices.Equal(subjects, []string{"Ops", "🧪 TailState test · example.com"}) {
		t.Fatalf("subjects=%q", subjects)
	}
	if strings.Count(messages[0]+messages[1], "TailState test · example.com") > 2 {
		t.Fatalf("subject repeated in the TailState-titled body")
	}
}

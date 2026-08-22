package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackingBody struct{ closed bool }

func (b *trackingBody) Read([]byte) (int, error) { return 0, errors.New("end") }
func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

func TestNotifyTestAndErrorHelpers(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serviceURL := strings.Replace(server.URL, "http://", "generic://", 1) + "?disabletls=true&template=json&messagekey=text"
	if err := New().Test(context.Background(), serviceURL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "notifications are configured correctly") {
		t.Fatalf("test payload=%q", body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New().Send(ctx, serviceURL, "message"); err != context.Canceled {
		t.Fatalf("canceled send error=%v", err)
	}
	if got := (&DeliveryError{Message: "delivery failed"}).Error(); got != "delivery failed" {
		t.Fatalf("delivery error=%q", got)
	}
	if err := Validate(""); err == nil {
		t.Fatal("empty notification URL was accepted")
	}
	if statusCode("provider failed without an HTTP status") != 0 || statusCode("provider returned 503") != 503 {
		t.Fatal("status code parser returned incorrect values")
	}
	for raw, want := range map[string]string{"%%%": "<redacted>", "mattermost:///path": "mattermost://<redacted>", "mattermost://host:8443/path": "mattermost://host:8443"} {
		if got := RedactURL(raw); got != want {
			t.Fatalf("RedactURL(%q)=%q, want %q", raw, got, want)
		}
	}
	if _, err := ConvertLegacyMattermostURL("ftp://mattermost.example/hooks/token"); err == nil {
		t.Fatal("non-http Mattermost URL was accepted")
	}
	if _, err := ConvertLegacyMattermostURL("https://"); err == nil {
		t.Fatal("missing-host Mattermost URL was accepted")
	}
	native, err := ConvertLegacyMattermostURL("http://mattermost.example/hooks/token")
	if err != nil || !strings.HasPrefix(native, "mattermost://TailState@mattermost.example/token") || !strings.Contains(native, "disabletls=true") {
		t.Fatalf("native HTTP conversion=%q err=%v", native, err)
	}
	if got := truncate(strings.Repeat("x", 501), 500); len(got) > 500 || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncate output length=%d", len(got))
	}
	if got := RedactError("provider rejected mattermost://TailState@host/token?secret=hidden", "mattermost://TailState@host/token?secret=hidden"); strings.Contains(got, "hidden") {
		t.Fatalf("RedactError leaked destination credential: %q", got)
	}
	if got := SafeDeliveryError(&DeliveryError{Status: http.StatusBadGateway, Message: "provider body contains secret"}); got != "notification delivery failed with HTTP 502" {
		t.Fatalf("safe HTTP delivery reason=%q", got)
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: "notification delivery failed"},
		{name: "status in generic error", err: errors.New("provider returned 429 while busy"), want: "notification delivery failed with HTTP 429"},
		{name: "deadline", err: errors.New("context deadline exceeded"), want: "notification delivery timed out"},
		{name: "timeout", err: errors.New("socket timeout"), want: "notification delivery timed out"},
		{name: "canceled", err: errors.New("request canceled by caller"), want: "notification delivery canceled"},
		{name: "cancelled", err: errors.New("request cancelled by caller"), want: "notification delivery canceled"},
		{name: "unknown", err: errors.New("provider rejected the request"), want: "notification delivery failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeDeliveryError(tc.err); got != tc.want {
				t.Fatalf("SafeDeliveryError(%v)=%q, want %q", tc.err, got, tc.want)
			}
		})
	}
	if got := SafeDeliveryMessage("upstream response contains an unrelated credential"); got != "notification delivery failed" {
		t.Fatalf("safe generic delivery reason=%q", got)
	}
	if got := SafeDeliveryMessage("request timeout after 15s"); got != "notification delivery timed out" {
		t.Fatalf("safe timeout delivery reason=%q", got)
	}
	if got := SafeDeliveryMessage("no notification destination configured"); got != "no notification destination configured" {
		t.Fatalf("safe migration delivery reason=%q", got)
	}
	if got := SafeDeliveryMessage("monitoring identity changed"); got != "monitoring identity changed" {
		t.Fatalf("safe identity-change delivery reason=%q", got)
	}
	if got := SafeDeliveryMessage("collector reconciliation failed"); got != "collector reconciliation failed" {
		t.Fatalf("safe reconciliation delivery reason=%q", got)
	}
	if got := SafeDeliveryMessage("reconciliation retry window expired"); got != "reconciliation retry window expired" {
		t.Fatalf("safe reconciliation expiry reason=%q", got)
	}
	if got := SafeTestError(&DeliveryError{Status: http.StatusBadGateway, Message: "provider body contains secret"}); got != "notification delivery failed with HTTP 502" {
		t.Fatalf("safe notification test reason=%q", got)
	}
	if got := SafeTestError(errors.New("invalid notification URL (generic://host)"), "generic://host"); got != "invalid notification URL (generic://<redacted>)" {
		t.Fatalf("validation notification test reason=%q", got)
	}
	if got := SafeTestError(errors.New("provider response contained a secret"), "generic://host/path?token=secret"); got != "notification delivery failed" {
		t.Fatalf("untyped provider notification test reason=%q", got)
	}
	secretURL := "mattermost://TailState:password@chat.example/hooks/secret-token?icon=:satellite:"
	got := SafeTestError(errors.New("provider rejected request for "+secretURL), secretURL)
	if strings.Contains(got, "password") || strings.Contains(got, "secret-token") || strings.Contains(got, ":satellite:") {
		t.Fatalf("notification test error leaked destination credentials: %q", got)
	}
	if got := SafeTestError(errors.New("provider response contained a secret")); got != "notification delivery failed" {
		t.Fatalf("unscoped notification test error=%q", got)
	}
	if got := SafeTestError(nil); got != "" {
		t.Fatalf("nil notification test error=%q", got)
	}
	if got := SafeTestError(errors.New("create notification sender: invalid service"), "generic://host/path?token=secret"); got != "create notification sender: invalid service" {
		t.Fatalf("unredacted sender validation error=%q", got)
	}
	if got := SafeTestError(errors.New("notification URL is required")); got != "notification URL is required" {
		t.Fatalf("missing destination validation was collapsed into a delivery failure: %q", got)
	}
	if got := SafeTestError(errors.New("invalid notification URL (generic://host)")); got != "notification configuration is invalid" {
		t.Fatalf("validation details leaked without a destination URL: %q", got)
	}
}

func TestNewConfiguresBoundedHTTPClient(t *testing.T) {
	sender := New()
	if sender == nil || sender.client == nil {
		t.Fatal("New returned a sender without an HTTP client")
	}
	if sender.client.Timeout != defaultTimeout {
		t.Fatalf("sender timeout=%s, want %s", sender.client.Timeout, defaultTimeout)
	}
	if sender.client.CheckRedirect == nil {
		t.Fatal("sender must disable redirects")
	}
	if err := sender.client.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirect policy allowed a redirect")
	}
	if sender.client.Transport == nil {
		t.Fatal("sender must configure a transport")
	}
}

func TestRejectRedirectTransportHandlesDefaultsErrorsAndRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (rejectRedirectTransport{}).RoundTrip(request)
	if err != nil {
		t.Fatalf("default transport error = %v", err)
	}
	response.Body.Close()

	transportError := errors.New("transport unavailable")
	if _, err := (rejectRedirectTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportError
	})}).RoundTrip(request); !errors.Is(err, transportError) {
		t.Fatalf("transport error = %v", err)
	}
	body := &trackingBody{}
	if _, err := (rejectRedirectTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Status: "302 Found", Body: body}, nil
	})}).RoundTrip(request); err == nil || !strings.Contains(err.Error(), "redirect response 302 Found") {
		t.Fatalf("redirect error = %v", err)
	}
	if !body.closed {
		t.Fatal("redirect response body was not closed")
	}
}

func TestSendReturnsRedactedDeliveryError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	serviceURL := strings.Replace(server.URL, "http://", "generic://", 1) + "/hooks/super-secret?disabletls=true"
	err := New().Send(context.Background(), serviceURL, "hello")
	if err == nil {
		t.Fatal("failed notification unexpectedly succeeded")
	}
	var delivery *DeliveryError
	if !errors.As(err, &delivery) {
		t.Fatalf("error type = %T (%v), want DeliveryError", err, err)
	}
	if delivery.Status != http.StatusBadGateway {
		t.Fatalf("delivery status = %d, want %d", delivery.Status, http.StatusBadGateway)
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), serviceURL) {
		t.Fatalf("delivery error leaked destination: %v", err)
	}
}

func TestSendValidationAndPostDeliveryCancellationIsSuccess(t *testing.T) {
	if err := New().Send(context.Background(), "not-a-shoutrrr-url", "message"); err == nil {
		t.Fatal("invalid notification URL was sent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serviceURL := strings.Replace(server.URL, "http://", "generic://", 1) + "?disabletls=true"
	if err := New().Send(ctx, serviceURL, "message"); err != nil {
		t.Fatalf("post-delivery cancellation was treated as a send failure: %v", err)
	}
}

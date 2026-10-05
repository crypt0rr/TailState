package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func genericURL(server *httptest.Server) string {
	return strings.Replace(server.URL, "http://", "generic://", 1) + "?disabletls=true"
}

// senderWithTransport returns a production sender whose network layer is
// replaced by base, keeping the redirect and recording wrapper in place.
func senderWithTransport(base http.RoundTripper) *SenderImpl {
	sender := New()
	sender.client.Transport = rejectRedirectTransport{base: base}
	return sender
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestDeliveryFailuresNeverParsePortsAsHTTPStatus guards the regression
// where `dial tcp 127.0.0.1:443` was persisted as "HTTP 443".
func TestDeliveryFailuresNeverParsePortsAsHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "refused", err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, Err: errors.New("connect: connection refused")}, want: "notification delivery failed"},
		{name: "timed out", err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, Err: timeoutError{}}, want: "notification delivery timed out"},
		{name: "smtp port", err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 587}, Err: errors.New("connect: connection refused")}, want: "notification delivery failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := senderWithTransport(roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, tc.err }))
			err := sender.Send(context.Background(), "generic://hooks.example.com/path?disabletls=true", "hello")
			var delivery *DeliveryError
			if !errors.As(err, &delivery) {
				t.Fatalf("error type = %T (%v), want DeliveryError", err, err)
			}
			if delivery.Status != 0 || delivery.Permanent || delivery.RetryAfter != 0 {
				t.Fatalf("network failure classified as %+v", delivery)
			}
			if got := SafeDeliveryError(err); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
			if got := SafeDeliveryMessage(err.Error()); got != tc.want {
				t.Fatalf("persisted reason = %q, want %q", got, tc.want)
			}
		})
	}

	// A real refused connection takes the same path.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	err = New().Send(context.Background(), "generic://"+address+"/hook?disabletls=true", "hello")
	if got := SafeDeliveryError(err); got != "notification delivery failed" {
		t.Fatalf("refused connection reason = %q (%v)", got, err)
	}
}

// TestProviderRetryAfterIsRecorded verifies that a rate-limited response
// carries its real status and capped Retry-After hint to the outbox.
func TestProviderRetryAfterIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{header: "120", want: 120 * time.Second},
		{header: "86400", want: maxRetryAfter},
		{header: "soon", want: 0},
		{header: "", want: 0},
	} {
		t.Run(fmt.Sprintf("retry-after %q", tc.header), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set("Retry-After", tc.header)
				}
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()
			err := New().Send(context.Background(), genericURL(server), "hello")
			var delivery *DeliveryError
			if !errors.As(err, &delivery) {
				t.Fatalf("error type = %T (%v), want DeliveryError", err, err)
			}
			if delivery.Status != http.StatusTooManyRequests || delivery.RetryAfter != tc.want || delivery.Permanent {
				t.Fatalf("delivery = %+v, want 429 retryable with RetryAfter %s", delivery, tc.want)
			}
			if got := SafeDeliveryError(err); got != "notification delivery failed with HTTP 429" {
				t.Fatalf("reason = %q", got)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"":                              0,
		"0":                             0,
		"-5":                            0,
		"30":                            30 * time.Second,
		"3600":                          time.Hour,
		"99999999999999999999":          0,
		"Mon, 05 Oct 2026 12:02:00 GMT": 2 * time.Minute,
		"Mon, 05 Oct 2026 11:00:00 GMT": 0,
		"Tue, 06 Oct 2026 12:00:00 GMT": maxRetryAfter,
		"not a date":                    0,
	} {
		if got := parseRetryAfter(value, now); got != want {
			t.Fatalf("parseRetryAfter(%q) = %s, want %s", value, got, want)
		}
	}
}

// TestProviderRejectionsArePermanent verifies that statuses no retry can fix
// are dead-lettered with an allowlisted reason, while transient statuses
// stay retryable.
func TestProviderRejectionsArePermanent(t *testing.T) {
	for _, tc := range []struct {
		status    int
		permanent bool
		reason    string
	}{
		{status: http.StatusBadRequest, permanent: true, reason: "notification rejected by provider (HTTP 400)"},
		{status: http.StatusUnauthorized, permanent: true, reason: "notification rejected by provider (HTTP 401)"},
		{status: http.StatusForbidden, permanent: true, reason: "notification rejected by provider (HTTP 403)"},
		{status: http.StatusNotFound, permanent: true, reason: "notification rejected by provider (HTTP 404)"},
		{status: http.StatusRequestEntityTooLarge, permanent: true, reason: messageTooLargeReason},
		{status: http.StatusTooManyRequests, reason: "notification delivery failed with HTTP 429"},
		{status: http.StatusInternalServerError, reason: "notification delivery failed with HTTP 500"},
		{status: http.StatusServiceUnavailable, reason: "notification delivery failed with HTTP 503"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("provider body with secret-token"))
			}))
			defer server.Close()
			err := New().Send(context.Background(), genericURL(server), "hello")
			var delivery *DeliveryError
			if !errors.As(err, &delivery) || delivery.Status != tc.status {
				t.Fatalf("error = %#v, want DeliveryError with status %d", err, tc.status)
			}
			if IsPermanent(err) != tc.permanent {
				t.Fatalf("IsPermanent = %t, want %t", IsPermanent(err), tc.permanent)
			}
			reason := SafeDeliveryError(err)
			if reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
			// The persistence boundary keeps the reason verbatim.
			if got := SafeDeliveryMessage(reason); got != reason {
				t.Fatalf("SafeDeliveryMessage(%q) = %q", reason, got)
			}
			if got := SafeTestError(err); got != reason {
				t.Fatalf("SafeTestError = %q, want %q", got, reason)
			}
		})
	}
	if got := SafeDeliveryMessage("notification delivery failed with HTTP 443 via secret-token"); got != "notification delivery failed" {
		t.Fatalf("non-exact HTTP reason was trusted: %q", got)
	}
	if got := SafeDeliveryMessage("notification delivery failed with HTTP 502"); got != "notification delivery failed with HTTP 502" {
		t.Fatalf("exact HTTP reason was not preserved: %q", got)
	}
}

// TestRedirectStatusIsRecorded keeps redirect refusals classified by their
// real status instead of by the transport's error text.
func TestRedirectStatusIsRecorded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer server.Close()
	err := New().Send(context.Background(), genericURL(server), "hello")
	if got := SafeDeliveryError(err); got != "notification delivery failed with HTTP 302" || IsPermanent(err) {
		t.Fatalf("redirect reason = %q permanent=%t", got, IsPermanent(err))
	}
}

// TestConcurrentSendsRecordIndependentOutcomes runs one sender against two
// providers at once; each send must report its own provider's status.
func TestConcurrentSendsRecordIndependentOutcomes(t *testing.T) {
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer unauthorized.Close()
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer limited.Close()
	sender := New()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 40 {
		server, want, retryAfter := unauthorized, http.StatusUnauthorized, time.Duration(0)
		if i%2 == 1 {
			server, want, retryAfter = limited, http.StatusTooManyRequests, 7*time.Second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sender.Send(context.Background(), genericURL(server), "hello")
			var delivery *DeliveryError
			if !errors.As(err, &delivery) || delivery.Status != want || delivery.RetryAfter != retryAfter {
				errs <- fmt.Errorf("send to %d provider returned %#v", want, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

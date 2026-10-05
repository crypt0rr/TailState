package tailscale

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordRetryWaits replaces the retry sleep with an immediate one that
// records the requested delays.
func recordRetryWaits(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	delays := []time.Duration{}
	originalWait := waitForRetry
	waitForRetry = func(ctx context.Context, delay time.Duration) bool {
		mu.Lock()
		delays = append(delays, delay)
		mu.Unlock()
		return ctx.Err() == nil
	}
	t.Cleanup(func() { waitForRetry = originalWait })
	return &delays
}

func TestTransientGatewayStatusIsRetried(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			delays := recordRetryWaits(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
				case "/api/v2/tailnet/-/devices":
					if calls.Add(1) == 1 {
						w.Header().Set("Retry-After", "2")
						w.WriteHeader(status)
						return
					}
					_, _ = w.Write([]byte(`{"devices":[{"id":"1"}]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
			resources, err := client.Collect(context.Background(), "devices")
			if err != nil || len(resources) != 1 {
				t.Fatalf("single %d followed by 200 failed: resources=%#v err=%v", status, resources, err)
			}
			if calls.Load() != 2 || len(*delays) != 1 || (*delays)[0] != 2*time.Second {
				t.Fatalf("calls=%d delays=%v, want one retry honoring Retry-After", calls.Load(), *delays)
			}
		})
	}
}

func TestPersistentGatewayStatusReportsUpstreamError(t *testing.T) {
	delays := recordRetryWaits(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	_, err := client.Collect(context.Background(), "devices")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusServiceUnavailable {
		t.Fatalf("persistent 503 error=%v", err)
	}
	if calls.Load() != 4 || len(*delays) != 3 {
		t.Fatalf("calls=%d delays=%v, want 4 attempts with 3 backoff waits", calls.Load(), *delays)
	}
	for i, delay := range *delays {
		if want := time.Duration(1<<i) * time.Second; delay != want {
			t.Fatalf("backoff %d=%s, want %s", i, delay, want)
		}
	}
}

func TestGatewayRetryAfterBeyondBudgetFailsWithoutWaiting(t *testing.T) {
	delays := recordRetryWaits(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	_, err := client.Collect(context.Background(), "devices")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusGatewayTimeout {
		t.Fatalf("over-budget Retry-After error=%v", err)
	}
	if len(*delays) != 0 {
		t.Fatalf("waited %v although Retry-After exceeds the 30 second request budget", *delays)
	}
}

func TestTransientTokenFailureIsRetried(t *testing.T) {
	recordRetryWaits(t)
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if tokenCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if resources, err := client.Collect(context.Background(), "devices"); err != nil || len(resources) != 1 {
		t.Fatalf("token 503 then success failed: resources=%#v err=%v", resources, err)
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("token calls=%d, want 2", tokenCalls.Load())
	}
}

func TestTokenFailureClassification(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		transient bool
	}{
		{"rate limited", &oauthStatusError{Status: http.StatusTooManyRequests, RetryAfter: "3"}, true},
		{"server error", &oauthStatusError{Status: http.StatusInternalServerError}, true},
		{"bad credentials", &oauthStatusError{Status: http.StatusUnauthorized}, false},
		{"network", &oauthTransportError{Err: errors.New("connection reset")}, true},
		{"cancelled", &oauthTransportError{Err: context.Canceled}, false},
		{"malformed", errors.New("unexpected end of JSON input"), false},
	}
	for _, tc := range cases {
		delay, transient := transientTokenDelay(tc.err, 1)
		if transient != tc.transient {
			t.Fatalf("%s transient=%v, want %v", tc.name, transient, tc.transient)
		}
		if tc.name == "rate limited" && delay != 3*time.Second {
			t.Fatalf("token Retry-After delay=%s", delay)
		}
		if tc.name == "network" && delay != 2*time.Second {
			t.Fatalf("token backoff delay=%s", delay)
		}
	}
	if got := (&oauthTransportError{Err: context.Canceled}); !errors.Is(got, context.Canceled) {
		t.Fatal("transport error does not unwrap")
	}
}

func TestPermanentTokenFailureIsNotRetried(t *testing.T) {
	delays := recordRetryWaits(t)
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "devices"); err == nil || err.Error() != "OAuth token request returned 400" {
		t.Fatalf("permanent token error=%v", err)
	}
	if tokenCalls.Load() != 1 || len(*delays) != 0 {
		t.Fatalf("token calls=%d waits=%v, want no retry for a 400", tokenCalls.Load(), *delays)
	}
}

func TestCursorPaginationKeepsOriginalQuery(t *testing.T) {
	var pageTwoQuery atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			if r.URL.Query().Get("cursor") == "page-2" {
				pageTwoQuery.Store(r.URL.RawQuery)
				if r.URL.Query().Get("fields") != "all" {
					_, _ = w.Write([]byte(`{"devices":[{"id":"2"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"devices":[{"id":"2","hostname":"two","advertisedRoutes":[]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"devices":[{"id":"1","hostname":"one"}],"pagination":{"nextCursor":"page-2"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "devices")
	if err != nil || len(resources) != 2 {
		t.Fatalf("cursor pagination resources=%#v err=%v", resources, err)
	}
	if got, _ := pageTwoQuery.Load().(string); got != "cursor=page-2&fields=all" {
		t.Fatalf("page 2 query=%q, want fields=all preserved", got)
	}
	if resources[1].Name != "two" {
		t.Fatalf("page 2 device lost its fields: %#v", resources[1])
	}
}

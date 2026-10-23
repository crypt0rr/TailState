package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func slowDeviceDetailsServer(t *testing.T, devices int, delay time.Duration) *httptest.Server {
	t.Helper()
	items := make([]string, 0, devices)
	for i := 0; i < devices; i++ {
		items = append(items, fmt.Sprintf(`{"id":"d%d","hostname":"d%d"}`, i, i))
	}
	list := `{"devices":[` + strings.Join(items, ",") + `]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(list))
		default:
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestDeviceDetailsDeadlineCountsEveryMissingDevice(t *testing.T) {
	previousTimeout := deviceDetailsPollTimeout
	deviceDetailsPollTimeout = 250 * time.Millisecond
	t.Cleanup(func() { deviceDetailsPollTimeout = previousTimeout })
	const devices = 40
	server := slowDeviceDetailsServer(t, devices, 30*time.Millisecond)
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := client.Collect(context.Background(), "device_details")
	var partial *PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("deadline-limited device_details returned err=%v with %d of %d devices", err, len(resources), devices)
	}
	if len(resources) >= devices {
		t.Fatalf("test server was too fast to exercise the deadline: %d resources", len(resources))
	}
	if want := devices - len(resources); partial.Count != want {
		t.Fatalf("partial count=%d, want %d missing devices (returned %d)", partial.Count, want, len(resources))
	}
}

func TestDeviceDetailsDeadlineEventuallyRefreshesEveryDevice(t *testing.T) {
	previousTimeout := deviceDetailsPollTimeout
	deviceDetailsPollTimeout = 250 * time.Millisecond
	t.Cleanup(func() { deviceDetailsPollTimeout = previousTimeout })
	const devices = 40
	server := slowDeviceDetailsServer(t, devices, 30*time.Millisecond)
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	refreshed := map[string]bool{}
	for poll := 0; poll < 30 && len(refreshed) < devices; poll++ {
		client.BeginPoll()
		resources, _ := client.Collect(context.Background(), "device_details")
		for _, resource := range resources {
			refreshed[resource.ID] = true
		}
	}
	if len(refreshed) != devices {
		missing := make([]string, 0)
		for i := 0; i < devices; i++ {
			if id := fmt.Sprintf("d%d", i); !refreshed[id] {
				missing = append(missing, id)
			}
		}
		t.Fatalf("repeated deadline-limited polls starved devices %v", missing)
	}
}

func TestDeviceDetailsExpiredDeadlineNeverLooksComplete(t *testing.T) {
	server := slowDeviceDetailsServer(t, 12, time.Millisecond)
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	devices := make([]map[string]any, 0, 12)
	for i := 0; i < 12; i++ {
		devices = append(devices, map[string]any{"id": fmt.Sprintf("d%d", i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resources, err := client.deviceDetailsFromDevices(ctx, devices)
	var partial *PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expired deadline returned err=%v with %d resources", err, len(resources))
	}
	if partial.Count != len(devices)-len(resources) {
		t.Fatalf("partial count=%d, want %d", partial.Count, len(devices)-len(resources))
	}
}

// refusedDetailClient answers every attributes request with status and counts
// those requests. A 429 carries a Retry-After beyond the 30 second request
// budget, so the transport reports it at once instead of waiting. Device
// invites always succeed.
func refusedDetailClient(t *testing.T, status int) (*Client, *atomic.Int32) {
	t.Helper()
	var attributeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case strings.HasSuffix(r.URL.Path, "/attributes"):
			attributeCalls.Add(1)
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(status)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	return client, &attributeCalls
}

// deviceListMaps returns n device maps with ids d0 to d(n-1) in API order.
func deviceListMaps(n int) []map[string]any {
	devices := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		devices = append(devices, map[string]any{"id": fmt.Sprintf("d%d", i)})
	}
	return devices
}

// TestDeviceDetailsRateLimitStopsFanOut covers a rate limit that outlasts the
// request budget. The fan-out must end after about one request per worker
// instead of one per device, report the missing devices as a PartialError, and
// leave the devices it did not refresh at the front of the next poll.
func TestDeviceDetailsRateLimitStopsFanOut(t *testing.T) {
	const devices = 50
	client, attributeCalls := refusedDetailClient(t, http.StatusTooManyRequests)
	list := deviceListMaps(devices)
	// d0 to d9 were refreshed by an earlier poll, so d10 onward are the stalest.
	earlier := make([]int, 0, 10)
	for i := 0; i < 10; i++ {
		earlier = append(earlier, i)
	}
	client.recordDeviceDetailAttempts(list, earlier)
	before := client.deviceDetailOrder(list)

	resources, err := client.deviceDetailsFromDevices(context.Background(), list)
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Count != devices || len(resources) != 0 {
		t.Fatalf("rate-limited fan-out returned %d resources, err=%v; want a PartialError missing all %d devices", len(resources), err, devices)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusTooManyRequests {
		t.Fatalf("rate-limited fan-out error=%v, want the upstream 429", err)
	}
	if got := attributeCalls.Load(); got == 0 || got > deviceDetailWorkers {
		t.Fatalf("attribute requests=%d, want at most %d (one per worker) for %d devices", got, deviceDetailWorkers, devices)
	}
	if after := client.deviceDetailOrder(list); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("refresh order after the rate limit=%v, want %v", after, before)
	}
}

// TestDeviceDetailsCredentialStatusScope separates two refusals that share the
// detail endpoints. A rejected credential stops the fan-out, while a 403 marks
// the subresource unsupported and every device is still reported.
func TestDeviceDetailsCredentialStatusScope(t *testing.T) {
	const devices = 50
	t.Run("rejected credential stops the fan-out", func(t *testing.T) {
		client, attributeCalls := refusedDetailClient(t, http.StatusUnauthorized)
		resources, err := client.deviceDetailsFromDevices(context.Background(), deviceListMaps(devices))
		var partial *PartialError
		if !errors.As(err, &partial) || partial.Count != devices || len(resources) != 0 {
			t.Fatalf("rejected credential returned %d resources, err=%v; want a PartialError missing all %d devices", len(resources), err, devices)
		}
		if got := FailureCategory(err); got != FailureAuthRejected {
			t.Fatalf("failure category=%q, want %q", got, FailureAuthRejected)
		}
		if got := attributeCalls.Load(); got >= devices {
			t.Fatalf("attribute requests=%d for %d devices; the rejected credential did not stop the fan-out", got, devices)
		}
	})
	t.Run("forbidden detail stays per device", func(t *testing.T) {
		client, attributeCalls := refusedDetailClient(t, http.StatusForbidden)
		resources, err := client.deviceDetailsFromDevices(context.Background(), deviceListMaps(devices))
		if err != nil || len(resources) != devices {
			t.Fatalf("forbidden detail returned %d resources, err=%v; want all %d devices", len(resources), err, devices)
		}
		if got := attributeCalls.Load(); got != devices {
			t.Fatalf("attribute requests=%d, want one per device (%d)", got, devices)
		}
	})
}

func TestDeviceDetailOrderPrefersStalestDevices(t *testing.T) {
	client := New("http://invalid.example", "http://invalid.example/token", "test", Credentials{})
	devices := []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}}
	if got := client.deviceDetailOrder(devices); fmt.Sprint(got) != "[0 1 2 3]" {
		t.Fatalf("initial order=%v", got)
	}
	client.recordDeviceDetailAttempts(devices, []int{0, 1})
	if got := client.deviceDetailOrder(devices); fmt.Sprint(got) != "[2 3 0 1]" {
		t.Fatalf("order after refreshing a,b=%v", got)
	}
	client.recordDeviceDetailAttempts(devices, []int{2})
	if got := client.deviceDetailOrder(devices); fmt.Sprint(got) != "[3 0 1 2]" {
		t.Fatalf("order after refreshing c=%v", got)
	}
	// Devices that left the list are forgotten.
	client.recordDeviceDetailAttempts(devices[3:], nil)
	if len(client.detailAttempt) != 0 {
		t.Fatalf("stale device attempts retained: %#v", client.detailAttempt)
	}
}

package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

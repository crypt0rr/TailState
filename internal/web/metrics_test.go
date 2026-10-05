package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

func scrapeMetrics(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

var (
	metricSampleLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (\S+)$`)
	metricHeaderLine = regexp.MustCompile(`^# (HELP|TYPE) ([a-zA-Z_:][a-zA-Z0-9_:]*) (.+)$`)
)

// lintExposition applies the structural rules `promtool check metrics`
// enforces for the text format: every family has HELP and TYPE before its
// samples, is declared once, keeps its samples contiguous, uses a known type,
// and counters end in _total.
func lintExposition(t *testing.T, body string) map[string]string {
	t.Helper()
	types := map[string]string{}
	helps := map[string]bool{}
	closed := map[string]bool{}
	current := ""
	for number, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if header := metricHeaderLine.FindStringSubmatch(line); header != nil {
			name := header[2]
			if closed[name] {
				t.Fatalf("line %d: family %s is declared again after other families", number+1, name)
			}
			if name != current && current != "" {
				closed[current] = true
			}
			current = name
			switch header[1] {
			case "HELP":
				if helps[name] {
					t.Fatalf("line %d: duplicate HELP for %s", number+1, name)
				}
				helps[name] = true
			case "TYPE":
				if _, ok := types[name]; ok {
					t.Fatalf("line %d: duplicate TYPE for %s", number+1, name)
				}
				switch header[3] {
				case "counter", "gauge", "histogram", "summary":
				default:
					t.Fatalf("line %d: unknown type %q", number+1, header[3])
				}
				if header[3] == "counter" && !strings.HasSuffix(name, "_total") {
					t.Fatalf("line %d: counter %s does not end in _total", number+1, name)
				}
				types[name] = header[3]
			}
			continue
		}
		sample := metricSampleLine.FindStringSubmatch(line)
		if sample == nil {
			t.Fatalf("line %d is not a valid sample: %q", number+1, line)
		}
		family := sample[1]
		if _, ok := types[family]; !ok {
			for _, suffix := range []string{"_bucket", "_sum", "_count"} {
				base := strings.TrimSuffix(family, suffix)
				if kind := types[base]; base != family && (kind == "histogram" || kind == "summary") {
					family = base
					break
				}
			}
		}
		if _, ok := types[family]; !ok || !helps[family] {
			t.Fatalf("line %d: sample %s has no preceding HELP and TYPE", number+1, sample[1])
		}
		if family != current {
			t.Fatalf("line %d: sample for %s appears inside family %s", number+1, family, current)
		}
	}
	for name := range types {
		if !helps[name] {
			t.Fatalf("family %s has TYPE but no HELP", name)
		}
	}
	return types
}

// TestMetricsExpositionDeclaresEveryFamily checks the complete exposition,
// including per-collector and resource families, against the text format
// rules that promtool enforces.
func TestMetricsExpositionDeclaresEveryFamily(t *testing.T) {
	server, st, _ := testServer(t)
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordCollectorFailure(context.Background(), 1, "devices", "failure"); err != nil {
		t.Fatal(err)
	}
	response := scrapeMetrics(t, server)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Length") == "" {
		t.Fatal("metrics response was not written in one piece")
	}
	types := lintExposition(t, response.Body.String())
	for name, kind := range map[string]string{
		"tailstate_resources":                        "gauge",
		"tailstate_notification_state":               "gauge",
		"tailstate_cleanup_duration_seconds":         "summary",
		"tailstate_outbox_delivery_duration_seconds": "histogram",
		"tailstate_collector_supported":              "gauge",
		"tailstate_storage_limit_enforced":           "gauge",
	} {
		if types[name] != kind {
			t.Fatalf("family %s type=%q, want %q", name, types[name], kind)
		}
	}

	// Exercise every optional sample (timestamps, resources) as well.
	now := time.Now()
	status := store.Status{
		Configured:     true,
		ResourceCounts: map[string]int{"users": 2, "devices": 3},
		Collectors: []store.CollectorState{
			{Name: "devices", Supported: true, Baseline: true, LastSuccess: &now, NextPoll: &now, PollDurationMS: 1500},
			{Name: "users", Partial: true, PartialErrorCount: 2},
		},
	}
	var body bytes.Buffer
	server.writeMetrics(&body, status, store.StorageMetrics{DatabaseLimitBytes: 1}, store.DefaultStorageLimits())
	lintExposition(t, body.String())
	for _, want := range []string{
		"tailstate_resources{collector=\"devices\"} 3\ntailstate_resources{collector=\"users\"} 2\n",
		"tailstate_collector_last_success_timestamp_seconds{collector=\"devices\"}",
		"tailstate_collector_poll_duration_seconds{collector=\"devices\"} 1.500",
		"tailstate_collector_partial_errors{collector=\"users\"} 2",
	} {
		if !strings.Contains(body.String(), want) {
			t.Fatalf("exposition missing %q:\n%s", want, body.String())
		}
	}
}

// TestMetricsStorageErrorIsACleanFailure proves a failure after status was
// loaded yields a 500 with no partial exposition.
func TestMetricsStorageErrorIsACleanFailure(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	// Replace the WAL sidecar's directory entry with a directory: SQLite keeps
	// its open descriptor, Status still succeeds, and the physical storage
	// probe fails.
	if err := os.Remove(path + "-wal"); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+"-wal", 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path + "-wal") })
	if _, err := st.Status(context.Background()); err != nil {
		t.Fatalf("status should still load: %v", err)
	}
	response := scrapeMetrics(t, server)
	body := response.Body.String()
	if response.Code != http.StatusInternalServerError || strings.TrimSpace(body) != "metrics unavailable" {
		t.Fatalf("storage failure status=%d body=%q", response.Code, body)
	}
	if strings.Contains(body, "tailstate_") {
		t.Fatalf("storage failure leaked a partial exposition: %q", body)
	}
}

// TestNotificationStateAgreesAcrossSurfaces walks every destination state
// and checks that the Settings banner, diagnostics, and metrics agree.
func TestNotificationStateAgreesAcrossSurfaces(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	ctx := context.Background()

	check := func(t *testing.T, want diagnostics.NotificationState) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/settings", nil)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		page := httptest.NewRecorder()
		server.Handler().ServeHTTP(page, request)
		body := page.Body.String()
		noDestinationBanner := strings.Contains(body, "no destination is configured")
		disabledBanner := strings.Contains(body, "every destination is disabled")
		switch want {
		case diagnostics.NotificationsNoDestinations:
			if !noDestinationBanner || disabledBanner {
				t.Fatalf("settings banner for %s: no-destination=%v disabled=%v", want, noDestinationBanner, disabledBanner)
			}
		case diagnostics.NotificationsPaused:
			if noDestinationBanner || !disabledBanner {
				t.Fatalf("settings banner for %s: no-destination=%v disabled=%v", want, noDestinationBanner, disabledBanner)
			}
		default:
			if noDestinationBanner || disabledBanner {
				t.Fatalf("settings banner for %s: no-destination=%v disabled=%v", want, noDestinationBanner, disabledBanner)
			}
		}

		report := server.diagnosticReport(ctx, nil)
		codes := map[string]bool{}
		for _, finding := range report.Findings {
			codes[finding.Code] = true
		}
		if codes["notifications_no_destinations"] != (want == diagnostics.NotificationsNoDestinations) || codes["notifications_paused"] != (want == diagnostics.NotificationsPaused) {
			t.Fatalf("diagnostics for %s: findings=%v", want, codes)
		}

		metrics := scrapeMetrics(t, server).Body.String()
		for _, state := range diagnostics.NotificationStates {
			value := "0"
			if state == want {
				value = "1"
			}
			if line := `tailstate_notification_state{state="` + string(state) + `"} ` + value; !strings.Contains(metrics, line) {
				t.Fatalf("metrics for %s missing %q", want, line)
			}
		}
		paused := "tailstate_notifications_paused 0"
		if want.Paused() {
			paused = "tailstate_notifications_paused 1"
		}
		if !strings.Contains(metrics, paused) {
			t.Fatalf("metrics for %s missing %q", want, paused)
		}
	}

	t.Run("unconfigured", func(t *testing.T) { check(t, diagnostics.NotificationsUnconfigured) })
	id, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Primary", ServiceURL: "mattermost://TailState@example.invalid/token?disabletls=true", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	t.Run("active", func(t *testing.T) { check(t, diagnostics.NotificationsActive) })
	if err := st.SetDestinationEnabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	t.Run("paused", func(t *testing.T) { check(t, diagnostics.NotificationsPaused) })
	if err := st.DeleteDestination(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Run("no destinations", func(t *testing.T) { check(t, diagnostics.NotificationsNoDestinations) })
}

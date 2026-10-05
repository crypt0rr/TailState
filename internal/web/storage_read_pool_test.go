package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestHealthzRespondsDuringLongWriteTransaction reproduces the original
// stall: another process holds the SQLite write lock, so a store write keeps
// the service's single writer connection busy for up to busy_timeout. Health,
// readiness, metrics, and History must still answer promptly.
func TestHealthzRespondsDuringLongWriteTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	setupToken, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	cookies := claimCoverageAdmin(t, server, setupToken)
	// A configured installation makes the status page read the expiry
	// options and snapshots for its "Expiring soon" card.
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}

	// API tokens and their status/history reads use the read-only pool;
	// the first use's last-used touch is bounded and best effort.
	_, apiToken, err := st.CreateAPIToken(context.Background(), "SIEM", []string{store.ScopeStatusRead, store.ScopeHistoryRead}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	locker, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { locker.Close() })
	tx, err := locker.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE meta SET value=value WHERE key='master_key_check'"); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, _, err := st.CreateSession(context.Background())
		writeDone <- err
	}()
	// Give the write time to take the writer connection and start waiting.
	time.Sleep(100 * time.Millisecond)

	for _, route := range []string{"/healthz", "/readyz", "/metrics", "/history", "/status", "/api/v1/status", "/api/v1/history"} {
		started := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		request := httptest.NewRequest(http.MethodGet, route, nil).WithContext(ctx)
		request.RemoteAddr = "127.0.0.1:1234"
		if route == "/history" || route == "/status" {
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
		}
		if strings.HasPrefix(route, "/api/") {
			request.Header.Set("Authorization", "Bearer "+apiToken)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		cancel()
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("%s took %s while a write was waiting on the lock", route, elapsed)
		}
		switch route {
		case "/readyz":
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "not_ready") {
				t.Fatalf("/readyz returned %d %s", response.Code, response.Body.String())
			}
		default:
			if response.Code != http.StatusOK {
				t.Fatalf("%s returned %d during a write: %s", route, response.Code, response.Body.String())
			}
		}
	}
	select {
	case err := <-writeDone:
		t.Fatalf("store write finished while the lock was held (err=%v); the test did not hold the writer", err)
	default:
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("store write failed after the lock was released: %v", err)
	}
}

func TestMetricsExposeUsedAndFreeStorage(t *testing.T) {
	server, _, _ := testServer(t)
	response := scrapeMetrics(t, server)
	body := response.Body.String()
	for _, family := range []string{"tailstate_storage_used_bytes ", "tailstate_storage_freelist_pages ", "tailstate_storage_free_bytes ", "tailstate_storage_bytes "} {
		if !strings.Contains(body, "\n"+family) {
			t.Fatalf("metrics missing %q:\n%s", family, body)
		}
	}
	lintExposition(t, body)
}

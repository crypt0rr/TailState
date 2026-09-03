package web

import (
	"context"
	"database/sql"
	"net"
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

func TestServeReturnsListenErrorAndShutsDown(t *testing.T) {
	server, _, _ := testServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.config.ListenAddr = listener.Addr().String()
	if err := server.Serve(context.Background()); err == nil {
		t.Fatal("Serve succeeded on an occupied address")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	server.config.ListenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve shutdown error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not shut down")
	}
}

func TestStatusRendersAndReportsSettingsFailure(t *testing.T) {
	server, st, setupToken := testServer(t)
	cookies := claimCoverageAdmin(t, server, setupToken)
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "TailState status") {
		t.Fatalf("status response %d: %s", response.Code, response.Body.String())
	}
}

func TestWebInterfaceDisplaysVersion(t *testing.T) {
	server, _, _ := testServer(t)
	for _, page := range []string{"setup", "login", "reset", "status", "history", "settings"} {
		response := httptest.NewRecorder()
		server.render(response, page, pageData{})
		if response.Code != http.StatusOK {
			t.Fatalf("%s page status=%d", page, response.Code)
		}
		if !strings.Contains(response.Body.String(), "Version test") {
			t.Fatalf("%s page does not display the configured version: %s", page, response.Body.String())
		}
	}
}

func TestMetricsReportsStoreFailure(t *testing.T) {
	server, st, _ := testServer(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	server.metrics(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "metrics unavailable") {
		t.Fatalf("metrics failure response %d: %s", response.Code, response.Body.String())
	}
}

func TestCurrentSettingsDataFallsBackWhenStoreIsUnavailable(t *testing.T) {
	server, st, _ := testServer(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	data := server.currentSettingsData(context.Background(), "csrf-token")
	if data.Configured || data.Settings.Tailnet != "-" || data.DeviceSeconds != 60 || data.InventorySeconds != 300 {
		t.Fatalf("fallback settings data=%#v", data)
	}
}

func TestAdminExistsFailsClosedWhenStoreIsUnavailable(t *testing.T) {
	server, st, _ := testServer(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	exists, ok := server.adminExists(response, request)
	if exists || ok || response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed-store admin check exists=%v ok=%v status=%d", exists, ok, response.Code)
	}
}

func TestStatusReportsSettingsLoadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
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
	setupToken, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cookies := claimCoverageAdmin(t, server, setupToken)
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE settings SET oauth_secret_enc='invalid-envelope'"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Baseline") {
		t.Fatalf("status response %d: %s", response.Code, response.Body.String())
	}
}

func TestHistoryExportReportsStoreError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
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
	setupToken, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cookies := claimCoverageAdmin(t, server, setupToken)
	generation, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := db.Exec("INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(?,?,?,?)", generation, now, 1, now)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	batchID, err := result.LastInsertId()
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,?,?,?,?,?,?,?)", batchID, generation, now, "devices", "changed", "device-1", "server", "invalid-json"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/history/export", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "export history") {
		t.Fatalf("history export failure response %d: %s", response.Code, response.Body.String())
	}
}

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := store.Open(filepath.Join(t.TempDir(), "tailstate.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	token, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	engine := monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version)
	server, err := New(config, st, engine)
	if err != nil {
		t.Fatal(err)
	}
	return server, st, token
}

func TestClaimLoginSurfaceAndSecurityHeaders(t *testing.T) {
	server, st, token := testServer(t)
	form := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	request := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("security headers missing")
	}
	exists, _ := st.AdminExists(context.Background())
	if !exists {
		t.Fatal("administrator not created")
	}
	cookies := response.Result().Cookies()
	settingsRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	for _, cookie := range cookies {
		settingsRequest.AddCookie(cookie)
	}
	settingsResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(settingsResponse, settingsRequest)
	if settingsResponse.Code != http.StatusOK || !strings.Contains(settingsResponse.Body.String(), "Monitoring settings") {
		t.Fatalf("settings status %d: %s", settingsResponse.Code, settingsResponse.Body.String())
	}
}

func TestReadyBeforeSetup(t *testing.T) {
	server, _, _ := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status %d", response.Code)
	}
}

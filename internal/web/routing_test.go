package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func routingGet(server *Server, path string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	return response
}

// TestRoutingIsExactAndStoreFree proves the home route no longer acts as a
// catch-all: favicon probes and unknown paths are answered without touching
// the store (it is closed here, so any store call would fail), and the static
// file server does not list directories.
func TestRoutingIsExactAndStoreFree(t *testing.T) {
	server, st, _ := testServer(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	favicon := routingGet(server, "/favicon.ico")
	if favicon.Code != http.StatusNoContent || favicon.Body.Len() != 0 || !strings.Contains(favicon.Header().Get("Cache-Control"), "max-age") {
		t.Fatalf("favicon status=%d cache=%q body=%q", favicon.Code, favicon.Header().Get("Cache-Control"), favicon.Body.String())
	}
	for _, path := range []string{"/does-not-exist", "/status/extra", "/settingsx", "/static/", "/static/missing.css"} {
		if response := routingGet(server, path); response.Code != http.StatusNotFound {
			t.Fatalf("GET %s status=%d location=%q", path, response.Code, response.Header().Get("Location"))
		}
	}
	if response := routingGet(server, "/static/style.css"); response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("static asset status=%d type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	// The root itself still reaches the home handler (which needs the store).
	if response := routingGet(server, "/"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("home with closed store status=%d", response.Code)
	}
}

func TestStaticFilesRejectsEmptyPath(t *testing.T) {
	called := false
	handler := staticFiles(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodGet, "/static/", nil)
	request.URL.Path = ""
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if called || response.Code != http.StatusNotFound {
		t.Fatalf("empty static path status=%d called=%v", response.Code, called)
	}
}

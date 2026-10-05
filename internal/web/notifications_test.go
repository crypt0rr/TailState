package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

func authenticatedGet(t *testing.T, server *Server, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// TestSettingsTestMessageNamesInstanceTailnetAndVersion guards E-010: the
// Settings test message identifies which TailState instance sent it.
func TestSettingsTestMessageNamesInstanceTailnetAndVersion(t *testing.T) {
	server, st, token := testServer(t)
	server.config.InstanceLabel = "lab-eu"
	server.config.Version = "v9.8.7"
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "corp.example", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var body string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(raw)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	serviceURL := strings.Replace(upstream.URL, "http://", "generic://", 1) + "?disabletls=true&template=json&messagekey=text"
	response := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "service_url": {serviceURL}}, cookies)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Notification test sent") {
		t.Fatalf("test status=%d body=%s", response.Code, response.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"TailState test", "lab", "corp.example", "v9.8.7", "Observed at "} {
		if !strings.Contains(body, want) {
			t.Fatalf("test message missing %q: %s", want, body)
		}
	}
}

// TestHistoryBatchFilterShowsOnlyLinkedBatch guards the /history?batch=<id>
// deep link used by digests when TAILSTATE_PUBLIC_URL is set.
func TestHistoryBatchFilterShowsOnlyLinkedBatch(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	ctx := context.Background()
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	apply := func(hostname string) store.ChangeBatchResult {
		batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: hostname, Data: map[string]any{"hostname": hostname}}}}}, notify.TextDigest("digest"))
		if err != nil {
			t.Fatal(err)
		}
		return batch
	}
	apply("baseline")
	first := apply("first-host")
	second := apply("second-host")
	response := authenticatedGet(t, server, fmt.Sprintf("/history?batch=%d", first.ID), cookies)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, fmt.Sprintf("Batch #%d", first.ID)) || strings.Contains(body, fmt.Sprintf("Batch #%d", second.ID)) {
		t.Fatalf("batch filter status=%d body=%s", response.Code, body)
	}
	if !strings.Contains(body, fmt.Sprintf(`name="batch" value="%d"`, first.ID)) || !strings.Contains(body, fmt.Sprintf("/history/export?batch=%d", first.ID)) {
		t.Fatalf("batch filter is not preserved in the form and export link: %s", body)
	}
	if got := historyURL(store.HistoryFilter{BatchID: 5, Collector: "devices"}, 9); got != "/history?batch=5&collector=devices&cursor=9" {
		t.Fatalf("history URL=%q", got)
	}
}

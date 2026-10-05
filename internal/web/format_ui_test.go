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

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestDestinationFormatOverrideIsEditableAndUsedForTests guards E-019: the
// per-destination format override is edited in Settings and the test message
// is rendered with the same format deliveries use.
func TestDestinationFormatOverrideIsEditableAndUsedForTests(t *testing.T) {
	server, st, token := testServer(t)
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	ctx := context.Background()
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
	id, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Hook", ServiceURL: serviceURL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"_csrf": {csrf}, "action": {"save"}, "id": {fmt.Sprint(id)}, "name": {"Hook"}, "enabled": {"on"}, "routing": {"1"}, "message_format": {"plain"}}
	if saved := coveragePost(t, server, "/settings/destinations", form, cookies); saved.Code != http.StatusSeeOther {
		t.Fatalf("format save status=%d body=%s", saved.Code, saved.Body.String())
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || destinations[0].Format != notify.FormatPlain {
		t.Fatalf("saved format=%+v err=%v", destinations, err)
	}
	page := authenticatedGet(t, server, "/settings", cookies).Body.String()
	if !strings.Contains(page, "Format: plain") || !strings.Contains(page, `<option value="plain" selected>`) {
		t.Fatalf("settings page does not show the format override: %s", page)
	}
	invalid := cloneForm(form)
	invalid.Set("message_format", "html")
	if rejected := followFlash(t, server, cookies, coveragePost(t, server, "/settings/destinations", invalid, cookies)); !strings.Contains(rejected, "Notification routing was not saved") {
		t.Fatalf("unknown format accepted: %s", rejected)
	}
	tested := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "id": {fmt.Sprint(id)}}, cookies)
	if result := followFlash(t, server, cookies, tested); tested.Code != http.StatusSeeOther || !strings.Contains(result, "Notification test sent") {
		t.Fatalf("test status=%d body=%s", tested.Code, result)
	}
	mu.Lock()
	plainBody := body
	mu.Unlock()
	if !strings.Contains(plainBody, "TailState test") || strings.Contains(plainBody, "**") || strings.Contains(plainBody, "###") {
		t.Fatalf("test message was not rendered as plain text: %s", plainBody)
	}
	tested = coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "service_url": {serviceURL}, "message_format": {"markdown"}}, cookies)
	if result := followFlash(t, server, cookies, tested); !strings.Contains(result, "Notification test sent") {
		t.Fatalf("markdown test body=%s", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(body, "**TailState test:**") {
		t.Fatalf("explicit markdown test was not rendered as Markdown: %s", body)
	}
}

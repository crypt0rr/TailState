package tailscale

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPolicyAdditionalCollectorsAndClientTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/acl":
			_, _ = w.Write([]byte(`{"acls":[{"action":"accept"}],"tests":[{"src":"*"}]}`))
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[]}`))
		case "/api/v2/tailnet/-/users":
			_, _ = w.Write([]byte(`{"users":[{"loginName":"alice"}]}`))
		case "/api/v2/tailnet/-/keys":
			_, _ = w.Write([]byte(`{"keys":[{"keyId":"key-1"}]}`))
		case "/api/v2/tailnet/-/posture/integrations":
			_, _ = w.Write([]byte(`{"integrations":[{"integrationId":"posture-1"}]}`))
		case "/api/v2/tailnet/-/settings":
			_, _ = w.Write([]byte(`{"magicDns":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{Tailnet: "-", ClientID: "id", ClientSecret: "secret"})
	policy, err := client.Collect(context.Background(), "policy")
	if err != nil || len(policy) != 1 {
		t.Fatalf("policy collection=%#v err=%v", policy, err)
	}
	sections, ok := policy[0].Data.(map[string]any)
	if !ok || len(sections) != 2 || len(fmt.Sprint(sections["acls"])) != 64 || len(fmt.Sprint(sections["tests"])) != 64 {
		t.Fatalf("policy sections were not hashed: %#v", policy[0].Data)
	}
	for _, collector := range []string{"users", "keys", "posture", "settings"} {
		resources, collectErr := client.Collect(context.Background(), collector)
		if collectErr != nil || len(resources) != 1 {
			t.Fatalf("%s collection=%#v err=%v", collector, resources, collectErr)
		}
	}
	if err := client.Test(context.Background()); err != nil {
		t.Fatalf("client test failed: %v", err)
	}
	if _, err := client.Collect(context.Background(), "unknown"); err == nil || !strings.Contains(err.Error(), "unknown collector") {
		t.Fatal("unknown collector was accepted")
	}

	primitiveServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`[{"action":"accept"}]`))
	}))
	defer primitiveServer.Close()
	primitive := New(primitiveServer.URL+"/api/v2", primitiveServer.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	resources, err := primitive.Collect(context.Background(), "policy")
	if err != nil || len(resources) != 1 {
		t.Fatalf("primitive policy collection=%#v err=%v", resources, err)
	}
	if sections, ok := resources[0].Data.(map[string]any); !ok || len(fmt.Sprint(sections["policy"])) != 64 {
		t.Fatalf("primitive policy was not hashed: %#v", resources[0].Data)
	}
}

func TestTailscaleHelpersAndHTTPError(t *testing.T) {
	if got := (&HTTPError{Status: 418}).Error(); got != "Tailscale GET returned 418" {
		t.Fatalf("HTTPError=%q", got)
	}
	if err := noRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("noRedirect error=%v", err)
	}
	if got := retryAfter("3", time.Minute); got != 3*time.Second {
		t.Fatalf("seconds Retry-After=%s", got)
	}
	future := time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfter(future, time.Minute); got <= 0 || got > 3*time.Second {
		t.Fatalf("date Retry-After=%s", got)
	}
	if got := retryAfter(time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat), time.Minute); got != 0 {
		t.Fatalf("expired Retry-After=%s", got)
	}
	if got := retryAfter("invalid", time.Minute); got != time.Minute {
		t.Fatalf("fallback Retry-After=%s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleep(ctx, time.Hour) {
		t.Fatal("canceled sleep returned true")
	}
	if !sleep(context.Background(), 0) {
		t.Fatal("zero sleep returned false")
	}
	if got := tailnetEscaped(New("https://example.invalid/api/v2", "", "", Credentials{Tailnet: "team/foo"})); got != "https://example.invalid/api/v2/tailnet/team%2Ffoo/" {
		t.Fatalf("escaped tailnet URL=%q", got)
	}
	if got := nextURL(map[string]any{"pagination": map[string]any{"nextCursor": "abc"}}); got != "?cursor=abc" {
		t.Fatalf("next cursor=%q", got)
	}
	if got := safeBody([]byte(strings.Repeat("x", 201))); !strings.HasPrefix(got, strings.Repeat("x", 200)) || !strings.HasSuffix(got, "…") {
		t.Fatalf("safe body=%q", got)
	}
	if got := idFor(map[string]any{"id": float64(42)}, []string{"id"}); got != "42" {
		t.Fatalf("numeric id=%q", got)
	}
	if got := nameFor(map[string]any{}, "fallback"); got != "fallback" {
		t.Fatalf("fallback name=%q", got)
	}
	if got := url.PathEscape("team/foo"); got != "team%2Ffoo" {
		t.Fatalf("PathEscape changed unexpectedly: %q", got)
	}
}

func tailnetEscaped(client *Client) string { return client.tailnet("") }

func TestLogStreamingAllUnsupportedAndHTTPRetries(t *testing.T) {
	unsupported := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		http.NotFound(w, r)
	}))
	client := New(unsupported.URL+"/api/v2", unsupported.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "log_streaming"); err == nil || !IsUnsupported(err) {
		t.Fatalf("all-unsupported log streaming error=%v", err)
	}
	unsupported.Close()

	var tokenCalls, deviceCalls int
	refresh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenCalls++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":"access-%d","expires_in":3600}`, tokenCalls)))
		case "/api/v2/tailnet/-/devices":
			deviceCalls++
			if deviceCalls == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer refresh.Close()
	refreshed := New(refresh.URL+"/api/v2", refresh.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if err := refreshed.Test(context.Background()); err != nil {
		t.Fatalf("401 refresh test=%v", err)
	}
	if tokenCalls != 2 || deviceCalls != 2 {
		t.Fatalf("401 refresh calls token=%d devices=%d", tokenCalls, deviceCalls)
	}

	var throttledCalls int
	throttled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		throttledCalls++
		if throttledCalls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[]}`))
	}))
	defer throttled.Close()
	throttledClient := New(throttled.URL+"/api/v2", throttled.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if err := throttledClient.Test(context.Background()); err != nil {
		t.Fatalf("429 retry test=%v", err)
	}
	if throttledCalls != 2 {
		t.Fatalf("429 retry calls=%d", throttledCalls)
	}
}

func TestDeviceDetailsPropagatesSecondaryEndpointFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/device/device-1/routes":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Collect(context.Background(), "device_details"); err == nil || !strings.Contains(err.Error(), "returned 500") {
		t.Fatalf("secondary endpoint failure was not propagated: %v", err)
	}
}

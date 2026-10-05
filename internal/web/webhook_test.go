package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/webhook"
)

func webhookServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	server, st, _ := testServer(t)
	if _, err := st.SaveSettings(context.Background(), store.Settings{
		Tailnet:           "-",
		OAuthClientID:     "client",
		OAuthClientSecret: "secret",
		WebhookSecret:     "webhook-secret",
		MattermostURL:     "https://mattermost.example/hooks/token",
		DeviceInterval:    time.Minute,
		InventoryInterval: 5 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	return server, st
}

func postWebhook(server *Server, body []byte, signature string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(string(body)))
	if signature != "" {
		request.Header.Set("Tailscale-Webhook-Signature", signature)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// TestAuthenticWebhookOutsideBoundsRequestsFullReconciliation proves that a
// validly signed delivery whose content exceeds TailState's bounds is
// recorded and answered with 202 plus a full reconciliation, instead of being
// dropped as an authentication failure.
func TestAuthenticWebhookOutsideBoundsRequestsFullReconciliation(t *testing.T) {
	server, st := webhookServer(t)
	events := make([]string, 101)
	for i := range events {
		events[i] = `{"type":"nodeCreated"}`
	}
	body := []byte("[" + strings.Join(events, ",") + "]")
	response := postWebhook(server, body, webhook.SignatureForTest(body, "webhook-secret", time.Now().Unix()))
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"status":"accepted"`) || !strings.Contains(response.Body.String(), `"reconciliation":"full"`) {
		t.Fatalf("101-event webhook status=%d body=%s", response.Code, response.Body.String())
	}
	hash := sha256.Sum256(body)
	trigger, created, err := st.RecordWebhookTrigger(context.Background(), hex.EncodeToString(hash[:]), nil, nil)
	if err != nil || created || trigger.Status != "pending" || len(trigger.Collectors) != 0 {
		t.Fatalf("fallback delivery was not durably queued for full reconciliation: %#v created=%v err=%v", trigger, created, err)
	}

	long := []byte(`[{"type":"` + strings.Repeat("x", 300) + `"},{"type":""}]`)
	if response := postWebhook(server, long, webhook.SignatureForTest(long, "webhook-secret", time.Now().Unix())); response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"reconciliation":"full"`) {
		t.Fatalf("long/missing type webhook status=%d body=%s", response.Code, response.Body.String())
	}

	targeted := []byte(`[{"type":"policyUpdate"}]`)
	if response := postWebhook(server, targeted, webhook.SignatureForTest(targeted, "webhook-secret", time.Now().Unix())); response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"reconciliation":"targeted"`) {
		t.Fatalf("targeted webhook status=%d body=%s", response.Code, response.Body.String())
	}

	if got := server.webhookOutcomeCount(webhookOutcomeContentFallback); got != 2 {
		t.Fatalf("content fallback count=%d", got)
	}
	if got := server.webhookOutcomeCount(webhookOutcomeInvalidSignature); got != 0 {
		t.Fatalf("content fallback counted as signature failure: %d", got)
	}
}

// TestWebhookStatusCodesDistinguishFailures keeps 401 for signature and
// timestamp failures only, and checks metrics tell the outcomes apart.
func TestWebhookStatusCodesDistinguishFailures(t *testing.T) {
	server, _ := webhookServer(t)
	body := []byte(`[{"type":"nodeCreated"}]`)
	cases := []struct {
		name      string
		body      []byte
		signature string
		code      int
	}{
		{"bad signature", body, webhook.SignatureForTest(body, "wrong-secret", time.Now().Unix()), http.StatusUnauthorized},
		{"missing signature", body, "", http.StatusUnauthorized},
		{"stale timestamp", body, webhook.SignatureForTest(body, "webhook-secret", time.Now().Add(-48*time.Hour).Unix()), http.StatusUnauthorized},
		{"empty body", nil, webhook.SignatureForTest(nil, "webhook-secret", time.Now().Unix()), http.StatusBadRequest},
		{"signed non-array", []byte(`{"type":"nodeCreated"}`), webhook.SignatureForTest([]byte(`{"type":"nodeCreated"}`), "webhook-secret", time.Now().Unix()), http.StatusBadRequest},
		{"unsigned non-array", []byte(`{"type":"nodeCreated"}`), "t=1,v1=00", http.StatusUnauthorized},
		{"oversized", []byte(strings.Repeat("x", webhook.MaxBodyBytes+1)), "t=1,v1=00", http.StatusRequestEntityTooLarge},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if response := postWebhook(server, test.body, test.signature); response.Code != test.code {
				t.Fatalf("status=%d, want %d body=%s", response.Code, test.code, response.Body.String())
			}
		})
	}
	// Calling the handler directly bypasses the transport body limit, so the
	// verifier's own size check must also answer 413.
	direct := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/webhooks/tailscale", strings.NewReader(strings.Repeat("x", webhook.MaxBodyBytes+1)))
	server.tailscaleWebhook(direct, request)
	if direct.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("verifier oversized status=%d", direct.Code)
	}

	metrics := scrapeMetrics(t, server).Body.String()
	for _, want := range []string{
		`tailstate_webhook_requests_total{outcome="invalid_signature"} 4`,
		`tailstate_webhook_requests_total{outcome="malformed"} 2`,
		`tailstate_webhook_requests_total{outcome="too_large"} 2`,
		`tailstate_webhook_requests_total{outcome="content_fallback"} 0`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q:\n%s", want, metrics)
		}
	}
	lintExposition(t, metrics)
}

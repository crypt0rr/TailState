package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// TestRevokedCredentialsSendOneGroupedHealthMessagePerDestination is the
// E-010 storm guarantee: when the OAuth credential is revoked, every
// collector that crosses the failure threshold in the same poll is reported
// in one "unhealthy" message per destination with the bounded reason
// "auth rejected", and recovery is likewise one grouped message.
func TestRevokedCredentialsSendOneGroupedHealthMessagePerDestination(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Second", ServiceURL: "generic://notify.example/hook", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 2 {
		t.Fatalf("destinations=%d err=%v", len(destinations), err)
	}
	var revoked atomic.Bool
	revoked.Store(true)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			if revoked.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client SECRET-DETAIL"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test")
	engine.ConfigureNotifications("lab", "https://tailstate.example")
	collectors := []string{"devices", "users", "dns"}
	for i := 0; i < 4; i++ {
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		if engine.poll(ctx, client, settings, collectors, true) {
			t.Fatalf("poll %d with a revoked credential succeeded", i+1)
		}
	}
	var payloads []string
	rows, err := db.QueryContext(ctx, "SELECT destination_id,payload FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	perDestination := map[int64]int{}
	for rows.Next() {
		var destination int64
		var payload string
		if err := rows.Scan(&destination, &payload); err != nil {
			t.Fatal(err)
		}
		perDestination[destination]++
		payloads = append(payloads, payload)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 || len(perDestination) != 2 {
		t.Fatalf("revocation queued %d messages for %d destinations, want one per destination: %q", len(payloads), len(perDestination), payloads)
	}
	for _, payload := range payloads {
		for _, want := range []string{"collectors unhealthy", "lab \\(default tailnet\\)", "`devices`: auth rejected", "`users`: auth rejected", "`dns`: auth rejected", "Observed at ", "https://tailstate.example/status"} {
			if !strings.Contains(payload, want) {
				t.Fatalf("grouped health message missing %q:\n%s", want, payload)
			}
		}
		if strings.Contains(payload, "SECRET-DETAIL") {
			t.Fatalf("provider error text leaked into the health message:\n%s", payload)
		}
	}

	revoked.Store(false)
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine.poll(ctx, client, settings, collectors, true)
	var recovered int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE payload LIKE '%collectors recovered%'").Scan(&recovered); err != nil {
		t.Fatal(err)
	}
	if recovered != 2 {
		t.Fatalf("recovery queued %d grouped messages, want one per destination", recovered)
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox").Scan(&total); err != nil || total != 4 {
		t.Fatalf("outbox rows=%d err=%v, want 4", total, err)
	}
}

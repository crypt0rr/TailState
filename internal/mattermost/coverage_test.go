package mattermost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

func TestMattermostTestHealthAndDeliveryHelpers(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(bodyBytes)
		body = string(bodyBytes)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := New().Test(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "connection test") {
		t.Fatalf("test payload=%q", body)
	}
	if err := noRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("noRedirect error=%v", err)
	}
	if got := (&DeliveryError{Message: "delivery failed"}).Error(); got != "delivery failed" {
		t.Fatalf("delivery error=%q", got)
	}
	for status, want := range map[int]bool{400: true, 408: false, 429: false, 500: false} {
		if got := (&DeliveryError{Status: status}).Permanent(); got != want {
			t.Fatalf("status %d permanent=%v, want %v", status, got, want)
		}
	}
	if recovered := SourceHealth("devices", true); !strings.Contains(recovered, "recovered") {
		t.Fatalf("recovery message=%q", recovered)
	}
	if unhealthy := SourceHealth("devices", false); !strings.Contains(unhealthy, "unhealthy") {
		t.Fatalf("unhealthy message=%q", unhealthy)
	}
	message := Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: []model.FieldChange{{Field: "description", Old: strings.Repeat("o", 200), New: strings.Repeat("n", 200)}}}})
	if !strings.Contains(message, "…") {
		t.Fatal("long field was not shortened")
	}
	if got := retryAfter("3"); got != 3*time.Second {
		t.Fatalf("numeric retry delay=%s", got)
	}
	if got := retryAfter("invalid"); got != 0 {
		t.Fatalf("invalid retry delay=%s", got)
	}
}

package mattermost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

func TestSendAndDigest(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	if err := New().Send(context.Background(), server.URL, Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: []model.FieldChange{{Field: "addresses", Old: "a", New: "b"}}}})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "server") || !strings.Contains(body, "addresses") {
		t.Fatalf("unexpected body %s", body)
	}
}
func TestPermanentError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer server.Close()
	err := New().Send(context.Background(), server.URL, "test")
	delivery, ok := err.(*DeliveryError)
	if !ok || !delivery.Permanent() {
		t.Fatalf("expected permanent delivery error: %v", err)
	}
}

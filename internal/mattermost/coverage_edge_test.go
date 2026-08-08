package mattermost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

func TestMattermostDeliveryAndRetryBranches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream failed"))
	}))
	defer server.Close()
	err := New().Send(context.Background(), server.URL, "message")
	delivery, ok := err.(*DeliveryError)
	if !ok || delivery.Status != http.StatusBadGateway || delivery.RetryAfter != 3e9 || delivery.Permanent() {
		t.Fatalf("delivery=%#v err=%v", delivery, err)
	}
	if err := New().Send(context.Background(), "http://[::1", "message"); err == nil {
		t.Fatal("invalid webhook URL succeeded")
	}
	if noRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect policy did not reject redirects")
	}
	if retryAfter("bad") != 0 || retryAfter("-1") != 0 {
		t.Fatal("invalid retry-after values were accepted")
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("test method=%s", r.Method)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer testServer.Close()
	if err := New().Test(context.Background(), testServer.URL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Digest(nil), "0 change(s)") {
		t.Fatal("empty digest missing count")
	}
}

func TestMattermostDigestOmissionBranches(t *testing.T) {
	if got := Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: strings.Repeat("x", 12000)}}); !strings.Contains(got, "Additional changes omitted") {
		t.Fatal("oversized change line was not omitted")
	}
	fields := make([]model.FieldChange, 100)
	for i := range fields {
		fields[i] = model.FieldChange{Field: strings.Repeat("f", 50), Old: strings.Repeat("o", 180), New: strings.Repeat("n", 180)}
	}
	if got := Digest([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: fields}}); len(got) > 12000 {
		t.Fatalf("field-bounded digest too large: %d", len(got))
	}
}

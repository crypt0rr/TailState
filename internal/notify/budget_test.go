package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/crypt0rr/tailstate/internal/model"
)

func largeDigest(changes int) string {
	list := make([]model.Change, 0, changes)
	for i := 0; i < changes; i++ {
		list = append(list, model.Change{
			Kind: "changed", Collector: "devices", Name: fmt.Sprintf("server-%03d", i),
			Fields: []model.FieldChange{
				// Values differ per device so fleet summarisation does not
				// collapse the fixture into one line.
				{Field: "tags", Old: []any{"tag:prod"}, New: []any{"tag:prod", fmt.Sprintf("tag:db-%03d", i)}},
				{Field: "clientVersion", Old: fmt.Sprintf("1.80.%d", i), New: "1.82.1"},
			},
		})
	}
	return digestText(list)
}

// TestDigestFitsEveryServiceBudget guards the regression where digests up to
// 12 KB were sent to services that reject anything over 4 KB, then retried for
// 24 hours and dead-lettered.
func TestDigestFitsEveryServiceBudget(t *testing.T) {
	message := largeDigest(500)
	for scheme, limit := range serviceMessageLimits {
		fitted := FitMessage(message, MessageLimit(scheme+"://example"))
		if len(fitted) > limit {
			t.Fatalf("%s digest is %d bytes, limit %d", scheme, len(fitted), limit)
		}
		if !strings.Contains(fitted, "omitted") {
			t.Fatalf("%s digest dropped content without an omission note", scheme)
		}
		if !utf8.ValidString(fitted) {
			t.Fatalf("%s digest is not valid UTF-8", scheme)
		}
		if strings.Count(fitted, "`")%2 != 0 {
			t.Fatalf("%s digest cut a code span in half", scheme)
		}
	}
	if fitted := FitMessage(message, digestBudget); len(fitted) > digestBudget {
		t.Fatalf("default digest is %d bytes", len(fitted))
	}
}

func TestDigestMarksFieldsDroppedAtTheBudget(t *testing.T) {
	fields := make([]model.FieldChange, 100)
	for i := range fields {
		fields[i] = model.FieldChange{Field: "field", Old: strings.Repeat("o", 180), New: strings.Repeat("n", 180)}
	}
	message := digestText([]model.Change{{Kind: "changed", Collector: "devices", Name: "server", Fields: fields}})
	if !strings.Contains(message, "Additional field changes omitted; total: 100") {
		t.Fatalf("dropped field lines were not marked: %s", message[len(message)-300:])
	}
}

func TestMessageLimitParsesSchemes(t *testing.T) {
	for raw, want := range map[string]int{
		"telegram://token@telegram?chats=1": 4096,
		"TELEGRAM://token@telegram":         4096,
		"pushover://shoutrrr:token@user":    1024,
		"discord://token@id":                6000,
		"generic://example.com/hook":        digestBudget,
		"not a url":                         digestBudget,
	} {
		if got := MessageLimit(raw); got != want {
			t.Errorf("MessageLimit(%q)=%d, want %d", raw, got, want)
		}
	}
}

func TestFitMessageEdges(t *testing.T) {
	if got := FitMessage("short", 100); got != "short" {
		t.Fatalf("short message changed: %q", got)
	}
	if got := FitMessage("anything", 0); got != "anything" {
		t.Fatalf("zero limit should disable fitting: %q", got)
	}
	long := strings.Repeat("é", 100)
	if got := FitMessage(long, 51); len(got) > 51 || !utf8.ValidString(got) {
		t.Fatalf("single long line fitted to %d bytes valid=%t", len(got), utf8.ValidString(got))
	}
	fitted := FitMessage("line one\nline two\nline three\nline four\n", 120)
	if fitted != "line one\nline two\nline three\nline four\n" {
		t.Fatalf("message within limit was changed: %q", fitted)
	}
	fitted = FitMessage("### title\n"+strings.Repeat("a line of text\n", 50), 150)
	if len(fitted) > 150 || !strings.HasPrefix(fitted, "### title\n") || !strings.Contains(fitted, "more line(s) omitted") {
		t.Fatalf("fitted message = %q", fitted)
	}
}

func TestSendFitsMessageToDestinationBudget(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","event":"message"}`))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	serviceURL := "ntfy://" + host + "/tailstate?scheme=http"
	if err := New().Send(context.Background(), serviceURL, largeDigest(200)); err != nil {
		t.Fatalf("send: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("expected one request, got %d", len(bodies))
	}
	// ntfy sends JSON; the message field must have been fitted to 4096 bytes.
	if len(bodies[0]) > 4096+512 || !strings.Contains(bodies[0], "omitted") {
		t.Fatalf("ntfy body was not fitted (%d bytes)", len(bodies[0]))
	}
}

func TestOversizedMessageFailuresArePermanent(t *testing.T) {
	for _, message := range []string{"telegram: Message exceeds the max length", "message exceeds the max length of 4096 bytes", "zulip: message exceeds max size"} {
		err := &DeliveryError{Message: message, Permanent: permanentDeliveryFailure(message, 0)}
		if !IsPermanent(err) {
			t.Fatalf("%q was not permanent", message)
		}
		if got := SafeDeliveryError(err); !strings.Contains(got, "too large") {
			t.Fatalf("%q safe reason=%q", message, got)
		}
	}
	if !permanentDeliveryFailure("", 413) {
		t.Fatal("HTTP 413 was not permanent")
	}
	if IsPermanent(errors.New("dial tcp: connection refused")) || IsPermanent(&DeliveryError{Message: "HTTP 503"}) {
		t.Fatal("transient failure was classified as permanent")
	}
}

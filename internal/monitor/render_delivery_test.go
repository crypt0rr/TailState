package monitor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

type capturingSender struct {
	mu       sync.Mutex
	messages map[string][]string
}

func (s *capturingSender) Send(_ context.Context, serviceURL, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.messages == nil {
		s.messages = map[string][]string{}
	}
	s.messages[serviceURL] = append(s.messages[serviceURL], message)
	return nil
}

func (s *capturingSender) Test(context.Context, string) error { return nil }

// TestDeliveryRendersEachDestinationsFormat guards E-019 end to end: one
// stored message is rendered per destination (by URL scheme or override),
// legacy Markdown rows are sent unchanged, and an undecodable payload is
// dead-lettered without contacting the provider.
func TestDeliveryRendersEachDestinationsFormat(t *testing.T) {
	ctx := context.Background()
	st, _, db := monitorTestStoreWithDB(t)
	urls := map[string]string{"slack": "generic://notify.example/slack", "plain": "generic://notify.example/plain"}
	for format, serviceURL := range urls {
		id, err := st.SaveDestination(ctx, store.NotificationDestination{Name: format, ServiceURL: serviceURL, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetDestinationFormat(ctx, id, format); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EnqueueSystem(ctx, "### legacy **markdown**"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueMessage(ctx, notify.Context{Tailnet: "example.com"}.Update("1.0", "1.1", time.Now())); err != nil {
		t.Fatal(err)
	}
	sender := &capturingSender{}
	engine := New(st, "", "", "test", sender)
	items, err := st.ClaimDueOutbox(ctx, 20, time.Minute)
	if err != nil || len(items) != 6 {
		t.Fatalf("claimed %d items err=%v", len(items), err)
	}
	for _, item := range items {
		engine.deliverItemWithLease(ctx, item, nil)
	}
	sender.mu.Lock()
	slack, plain := sender.messages[urls["slack"]], sender.messages[urls["plain"]]
	var markdown []string
	for serviceURL, messages := range sender.messages {
		if serviceURL != urls["slack"] && serviceURL != urls["plain"] {
			markdown = messages
		}
	}
	sender.mu.Unlock()
	if len(slack) != 2 || len(plain) != 2 || len(markdown) != 2 {
		t.Fatalf("deliveries slack=%d plain=%d markdown=%d", len(slack), len(plain), len(markdown))
	}
	for _, messages := range [][]string{slack, plain, markdown} {
		if messages[0] != "### legacy **markdown**" {
			t.Fatalf("legacy row was not delivered unchanged: %q", messages[0])
		}
	}
	if !strings.HasPrefix(slack[1], "*🚀 TailState updated · example.com*") || strings.Contains(slack[1], "###") || strings.Contains(slack[1], "**") {
		t.Fatalf("slack rendering: %q", slack[1])
	}
	if !strings.HasPrefix(plain[1], "🚀 TailState updated · example.com\nPrevious version: 1.0") || strings.ContainsAny(plain[1], "*`") {
		t.Fatalf("plain rendering: %q", plain[1])
	}
	if !strings.HasPrefix(markdown[1], "### 🚀 TailState updated · example.com\n**Previous version:** `1.0`") {
		t.Fatalf("markdown rendering: %q", markdown[1])
	}

	if err := st.EnqueueMessage(ctx, notify.Context{}.Update("1.1", "1.2", time.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE outbox SET payload='{' WHERE status='pending'"); err != nil {
		t.Fatal(err)
	}
	damaged, err := st.ClaimDueOutbox(ctx, 20, time.Minute)
	if err != nil || len(damaged) != 3 {
		t.Fatalf("claimed %d damaged items err=%v", len(damaged), err)
	}
	for _, item := range damaged {
		engine.deliverItemWithLease(ctx, item, nil)
	}
	var dead int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='dead' AND last_error='notification delivery failed'").Scan(&dead); err != nil || dead != 3 {
		t.Fatalf("damaged payloads dead-lettered=%d err=%v", dead, err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.messages[urls["slack"]]) != 2 {
		t.Fatal("a damaged payload reached the provider")
	}
}

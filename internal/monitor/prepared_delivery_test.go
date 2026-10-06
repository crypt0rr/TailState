package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// preparedSender records the prepared messages the engine hands to a sender
// that delivers titles separately, like the production sender.
type preparedSender struct {
	capturingSender
	prepared []notify.Prepared
}

func (s *preparedSender) SendPrepared(_ context.Context, serviceURL string, message notify.Prepared) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if serviceURL == discordDestination {
		s.prepared = append(s.prepared, message)
	}
	return nil
}

const discordDestination = "discord://token@123456789"

// TestQueuedMessagesAreDeliveredWithSeparateTitles checks that outbox rows
// are prepared at send time: a queued structured message reaches a Discord
// destination with its title as a separate field and no title line in the
// body, while a legacy pre-rendered row is delivered exactly as stored.
func TestQueuedMessagesAreDeliveredWithSeparateTitles(t *testing.T) {
	ctx := context.Background()
	st, _, _ := monitorTestStoreWithDB(t)
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "discord", ServiceURL: discordDestination, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "### legacy **markdown**"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueMessage(ctx, notify.Context{Tailnet: "example.com"}.Update("1.0", "1.1", time.Now())); err != nil {
		t.Fatal(err)
	}
	sender := &preparedSender{}
	engine := New(st, "", "", "test", sender)
	items, err := st.ClaimDueOutbox(ctx, 20, time.Minute)
	if err != nil || len(items) != 4 {
		t.Fatalf("claimed %d items err=%v", len(items), err)
	}
	for _, item := range items {
		engine.deliverItemWithLease(ctx, item, nil)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.prepared) != 2 || len(sender.messages) != 0 {
		t.Fatalf("prepared=%d text sends=%d", len(sender.prepared), len(sender.messages))
	}
	legacy, structured := sender.prepared[0], sender.prepared[1]
	if legacy.Title != "" || legacy.Message() != "### legacy **markdown**" {
		t.Fatalf("legacy row changed: %+v", legacy)
	}
	if structured.Title != "🚀 TailState updated · example.com" || strings.Contains(structured.Message(), "TailState updated") || !strings.HasPrefix(structured.Message(), "**Previous version:** `1.0`") {
		t.Fatalf("structured row: %+v", structured)
	}
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// TestSaveSettingsRejectsOutOfRangeIntervals proves that the persistence
// layer itself refuses intervals outside the supported range, including
// values that would effectively disable polling.
func TestSaveSettingsRejectsOutOfRangeIntervals(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(*Settings)
		want   string
	}{
		{"device below minimum", func(s *Settings) { s.DeviceInterval = MinDevicePollInterval - time.Second }, "device poll interval"},
		{"device above maximum", func(s *Settings) { s.DeviceInterval = MaxPollInterval + time.Second }, "device poll interval"},
		{"device effectively disabled", func(s *Settings) { s.DeviceInterval = time.Duration(math.MaxInt64) }, "device poll interval"},
		{"inventory below minimum", func(s *Settings) { s.InventoryInterval = MinInventoryPollInterval - time.Second }, "inventory poll interval"},
		{"inventory above maximum", func(s *Settings) { s.InventoryInterval = 3_000_000_000 * time.Second }, "inventory poll interval"},
		{"webhook secret too long", func(s *Settings) { s.WebhookSecret = strings.Repeat("s", MaxWebhookSecretBytes+1) }, "webhook secret"},
		{"oauth missing", func(s *Settings) { s.OAuthClientSecret = "" }, "OAuth credentials"},
		{"tailnet invalid", func(s *Settings) { s.Tailnet = "a b" }, "tailnet name"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := settings()
			test.mutate(&in)
			if _, err := st.SaveSettings(ctx, in); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("SaveSettings error=%v, want %q", err, test.want)
			}
			if _, err := st.Settings(ctx); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("out-of-range settings were persisted: %v", err)
			}
		})
	}
	in := settings()
	in.DeviceInterval, in.InventoryInterval = MinDevicePollInterval, MaxPollInterval
	if _, err := st.SaveSettings(ctx, in); err != nil {
		t.Fatalf("boundary intervals rejected: %v", err)
	}
}

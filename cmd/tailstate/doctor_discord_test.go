package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

// TestDoctorWarnsAboutDiscordSplitLines checks that doctor flags an enabled
// Discord destination forcing splitlines=yes without printing its URL.
func TestDoctorWarnsAboutDiscordSplitLines(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "corp.example", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Discord", ServiceURL: "discord://doctor-secret@123456789?splitlines=yes", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := captureStdout(t, func() error { return doctor(nil) })
	if err != nil {
		t.Fatalf("doctor returned %v", err)
	}
	if !strings.Contains(output, "[discord_splitlines_forced]") || strings.Contains(output, "doctor-secret") {
		t.Fatalf("doctor report=%q", output)
	}
}

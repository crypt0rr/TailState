package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

// TestDoctorDefaultComposeDeploymentIsOK runs doctor with the environment the
// default Compose file gives the container (wildcard listener inside the
// image, published on loopback only) for a claimed, configured installation.
func TestDoctorDefaultComposeDeploymentIsOK(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	t.Setenv("TAILSTATE_LISTEN_ADDR", "0.0.0.0:8080")
	t.Setenv("TAILSTATE_CONTAINER", "1")

	output, err := captureStdout(t, func() error { return doctor(nil) })
	if err != nil || !strings.Contains(output, "TailState deployment doctor: ok") || !strings.Contains(output, "INFO [container_listener]") {
		t.Fatalf("fresh Compose doctor err=%v output=%q", err, output)
	}

	box, err := storeBoxFromCommandKey(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dataDir, "tailstate.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	claimCommandAdmin(t, st)
	ctx := context.Background()
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Primary", ServiceURL: "mattermost://TailState@example.invalid/token", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	output, err = captureStdout(t, func() error { return doctor(nil) })
	if err != nil || !strings.Contains(output, "TailState deployment doctor: ok") || strings.Contains(output, "WARNING") {
		t.Fatalf("configured Compose doctor err=%v output=%q", err, output)
	}

	// The same listener outside the container image still warns.
	t.Setenv("TAILSTATE_CONTAINER", "0")
	output, err = captureStdout(t, func() error { return doctor(nil) })
	if err != nil || !strings.Contains(output, "TailState deployment doctor: warning") || !strings.Contains(output, "WARNING [plaintext_public_listener]") {
		t.Fatalf("standalone wildcard doctor err=%v output=%q", err, output)
	}
}

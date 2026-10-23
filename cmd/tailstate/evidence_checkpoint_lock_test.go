package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
)

// TestEvidenceCheckpointChangesRefuseDuringCompaction covers the checkpoint side
// of the maintenance lock. A change to the checkpoint destination runs while the
// service lock is held, but it refuses with ErrMaintenanceBusy while an admin
// compact holds the maintenance lock, and it writes nothing in that case.
func TestEvidenceCheckpointChangesRefuseDuringCompaction(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	destinationID, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Ops", ServiceURL: "mattermost://TailState@example.invalid/ops", Enabled: true})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "tailstate.db")
	chosen := strconv.FormatInt(destinationID, 10)

	serviceLock, err := store.LockService(path)
	if err != nil {
		t.Fatal(err)
	}
	compaction, err := store.LockMaintenanceExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	chooseErr := evidenceCheckpoint([]string{"-destination-id", chosen})
	clearErr := evidenceCheckpoint([]string{"-clear"})
	if err := compaction.Release(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(chooseErr, store.ErrMaintenanceBusy) || exitCode(chooseErr) != exitRuntime {
		t.Fatalf("choosing a destination during compaction err=%v exit=%d", chooseErr, exitCode(chooseErr))
	}
	if !errors.Is(clearErr, store.ErrMaintenanceBusy) || exitCode(clearErr) != exitRuntime {
		t.Fatalf("clearing checkpoints during compaction err=%v exit=%d", clearErr, exitCode(clearErr))
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused checkpoint change modified the database")
	}
	out, err := captureStdout(t, func() error { return evidenceCheckpoint(nil) })
	if err != nil || !strings.Contains(out, "Ledger checkpoints: off") {
		t.Fatalf("status after refused change out=%q err=%v", out, err)
	}
	// Once the compaction has finished, the same change is applied.
	if err := evidenceCheckpoint([]string{"-destination-id", chosen}); err != nil {
		t.Fatalf("choosing a destination after compaction: %v", err)
	}
	if err := serviceLock.Release(); err != nil {
		t.Fatal(err)
	}
}

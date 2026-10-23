package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestEvidenceAuditCheckpointFlagsFailTruncatedLedger anchors the ledger head
// with a checkpoint and audits with its sequence and head. The untouched ledger
// passes. After the tail is removed and its stored head rewritten, the same
// audit exits with the findings code, while the database-only audit still
// passes, which is why the checkpoint has to be kept outside the database.
func TestEvidenceAuditCheckpointFlagsFailTruncatedLedger(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		name := fmt.Sprintf("server-%d", index)
		collected := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: name, Data: map[string]any{"hostname": name}}}}}
		if _, err := st.ApplyBatchWithBatch(ctx, generation, collected, notify.TextDigest(name)); err != nil {
			st.Close()
			t.Fatal(err)
		}
	}
	destinationID, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Ops", ServiceURL: "mattermost://TailState@example.invalid/ops", Enabled: true})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.SetEvidenceCheckpointDestination(ctx, destinationID); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if sent, err := st.EnqueueLedgerCheckpointIfDue(ctx, time.Now().UTC(), time.Hour, func(store.LedgerCheckpoint) notify.Message {
		return notify.Text("checkpoint")
	}); !sent || err != nil {
		st.Close()
		t.Fatalf("checkpoint sent=%t err=%v", sent, err)
	}
	status, err := st.EvidenceCheckpointStatus(ctx)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	sequence := strconv.FormatInt(status.LastSequence, 10)
	out, err := captureStdout(t, func() error {
		return evidenceAudit([]string{"-min-sequence", sequence, "-expect-head", status.LastHead})
	})
	if err != nil || !strings.Contains(out, "checkpoint_sequence="+sequence) || !strings.Contains(out, "checkpoint_head=matched") {
		t.Fatalf("untouched ledger audit out=%q err=%v", out, err)
	}
	db := commandDB(t, dataDir)
	if _, err := db.Exec("DELETE FROM evidence_ledger WHERE sequence>=?", status.LastSequence); err != nil {
		t.Fatal(err)
	}
	var tail string
	if err := db.QueryRow("SELECT entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&tail); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE meta SET value=? WHERE key='evidence_ledger_head'", tail); err != nil {
		t.Fatal(err)
	}
	if err := evidenceAudit(nil); err != nil {
		t.Fatalf("database-only audit of the truncated ledger failed: %v", err)
	}
	if err := evidenceAudit([]string{"-min-sequence", sequence, "-expect-head", status.LastHead}); exitCode(err) != exitFindings {
		t.Fatalf("truncated ledger audit exit=%d err=%v, want %d", exitCode(err), err, exitFindings)
	}
	for _, args := range [][]string{
		{"-expect-head", status.LastHead},
		{"-min-sequence", "-1"},
		{"-min-sequence", sequence, "-expect-head", "not-a-head"},
	} {
		if err := evidenceAudit(args); exitCode(err) != exitUsage {
			t.Fatalf("evidence audit %v exit=%d err=%v, want usage error", args, exitCode(err), err)
		}
	}
}

// TestEvidenceCheckpointCommandChoosesAndClearsDestination checks that the
// checkpoint command chooses an enabled destination by ID, refuses disabled or
// unknown ones, reports its status, and turns checkpoints off again.
func TestEvidenceCheckpointCommandChoosesAndClearsDestination(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	enabledID, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Ops", ServiceURL: "mattermost://TailState@example.invalid/ops", Enabled: true})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	disabledID, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Spare", ServiceURL: "mattermost://TailState@example.invalid/spare", Enabled: false})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	chosen := strconv.FormatInt(enabledID, 10)
	if err := evidenceCheckpoint([]string{"-destination-id", chosen}); err != nil {
		t.Fatalf("choose destination: %v", err)
	}
	out, err := captureStdout(t, func() error { return evidenceCheckpoint(nil) })
	if want := fmt.Sprintf("Ledger checkpoints: destination %s \"Ops\" (enabled)", chosen); err != nil || !strings.Contains(out, want) || !strings.Contains(out, "(receives checkpoints)") {
		t.Fatalf("status out=%q err=%v, want %q", out, err, want)
	}
	if err := evidenceCheckpoint([]string{"-destination-id", strconv.FormatInt(disabledID, 10)}); exitCode(err) != exitRuntime {
		t.Fatalf("disabled destination exit=%d err=%v", exitCode(err), err)
	}
	if err := evidenceCheckpoint([]string{"-destination-id", "999"}); exitCode(err) != exitRuntime {
		t.Fatalf("unknown destination exit=%d err=%v", exitCode(err), err)
	}
	for _, args := range [][]string{{"-clear", "-destination-id", chosen}, {"-destination-id", "-3"}} {
		if err := evidenceCheckpoint(args); exitCode(err) != exitUsage {
			t.Fatalf("evidence checkpoint %v exit=%d err=%v, want usage error", args, exitCode(err), err)
		}
	}
	if err := evidenceCheckpoint([]string{"-clear"}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	out, err = captureStdout(t, func() error { return evidenceCheckpoint(nil) })
	if err != nil || !strings.Contains(out, "Ledger checkpoints: off") {
		t.Fatalf("cleared status out=%q err=%v", out, err)
	}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestAdminCompactRefusesWhileServing proves the offline-only guarantee end
// to end: while serve runs it holds the service lock and compact exits with a
// runtime error without touching the database; after serve stops, compact
// succeeds and a second serve cannot start while the first is running.
func TestAdminCompactRefusesWhileServing(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	originalStart := startEngine
	t.Cleanup(func() { startEngine = originalStart })
	started := make(chan struct{})
	startEngine = func(ctx context.Context, engine *monitor.Engine) {
		engine.Run(ctx)
		close(started)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- serveContext(ctx) }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
	path := filepath.Join(dataDir, "tailstate.db")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = captureStdout(t, func() error { return adminCompact(nil) })
	if !errors.Is(err, store.ErrServiceRunning) || exitCode(err) != exitRuntime {
		t.Fatalf("compact while serving err=%v exit=%d", err, exitCode(err))
	}
	if after, statErr := os.Stat(path); statErr != nil || !os.SameFile(before, after) {
		t.Fatalf("refused compaction replaced the database: %v", statErr)
	}
	if err := serveContext(context.Background()); !errors.Is(err, store.ErrServiceRunning) {
		t.Fatalf("second serve on the same data directory err=%v", err)
	}
	cancel()
	if err := <-served; err != nil {
		t.Fatalf("serve returned %v", err)
	}
	output, err := captureStdout(t, func() error { return adminCompact([]string{"-incremental-vacuum"}) })
	if err != nil || !strings.Contains(output, "TailState database compacted") || !strings.Contains(output, "incremental auto-vacuum true") {
		t.Fatalf("compact after serve stopped output=%q err=%v", output, err)
	}
	box, err := storeBoxFromCommandKey(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenExisting(path, box)
	if err != nil {
		t.Fatalf("compacted database is unusable: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminCompactReportsConfigurationAndDatabaseErrors(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	if _, err := captureStdout(t, func() error { return adminCompact(nil) }); !errors.Is(err, store.ErrDatabaseNotFound) {
		t.Fatalf("missing database err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tailstate.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("compact created a database: %v", err)
	}
	if _, err := captureStdout(t, func() error { return adminCompact([]string{"extra"}) }); exitCode(err) != exitUsage {
		t.Fatalf("unexpected argument err=%v", err)
	}
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", filepath.Join(dataDir, "missing.key"))
	if _, err := captureStdout(t, func() error { return adminCompact(nil) }); err == nil || !strings.Contains(err.Error(), "admin compact master key") {
		t.Fatalf("missing key err=%v", err)
	}
	t.Setenv("TAILSTATE_LOG_LEVEL", "verbose")
	if _, err := captureStdout(t, func() error { return adminCompact(nil) }); err == nil || !strings.Contains(err.Error(), "admin compact configuration") {
		t.Fatalf("invalid configuration err=%v", err)
	}
}

// TestDoctorReportsUsedAndFreeStorage checks that doctor exposes free pages
// and bases pressure on used bytes.
func TestDoctorReportsUsedAndFreeStorage(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	db := commandDB(t, dataDir)
	if _, err := db.Exec("CREATE TABLE doctor_probe(b BLOB)"); err != nil {
		t.Fatal(err)
	}
	for range 16 {
		if _, err := db.Exec("INSERT INTO doctor_probe VALUES(randomblob(262144))"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("DELETE FROM doctor_probe"); err != nil {
		t.Fatal(err)
	}
	output, err := captureStdout(t, func() error { return doctor([]string{"-json"}) })
	if err != nil {
		t.Fatalf("doctor returned %v", err)
	}
	var report diagnostics.Report
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatal(err)
	}
	storage := report.Storage
	if storage.DatabaseFreelistPages == 0 || storage.DatabaseFreeBytes == 0 || storage.DatabaseUsedBytes+storage.DatabaseFreeBytes != storage.DatabaseBytes {
		t.Fatalf("doctor storage accounting=%+v", storage)
	}
	if want := float64(storage.DatabaseUsedBytes) / float64(storage.DatabaseLimitBytes); storage.StoragePressure != want {
		t.Fatalf("doctor pressure=%f want used-based %f", storage.StoragePressure, want)
	}
	text, err := captureStdout(t, func() error { return doctor(nil) })
	if err != nil || !strings.Contains(text, "free pages") || !strings.Contains(text, "bytes used") {
		t.Fatalf("doctor text output=%q err=%v", text, err)
	}
}

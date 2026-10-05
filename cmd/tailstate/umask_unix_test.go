//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRestrictFileCreationMaskMakesNewFilesPrivate verifies that the
// process-wide mask set at startup strips group and world bits from files the
// service creates, even when they are requested with a permissive mode.
func TestRestrictFileCreationMaskMakesNewFilesPrivate(t *testing.T) {
	original := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(original) })
	if previous := restrictFileCreationMask(); previous != 0o022 {
		t.Fatalf("previous mask=%#o, want 0o022", previous)
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "tailstate.db-wal")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, file: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode=%#o, want %#o", path, got, want)
		}
	}
}

//go:build unix

package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func assertPrivateDatabaseFiles(t *testing.T, path string) {
	t.Helper()
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode=%#o, want 0600", filepath.Base(name), got)
		}
	}
}

// TestDatabaseSidecarsArePrivate opens a fresh database under a permissive
// umask and asserts that the database and its WAL and shared-memory sidecars
// are owner-only while the store is serving, and that world-readable
// sidecars left by an unclean shutdown are tightened on the next start.
func TestDatabaseSidecarsArePrivate(t *testing.T) {
	original := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(original) })
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	assertPrivateDatabaseFiles(t, path)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Recreate the state after a crash of an older release: world-readable
	// sidecars that SQLite will reuse rather than recreate.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(path+suffix, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+suffix, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	assertPrivateDatabaseFiles(t, path)
}

func TestOpenReportsDatabaseFileCreationErrors(t *testing.T) {
	box, _ := secret.NewBox(make([]byte, 32))
	dir := t.TempDir()
	// A directory at the database path cannot be opened for writing.
	path := filepath.Join(dir, "tailstate.db")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, box); err == nil {
		t.Fatal("Open accepted a directory as the database file")
	}
	if err := restrictDatabaseSidecars(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("restrictDatabaseSidecars accepted a missing database file")
	}
}

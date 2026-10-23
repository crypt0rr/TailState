package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

func writeOlderSchemaDatabase(t *testing.T, path string) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(11)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// writeReplacementKey writes a valid replacement master key into dataDir and
// returns its path.
func writeReplacementKey(t *testing.T, dataDir string) string {
	t.Helper()
	path := filepath.Join(dataDir, "replacement.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// dirEntries lists the names in dir, so a test can prove that a command
// created no file.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestAdminCommandsNeverCreateOrMigrateDatabases proves that `admin reset`,
// `admin rekey`, and `evidence public-key` leave a missing or older-schema
// database untouched and exit with an explicit error. A missing database must
// also leave the data directory unchanged, so no lock file is created either.
func TestAdminCommandsNeverCreateOrMigrateDatabases(t *testing.T) {
	commands := map[string]func(newKeyFile string) func() error{
		"admin reset": func(string) func() error { return adminReset },
		"admin rekey": func(newKeyFile string) func() error {
			return func() error { return adminRekey([]string{"-new-key-file", newKeyFile}) }
		},
		"evidence public-key": func(string) func() error { return evidencePublicKey },
	}
	for name, newCommand := range commands {
		t.Run(name+" missing", func(t *testing.T) {
			dataDir := t.TempDir()
			configureCommandEnvironment(t, dataDir)
			command := newCommand(writeReplacementKey(t, dataDir))
			before := dirEntries(t, dataDir)
			output, err := captureStdout(t, command)
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Fatalf("missing database err=%v output=%q", err, output)
			}
			if _, statErr := os.Stat(filepath.Join(dataDir, "tailstate.db")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s created a database: %v", name, statErr)
			}
			if after := dirEntries(t, dataDir); !slices.Equal(before, after) {
				t.Fatalf("%s changed the data directory: before=%v after=%v", name, before, after)
			}
			if strings.TrimSpace(output) != "" {
				t.Fatalf("%s printed output for a missing database: %q", name, output)
			}
		})
		t.Run(name+" older schema", func(t *testing.T) {
			dataDir := t.TempDir()
			configureCommandEnvironment(t, dataDir)
			command := newCommand(writeReplacementKey(t, dataDir))
			path := filepath.Join(dataDir, "tailstate.db")
			before := writeOlderSchemaDatabase(t, path)
			if _, err := captureStdout(t, command); err == nil || !strings.Contains(err.Error(), "schema version") {
				t.Fatalf("older schema err=%v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("%s modified an older-schema database", name)
			}
		})
	}
}

// TestAdminRekeyValidatesKeyBeforeTouchingDatabase proves that the replacement
// key is read and checked before the database is opened. A mistyped path or a
// malformed key therefore creates nothing in an empty data directory and
// changes nothing in an existing database, and a wrong current key is refused
// without rewriting anything.
func TestAdminRekeyValidatesKeyBeforeTouchingDatabase(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	malformed := filepath.Join(dataDir, "malformed.key")
	if err := os.WriteFile(malformed, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	mistyped := filepath.Join(dataDir, "mistyped.key")
	before := dirEntries(t, dataDir)

	if _, err := captureStdout(t, func() error { return adminRekey(nil) }); exitCode(err) != exitUsage {
		t.Fatalf("missing -new-key-file exit=%d err=%v", exitCode(err), err)
	}
	if _, err := captureStdout(t, func() error { return adminRekey([]string{"-new-key-file", mistyped}) }); err == nil || !strings.Contains(err.Error(), "read master key") {
		t.Fatalf("mistyped replacement key path err=%v", err)
	}
	if _, err := captureStdout(t, func() error { return adminRekey([]string{"-new-key-file", malformed}) }); err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("malformed replacement key err=%v", err)
	}
	if after := dirEntries(t, dataDir); !slices.Equal(before, after) {
		t.Fatalf("rekey with an invalid replacement key changed the data directory: before=%v after=%v", before, after)
	}

	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	claimCommandAdmin(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "tailstate.db")
	database, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return adminRekey([]string{"-new-key-file", malformed}) }); err == nil {
		t.Fatal("rekey accepted a malformed replacement key")
	}
	wrongKey := filepath.Join(dataDir, "wrong.key")
	if err := os.WriteFile(wrongKey, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", wrongKey)
	replacement := writeReplacementKey(t, dataDir)
	if _, err := captureStdout(t, func() error { return adminRekey([]string{"-new-key-file", replacement}) }); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("rekey with a wrong current key err=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(database, after) {
		t.Fatal("refused rekey modified the database")
	}
}

// TestAdminResetRunsWhileServiceLockHeldButNotDuringCompaction covers the reset
// side of the maintenance lock. Reset keeps working while serve holds the
// service lock, several resets may overlap, and reset refuses with
// ErrMaintenanceBusy while an admin compact holds the maintenance lock, writing
// nothing in that case.
func TestAdminResetRunsWhileServiceLockHeldButNotDuringCompaction(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	claimCommandAdmin(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "tailstate.db")

	serviceLock, err := store.LockService(path)
	if err != nil {
		t.Fatal(err)
	}
	output, err := captureStdout(t, adminReset)
	if err != nil || !strings.Contains(output, "Password reset token:") {
		t.Fatalf("reset while the service lock is held output=%q err=%v", output, err)
	}
	overlap, err := store.LockMaintenanceShared(path)
	if err != nil {
		t.Fatal(err)
	}
	output, err = captureStdout(t, adminReset)
	if err != nil || !strings.Contains(output, "Password reset token:") {
		t.Fatalf("reset alongside another reset output=%q err=%v", output, err)
	}
	if err := overlap.Release(); err != nil {
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
	output, err = captureStdout(t, adminReset)
	if err := compaction.Release(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, store.ErrMaintenanceBusy) || exitCode(err) != exitRuntime || strings.TrimSpace(output) != "" {
		t.Fatalf("reset during compaction output=%q err=%v exit=%d", output, err, exitCode(err))
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused reset modified the database")
	}
	if err := serviceLock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestEvidencePublicKeyRequiresStoredSigningKey(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	want, err := st.EvidenceSigningPublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := captureStdout(t, evidencePublicKey)
	if err != nil || strings.TrimSpace(output) != base64.RawStdEncoding.EncodeToString(want) {
		t.Fatalf("public key output=%q err=%v", output, err)
	}

	db := commandDB(t, dataDir)
	if _, err := db.Exec("DELETE FROM meta WHERE key LIKE 'evidence_signing_%'"); err != nil {
		t.Fatal(err)
	}
	output, err = captureStdout(t, evidencePublicKey)
	if err == nil || strings.TrimSpace(output) != "" {
		t.Fatalf("missing signing key output=%q err=%v", output, err)
	}
	var keys int
	if err := db.QueryRow("SELECT COUNT(*) FROM meta WHERE key LIKE 'evidence_signing_%'").Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("evidence public-key generated a signing key: keys=%d err=%v", keys, err)
	}
}

// TestAdminResetSucceedsWhileServeWrites runs the reset command repeatedly
// against a database another handle is actively writing to, as operators do
// with `docker compose exec` while the service runs.
func TestAdminResetSucceedsWhileServeWrites(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, serving, err := load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serving.Close() })
	claimCommandAdmin(t, serving)
	ctx := context.Background()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var servingErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			hash := make([]byte, 32)
			_, _ = rand.Read(hash)
			if _, _, err := serving.RecordWebhookTrigger(ctx, hex.EncodeToString(hash), []string{"nodeCreated"}, nil); err != nil {
				servingErr = err
				return
			}
			if _, _, err := serving.CreateSession(ctx); err != nil {
				servingErr = err
				return
			}
			// SQLite's busy handler sleeps and is not fair: a writer that
			// re-acquires the lock in a zero-pause loop can starve the admin
			// command past busy_timeout on a loaded machine, which no real
			// serving workload does. A pause keeps the writers interleaved at a
			// rate closer to a busy service (two synced commits per loop).
			time.Sleep(5 * time.Millisecond)
		}
	}()
	deadline := time.Now().Add(time.Second)
	runs := 0
	for time.Now().Before(deadline) {
		output, err := captureStdout(t, adminReset)
		if err != nil || !strings.Contains(output, "Password reset token:") {
			close(stop)
			wg.Wait()
			t.Fatalf("admin reset during serve writes (run %d) output=%q err=%v", runs, output, err)
		}
		runs++
	}
	close(stop)
	wg.Wait()
	if servingErr != nil {
		t.Fatalf("serve writes failed during admin reset: %v", servingErr)
	}
}

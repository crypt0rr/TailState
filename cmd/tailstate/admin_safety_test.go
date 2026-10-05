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
	"strings"
	"sync"
	"testing"
	"time"
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

// TestAdminCommandsNeverCreateOrMigrateDatabases proves that `admin reset`
// and `evidence public-key` leave a missing or older-schema database
// untouched and exit with an explicit error.
func TestAdminCommandsNeverCreateOrMigrateDatabases(t *testing.T) {
	commands := map[string]func() error{
		"admin reset":         adminReset,
		"evidence public-key": evidencePublicKey,
	}
	for name, command := range commands {
		t.Run(name+" missing", func(t *testing.T) {
			dataDir := t.TempDir()
			configureCommandEnvironment(t, dataDir)
			output, err := captureStdout(t, command)
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Fatalf("missing database err=%v output=%q", err, output)
			}
			if _, statErr := os.Stat(filepath.Join(dataDir, "tailstate.db")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s created a database: %v", name, statErr)
			}
			if strings.TrimSpace(output) != "" {
				t.Fatalf("%s printed output for a missing database: %q", name, output)
			}
		})
		t.Run(name+" older schema", func(t *testing.T) {
			dataDir := t.TempDir()
			configureCommandEnvironment(t, dataDir)
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

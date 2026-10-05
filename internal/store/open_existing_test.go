package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// TestOpenExistingIssuesResetTokensWhileServing proves that an administrative
// handle can write while the serving handle is busy with read-then-write
// transactions. With deferred transactions one side fails immediately with
// SQLITE_BUSY_SNAPSHOT; with _txlock=immediate both wait for busy_timeout.
func TestOpenExistingIssuesResetTokensWhileServing(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tailstate.db")
	serving, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serving.Close() })
	ctx := context.Background()
	token, err := serving.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := serving.Claim(ctx, token, "a secure password"); err != nil {
		t.Fatal(err)
	}

	admin, err := OpenExisting(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })

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
			// Both calls read before they write inside one transaction.
			if _, err := serving.NewResetToken(ctx); err != nil {
				servingErr = err
				return
			}
			hash := make([]byte, 32)
			_, _ = rand.Read(hash)
			if _, _, err := serving.RecordWebhookTrigger(ctx, hex.EncodeToString(hash), []string{"nodeCreated"}, nil); err != nil {
				servingErr = err
				return
			}
			// SQLite's busy handler waits by sleeping and is not fair. A
			// writer that re-acquires the lock in a zero-pause loop can starve
			// the other writer past busy_timeout on a loaded machine, which no
			// real serving workload does. A short pause keeps both writers
			// continuously interleaved without that artificial starvation.
			time.Sleep(time.Millisecond)
		}
	}()
	deadline := time.Now().Add(1500 * time.Millisecond)
	issued := 0
	for time.Now().Before(deadline) {
		if _, err := admin.NewResetToken(ctx); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("admin reset token failed while serving writes after %d tokens: %v", issued, err)
		}
		issued++
	}
	close(stop)
	wg.Wait()
	if servingErr != nil {
		t.Fatalf("serving writes failed while admin wrote: %v", servingErr)
	}
	if issued == 0 {
		t.Fatal("no reset tokens were issued")
	}
}

// TestOpenExistingLeavesMissingAndOlderDatabasesUntouched proves the admin
// open path neither creates nor migrates a database.
func TestOpenExistingLeavesMissingAndOlderDatabasesUntouched(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "missing-dir")
	missing := filepath.Join(dir, "tailstate.db")
	if _, err := OpenExisting(missing, box); !errors.Is(err, ErrDatabaseNotFound) {
		t.Fatalf("missing database error=%v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database directory was created: %v", err)
	}

	older := filepath.Join(t.TempDir(), "tailstate.db")
	db, err := sql.Open("sqlite", "file:"+older)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(11)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(older)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(older, box); err == nil || !strings.Contains(err.Error(), "schema version 11") {
		t.Fatalf("older schema error=%v", err)
	}
	after, err := os.ReadFile(older)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("older database was modified")
	}

	empty := filepath.Join(t.TempDir(), "tailstate.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(empty, box); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("empty database error=%v", err)
	}
	if info, err := os.Stat(empty); err != nil || info.Size() != 0 {
		t.Fatalf("empty database was initialized: %v", err)
	}

	current := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := Open(current, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	wrongBox, err := secret.NewBox(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(current, wrongBox); err == nil {
		t.Fatal("wrong master key was accepted")
	}
	if _, err := OpenExisting(current, nil); err == nil {
		t.Fatal("nil master key was accepted")
	}
	if _, err := OpenExisting(" ", box); err == nil {
		t.Fatal("blank path was accepted")
	}
	noKeyCheck, err := sql.Open("sqlite", "file:"+current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noKeyCheck.Exec("DELETE FROM meta WHERE key='master_key_check'"); err != nil {
		t.Fatal(err)
	}
	_ = noKeyCheck.Close()
	if _, err := OpenExisting(current, box); err == nil {
		t.Fatal("database without a master key check was accepted")
	}
}

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func backupTestStore(t *testing.T) (string, *secret.Box) {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.NewSetupToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path, box
}

// TestBackupSnapshotIsConsistentVerifiedAndPrivate checks the published
// snapshot, its sha256sum-format checksum, and that the source database file
// is not modified by taking it.
func TestBackupSnapshotIsConsistentVerifiedAndPrivate(t *testing.T) {
	path, box := backupTestStore(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snapshot.db")
	result, err := Backup(context.Background(), path, box, out)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != currentSchemaVersion || result.Path != out || result.ChecksumPath != out+".sha256" || result.Bytes <= 0 {
		t.Fatalf("result=%#v", result)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("reported checksum %s does not match the file", result.SHA256)
	}
	for _, file := range []string{out, out + ".sha256"} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%v, want 0600", file, info.Mode().Perm())
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("backup modified the source database file")
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(out), ".tailstate-backup-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary snapshot files left behind: %v %v", leftovers, err)
	}
}

func TestBackupRejectsInvalidRequests(t *testing.T) {
	path, box := backupTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	wrongBox, err := secret.NewBox([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "existing.db")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	checksumOnly := filepath.Join(dir, "checksum-only.db")
	if err := os.WriteFile(checksumOnly+".sha256", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		path   string
		box    *secret.Box
		out    string
		target error
		text   string
	}{
		{name: "nil key", path: path, out: filepath.Join(dir, "a.db"), text: "master key is required"},
		{name: "empty path", path: " ", box: box, out: filepath.Join(dir, "a.db"), text: "database path is required"},
		{name: "empty output", path: path, box: box, out: "", text: "output path is required"},
		{name: "missing database", path: filepath.Join(dir, "missing.db"), box: box, out: filepath.Join(dir, "a.db"), target: ErrDatabaseNotFound},
		{name: "live database", path: path, box: box, out: path, text: "live database"},
		{name: "live WAL", path: path, box: box, out: path + "-wal", text: "live database"},
		{name: "existing output", path: path, box: box, out: existing, target: ErrBackupTargetExists},
		{name: "existing checksum", path: path, box: box, out: checksumOnly, target: ErrBackupTargetExists},
		{name: "wrong key", path: path, box: wrongBox, out: filepath.Join(dir, "a.db"), text: "master key does not match"},
		{name: "uninitialized database", path: empty, box: box, out: filepath.Join(dir, "a.db"), text: "not initialized"},
		{name: "missing output directory", path: path, box: box, out: filepath.Join(dir, "missing", "a.db"), text: "create backup file"},
	}
	for _, tc := range cases {
		_, err := Backup(ctx, tc.path, tc.box, tc.out)
		if err == nil || (tc.target != nil && !errors.Is(err, tc.target)) || (tc.text != "" && !strings.Contains(err.Error(), tc.text)) {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "a.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a rejected backup published a file: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Backup(canceled, path, box, filepath.Join(dir, "canceled.db")); err == nil {
		t.Fatal("canceled backup succeeded")
	}
}

// TestBackupNeverReplacesATargetCreatedDuringTheSnapshot guards the publish
// step: a file that appears at the target while the snapshot is written is
// left untouched and the temporary snapshot is removed.
func TestBackupNeverReplacesATargetCreatedDuringTheSnapshot(t *testing.T) {
	path, box := backupTestStore(t)
	out := filepath.Join(t.TempDir(), "race.db")
	t.Cleanup(func() { backupBeforeRename = nil })
	backupBeforeRename = func(string) error { return os.WriteFile(out, []byte("operator file"), 0o600) }
	if _, err := Backup(context.Background(), path, box, out); !errors.Is(err, ErrBackupTargetExists) {
		t.Fatalf("racing target err=%v", err)
	}
	if data, err := os.ReadFile(out); err != nil || string(data) != "operator file" {
		t.Fatalf("racing target was replaced: %q %v", data, err)
	}
	backupBeforeRename = func(string) error { return errors.New("injected publish failure") }
	other := filepath.Join(filepath.Dir(out), "other.db")
	if _, err := Backup(context.Background(), path, box, other); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("publish failure err=%v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".tailstate-backup-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary snapshot files left behind: %v", leftovers)
	}
}

func TestVerifyBackupSnapshotRejectsForeignDatabases(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	notSQLite := filepath.Join(t.TempDir(), "garbage.db")
	if err := os.WriteFile(notSQLite, []byte(strings.Repeat("not a database ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupSnapshot(ctx, notSQLite, box); err == nil {
		t.Fatal("a non-SQLite snapshot was accepted")
	}
	path, _ := backupTestStore(t)
	wrongBox, err := secret.NewBox([]byte(strings.Repeat("w", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupSnapshot(ctx, path, wrongBox); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("wrong-key snapshot err=%v", err)
	}
	legacy := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(11)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupSnapshot(ctx, legacy, box); err != nil {
		t.Fatalf("legacy snapshot without a key check was rejected: %v", err)
	}
	if _, _, err := syncAndHashFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("hashing a missing file succeeded")
	}
	if err := writeNewFile(legacy, nil); err == nil {
		t.Fatal("writeNewFile replaced an existing file")
	}
}

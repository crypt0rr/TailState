package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// BackupResult describes a completed online snapshot.
type BackupResult struct {
	Path          string
	ChecksumPath  string
	SHA256        string
	Bytes         int64
	SchemaVersion int
}

// ErrBackupTargetExists indicates that Backup refused to overwrite an
// existing snapshot or checksum file.
var ErrBackupTargetExists = errors.New("backup target already exists")

// backupBeforeRename is a test seam invoked after the snapshot has been
// written and verified and before it is renamed into place.
var backupBeforeRename func(tempPath string) error

// Backup writes a transactionally consistent copy of the database at path to
// out with SQLite's VACUUM INTO, plus out+".sha256" in sha256sum(1) format.
// It is safe while the service is serving: the source is opened read-only
// (mode=ro), so it never creates, migrates, backfills, or rewrites the
// database, and a WAL reader does not block the service's writer. The master
// key is verified first so a snapshot is only taken from the database that
// key protects, and the copy is integrity-checked and key-checked before it
// is published. A partial snapshot is removed on any failure.
func Backup(ctx context.Context, path string, box *secret.Box, out string) (BackupResult, error) {
	var result BackupResult
	if box == nil {
		return result, errors.New("master key is required")
	}
	if strings.TrimSpace(path) == "" {
		return result, errors.New("database path is required")
	}
	if strings.TrimSpace(out) == "" {
		return result, errors.New("backup output path is required")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("%w: %s", ErrDatabaseNotFound, path)
		}
		return result, fmt.Errorf("inspect database path: %w", err)
	}
	absOut, err := filepath.Abs(out)
	if err != nil {
		return result, fmt.Errorf("resolve backup output path: %w", err)
	}
	absSource, err := filepath.Abs(path)
	if err != nil {
		return result, fmt.Errorf("resolve database path: %w", err)
	}
	for _, live := range []string{absSource, absSource + "-wal", absSource + "-shm", absSource + "-journal"} {
		if absOut == live {
			return result, errors.New("backup output must not be the live database or one of its sidecars")
		}
	}
	checksumPath := absOut + ".sha256"
	for _, target := range []string{absOut, checksumPath} {
		if _, err := os.Lstat(target); err == nil {
			return result, fmt.Errorf("%w: %s", ErrBackupTargetExists, target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("inspect backup target: %w", err)
		}
	}

	// mode=ro refuses to create the source and makes every statement on
	// this connection read-only; VACUUM INTO only reads the source inside
	// one read transaction, so the copy is a single consistent snapshot.
	// query_only is deliberately absent because SQLite treats VACUUM INTO
	// as a write statement under that pragma even though the source is
	// never modified.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return result, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return result, fmt.Errorf("open database: %w", err)
	}
	present, err := verifyExistingMasterKey(db, box)
	if err != nil {
		return result, err
	}
	if !present {
		if err := verifyLegacyMasterKey(db, box); err != nil {
			return result, err
		}
	}
	if err := verifyDatabaseVersionPreflight(db); err != nil {
		return result, err
	}
	version, versioned, err := readDatabaseSchemaVersion(db)
	if err != nil {
		return result, err
	}
	if !versioned {
		return result, errors.New("database is not initialized; start TailState once before running this command")
	}
	result.SchemaVersion = version

	dir := filepath.Dir(absOut)
	temp, err := os.CreateTemp(dir, ".tailstate-backup-*.db")
	if err != nil {
		return result, fmt.Errorf("create backup file: %w", err)
	}
	tempPath := temp.Name()
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tempPath)
		}
	}()
	// VACUUM INTO accepts an existing empty file; creating it here keeps
	// the owner-only permissions independent of the process umask.
	if err := temp.Close(); err != nil {
		return result, fmt.Errorf("create backup file: %w", err)
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", tempPath); err != nil {
		return result, fmt.Errorf("write database snapshot: %w", err)
	}
	if err := db.Close(); err != nil {
		return result, fmt.Errorf("close database: %w", err)
	}
	if err := verifyBackupSnapshot(ctx, tempPath, box); err != nil {
		return result, err
	}
	sum, size, err := syncAndHashFile(tempPath)
	if err != nil {
		return result, err
	}
	if backupBeforeRename != nil {
		if err := backupBeforeRename(tempPath); err != nil {
			return result, err
		}
	}
	// Recheck immediately before publishing so a target created while the
	// snapshot was being written is never replaced.
	if _, err := os.Lstat(absOut); err == nil {
		return result, fmt.Errorf("%w: %s", ErrBackupTargetExists, absOut)
	}
	if err := os.Rename(tempPath, absOut); err != nil {
		return result, fmt.Errorf("publish backup: %w", err)
	}
	published = true
	line := fmt.Sprintf("%s  %s\n", sum, filepath.Base(absOut))
	if err := writeNewFile(checksumPath, []byte(line)); err != nil {
		return result, fmt.Errorf("write backup checksum: %w", err)
	}
	syncDirectory(dir)
	result.Path = absOut
	result.ChecksumPath = checksumPath
	result.SHA256 = sum
	result.Bytes = size
	return result, nil
}

// verifyBackupSnapshot proves the copy is a readable database protected by
// the same master key before it is published under the requested name.
func verifyBackupSnapshot(ctx context.Context, path string, box *secret.Box) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return fmt.Errorf("open database snapshot: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var check string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return fmt.Errorf("check database snapshot: %w", err)
	}
	if check != "ok" {
		return fmt.Errorf("database snapshot failed its integrity check: %s", check)
	}
	present, err := verifyExistingMasterKey(db, box)
	if err != nil {
		return fmt.Errorf("database snapshot: %w", err)
	}
	if !present {
		if err := verifyLegacyMasterKey(db, box); err != nil {
			return fmt.Errorf("database snapshot: %w", err)
		}
	}
	return db.Close()
}

func syncAndHashFile(path string) (string, int64, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return "", 0, fmt.Errorf("open database snapshot: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return "", 0, fmt.Errorf("sync database snapshot: %w", err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("hash database snapshot: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), size, file.Close()
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// syncDirectory makes the renamed snapshot and its checksum durable. It is
// best-effort because some platforms cannot fsync a directory.
func syncDirectory(dir string) {
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
}

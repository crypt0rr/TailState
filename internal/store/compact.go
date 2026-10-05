package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/crypt0rr/tailstate/internal/secret"
)

// CompactOptions selects optional behavior for Compact.
type CompactOptions struct {
	// IncrementalVacuum switches the compacted database to
	// auto_vacuum=INCREMENTAL, after which every cleanup pass that removes
	// rows also returns a bounded number of free pages to the filesystem.
	IncrementalVacuum bool
}

// CompactResult reports the database size before and after compaction.
type CompactResult struct {
	PageSize          int64
	PagesBefore       int64
	FreePagesBefore   int64
	PagesAfter        int64
	FreePagesAfter    int64
	FileBytesBefore   int64
	FileBytesAfter    int64
	AutoVacuumEnabled bool
}

func serviceLockPath(path string) string { return path + ".lock" }

// compactBeforeReplace is a test seam invoked after the compacted copy is
// verified and the source is closed, before it replaces the database.
var compactBeforeReplace func(tempPath string) error

// Compact rewrites the database at path without free pages, so the logical
// size, storage pressure, and the enforced page ceiling reflect live data and
// a lowered budget becomes enforceable. It is an offline operation: it takes
// the service lock (refusing with ErrServiceRunning while serve holds it) and
// it opens the database like OpenExisting, so a missing, older-schema, or
// wrong-key database is never created, migrated, or rewritten.
//
// The copy is written next to the database with VACUUM INTO (no temporary
// directory is needed, which matters on a read-only container root), checked
// for integrity and the master key, and then renamed over the original after
// the source connection has checkpointed and removed its WAL. Until that
// rename the original file is untouched, so a failure at any earlier step
// leaves the database exactly as it was.
func Compact(ctx context.Context, path string, box *secret.Box, options CompactOptions) (CompactResult, error) {
	var result CompactResult
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("%w: %s", ErrDatabaseNotFound, path)
		}
		return result, fmt.Errorf("inspect database path: %w", err)
	}
	lock, err := LockService(path)
	if err != nil {
		return result, err
	}
	defer lock.Release()
	st, err := OpenExisting(path, box)
	if err != nil {
		return result, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = st.Close()
		}
	}()
	if err := readPageStats(ctx, st, &result.PageSize, &result.PagesBefore, &result.FreePagesBefore); err != nil {
		return result, err
	}
	if result.FileBytesBefore, err = physicalFileBytes(path); err != nil {
		return result, fmt.Errorf("read database file size: %w", err)
	}
	if options.IncrementalVacuum {
		// VACUUM INTO applies a pending auto_vacuum change to its output.
		if _, err := st.db.ExecContext(ctx, "PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			return result, fmt.Errorf("enable incremental auto-vacuum: %w", err)
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".tailstate-compact-*.db")
	if err != nil {
		return result, fmt.Errorf("create compacted database: %w", err)
	}
	tempPath := temp.Name()
	replaced := false
	defer func() {
		if !replaced {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Close(); err != nil {
		return result, fmt.Errorf("create compacted database: %w", err)
	}
	if _, err := st.db.ExecContext(ctx, "VACUUM INTO ?", tempPath); err != nil {
		return result, fmt.Errorf("write compacted database: %w", err)
	}
	if err := verifyBackupSnapshot(ctx, tempPath, box); err != nil {
		return result, fmt.Errorf("verify compacted database: %w", err)
	}
	if _, _, err := syncAndHashFile(tempPath); err != nil {
		return result, err
	}
	closed = true
	if err := st.Close(); err != nil {
		return result, fmt.Errorf("close database: %w", err)
	}
	// Closing the last connection checkpoints the WAL into the database and
	// removes both sidecars. A remaining sidecar means another process (an
	// admin command or a service on another host sharing the volume) still
	// has the database open, so replacing the file could lose its writes.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			return result, fmt.Errorf("database is still open by another process (%s exists); stop every TailState process and retry", filepath.Base(path+suffix))
		}
	}
	if compactBeforeReplace != nil {
		if err := compactBeforeReplace(tempPath); err != nil {
			return result, err
		}
	}
	if err := os.Rename(tempPath, path); err != nil {
		return result, fmt.Errorf("replace database: %w", err)
	}
	replaced = true
	syncDirectory(filepath.Dir(path))
	if err := os.Chmod(path, 0o600); err != nil {
		return result, err
	}
	// Reopen the compacted file to restore WAL mode (VACUUM INTO writes a
	// rollback-journal database) and report the new size.
	after, err := OpenExisting(path, box)
	if err != nil {
		return result, fmt.Errorf("reopen compacted database: %w", err)
	}
	defer after.Close()
	if _, err := after.db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return result, fmt.Errorf("restore WAL mode: %w", err)
	}
	if err := readPageStats(ctx, after, &result.PageSize, &result.PagesAfter, &result.FreePagesAfter); err != nil {
		return result, err
	}
	var autoVacuum int
	if err := after.db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&autoVacuum); err != nil {
		return result, fmt.Errorf("read auto-vacuum mode: %w", err)
	}
	result.AutoVacuumEnabled = autoVacuum == 2
	if err := after.Close(); err != nil {
		return result, err
	}
	if result.FileBytesAfter, err = physicalFileBytes(path); err != nil {
		return result, fmt.Errorf("read database file size: %w", err)
	}
	return result, nil
}

func readPageStats(ctx context.Context, st *Store, pageSize, pages, free *int64) error {
	if err := st.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(pageSize); err != nil {
		return fmt.Errorf("read database page size: %w", err)
	}
	if err := st.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(pages); err != nil {
		return fmt.Errorf("read database page count: %w", err)
	}
	if err := st.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(free); err != nil {
		return fmt.Errorf("read database free page count: %w", err)
	}
	return nil
}

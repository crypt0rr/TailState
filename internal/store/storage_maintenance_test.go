package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func maintenanceBox(t *testing.T) *secret.Box {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// TestReadPathsRespondDuringLongWriteTransaction is the regression for the
// single-connection pool: health, readiness, metrics, and History reads must
// not queue behind an open write transaction, and must observe exactly the
// committed state.
func TestReadPathsRespondDuringLongWriteTransaction(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "tailstate.db"), maintenanceBox(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), []string{"nodeCreated"}, nil); err != nil {
		t.Fatal(err)
	}
	if status, err := st.Status(ctx); err != nil || status.WebhookPending != 1 {
		t.Fatalf("committed trigger not visible to readers: %+v %v", status, err)
	}

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status='dead'"); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	started := time.Now()
	if err := st.Ping(readCtx); err != nil {
		t.Fatalf("Ping blocked behind a write transaction: %v", err)
	}
	status, err := st.Status(readCtx)
	if err != nil {
		t.Fatalf("Status blocked behind a write transaction: %v", err)
	}
	if status.WebhookPending != 1 || status.WebhookDead != 0 {
		t.Fatalf("reader observed uncommitted data: %+v", status)
	}
	if _, err := st.StorageMetrics(readCtx); err != nil {
		t.Fatalf("StorageMetrics blocked behind a write transaction: %v", err)
	}
	if _, err := st.ListHistory(readCtx, HistoryFilter{}); err != nil {
		t.Fatalf("ListHistory blocked behind a write transaction: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("read paths took %s during a write transaction", elapsed)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if status, err := st.Status(ctx); err != nil || status.WebhookPending != 0 || status.WebhookDead != 1 {
		t.Fatalf("reader missed a committed update: %+v %v", status, err)
	}
}

func TestReaderPoolIsReadOnlyAndBounded(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "tailstate.db"), maintenanceBox(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if st.reader == nil {
		t.Fatal("serving store has no read-only pool")
	}
	if got := st.reader.Stats().MaxOpenConnections; got != readerPoolSize || got < 2 || got > 4 {
		t.Fatalf("reader pool size=%d", got)
	}
	for _, statement := range []string{"CREATE TABLE reader_probe(a)", "DELETE FROM meta", "PRAGMA journal_mode=DELETE"} {
		if _, err := st.reader.Exec(statement); err == nil && !strings.HasPrefix(statement, "PRAGMA") {
			t.Fatalf("read-only pool executed %q", statement)
		}
	}
	var mode string
	if err := st.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode changed through the read-only pool: %q %v", mode, err)
	}
	var limit int64
	if err := st.db.QueryRow("PRAGMA journal_size_limit").Scan(&limit); err != nil || limit != 64<<20 {
		t.Fatalf("writer journal_size_limit=%d err=%v, want 67108864", limit, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded after Close")
	}
}

// TestWALReturnsToCapAfterBurst proves a burst no longer leaves a WAL as
// large as the burst on disk: journal_size_limit truncates it to the cap when
// the log is reset, and a cleanup pass that did work truncates it fully.
func TestWALReturnsToCapAfterBurst(t *testing.T) {
	original := journalSizeLimitBytes
	journalSizeLimitBytes = 256 << 10
	t.Cleanup(func() { journalSizeLimitBytes = original })
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := Open(path, maintenanceBox(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	burst := func() {
		t.Helper()
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS burst(b BLOB)"); err != nil {
			t.Fatal(err)
		}
		for range 64 {
			if _, err := tx.ExecContext(ctx, "INSERT INTO burst VALUES(randomblob(65536))"); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if size := fileSize(t, path+"-wal"); size < 2<<20 {
			t.Fatalf("burst WAL=%d bytes; the test needs a WAL above the cap", size)
		}
	}

	burst()
	var busy, frames, checkpointed int64
	if err := st.db.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &checkpointed); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM burst"); err != nil {
		t.Fatal(err)
	}
	if size := fileSize(t, path+"-wal"); size > journalSizeLimitBytes {
		t.Fatalf("WAL=%d bytes after the log was reset, want at most the %d byte cap", size, journalSizeLimitBytes)
	}

	burst()
	if _, err := st.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES('expired','csrf',?1,?1)", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if stats.SessionsDeleted != 1 || !stats.WALCheckpointed {
		t.Fatalf("cleanup stats=%+v", stats)
	}
	if size := fileSize(t, path+"-wal"); size != 0 {
		t.Fatalf("WAL=%d bytes after a cleanup pass that did work, want 0", size)
	}

	// A pass with nothing to delete leaves the WAL alone.
	quiet, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 30 * 24 * time.Hour})
	if err != nil || quiet.WALCheckpointed || quiet.TotalRowsChanged() != 0 {
		t.Fatalf("no-op cleanup stats=%+v err=%v", quiet, err)
	}
}

func fillProbe(t *testing.T, st *Store, mebibytes int) {
	t.Helper()
	if _, err := st.db.Exec("CREATE TABLE IF NOT EXISTS retention_probe(b BLOB)"); err != nil {
		t.Fatal(err)
	}
	for range mebibytes * 4 {
		if _, err := st.db.Exec("INSERT INTO retention_probe VALUES(randomblob(262144))"); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPressureFallsAfterRetentionAndCompaction covers the storage budget
// lifecycle: retention lowers used bytes and the pressure ratio immediately,
// a lowered limit that fits the live data is accepted, and after an offline
// compaction the lowered limit is enforced by SQLite again.
func TestPressureFallsAfterRetentionAndCompaction(t *testing.T) {
	box := maintenanceBox(t)
	path := filepath.Join(t.TempDir(), "tailstate.db")
	ctx := context.Background()
	st, err := OpenWithLimits(path, box, StorageLimits{DatabaseBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	fillProbe(t, st, 10)
	full, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("DELETE FROM retention_probe"); err != nil {
		t.Fatal(err)
	}
	afterRetention, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRetention.DatabaseBytes != full.DatabaseBytes || afterRetention.DatabaseFreelistPages == 0 {
		t.Fatalf("retention should leave the file allocated with free pages: before=%+v after=%+v", full, afterRetention)
	}
	if afterRetention.DatabaseUsedBytes >= full.DatabaseUsedBytes/4 || afterRetention.PressureRatio() >= full.PressureRatio()/4 {
		t.Fatalf("pressure did not fall after retention: before=%f after=%f", full.PressureRatio(), afterRetention.PressureRatio())
	}
	if afterRetention.DatabaseFreeBytes != afterRetention.DatabaseFreelistPages*afterRetention.DatabasePageSizeBytes || afterRetention.DatabaseUsedBytes+afterRetention.DatabaseFreeBytes != afterRetention.DatabaseBytes {
		t.Fatalf("inconsistent used/free accounting: %+v", afterRetention)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// The live data fits 8 MiB even though the file is larger: start up,
	// enforce at the current file size, and report the gap.
	lowered, err := OpenWithLimits(path, box, StorageLimits{DatabaseBytes: 8 << 20})
	if err != nil {
		t.Fatalf("lowered limit above the used size was refused: %v", err)
	}
	beforeCompact, err := lowered.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if beforeCompact.LimitEnforced() || beforeCompact.PressureRatio() >= 1 {
		t.Fatalf("before compaction: enforced=%t pressure=%f", beforeCompact.LimitEnforced(), beforeCompact.PressureRatio())
	}
	if err := lowered.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := Compact(ctx, path, box, CompactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.PagesAfter >= result.PagesBefore || result.FreePagesAfter != 0 || result.FileBytesAfter >= result.FileBytesBefore || result.AutoVacuumEnabled {
		t.Fatalf("compaction result=%+v", result)
	}
	compacted, err := OpenWithLimits(path, box, StorageLimits{DatabaseBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { compacted.Close() })
	afterCompact, err := compacted.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterCompact.DatabaseBytes >= beforeCompact.DatabaseBytes || afterCompact.PressureRatio() > afterRetention.PressureRatio()*8 || afterCompact.DatabaseFreelistPages != 0 {
		t.Fatalf("after compaction metrics=%+v", afterCompact)
	}
	assertBudgetEnforced(t, compacted, "after compaction")
}

func TestLimitBelowUsedBytesIsStillRefused(t *testing.T) {
	box := maintenanceBox(t)
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := OpenWithLimits(path, box, StorageLimits{DatabaseBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	fillProbe(t, st, 10)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithLimits(path, box, StorageLimits{DatabaseBytes: 8 << 20}); err == nil || !strings.Contains(err.Error(), "above configured limit") {
		t.Fatalf("limit below the live data err=%v", err)
	}
}

// TestCompactIncrementalVacuumReleasesPagesAfterCleanup proves the optional
// auto_vacuum=INCREMENTAL switch: later cleanup passes return free pages.
func TestCompactIncrementalVacuumReleasesPagesAfterCleanup(t *testing.T) {
	box := maintenanceBox(t)
	path := filepath.Join(t.TempDir(), "tailstate.db")
	ctx := context.Background()
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Compact(ctx, path, box, CompactOptions{IncrementalVacuum: true})
	if err != nil || !result.AutoVacuumEnabled {
		t.Fatalf("incremental compaction result=%+v err=%v", result, err)
	}
	st, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fillProbe(t, st, 2)
	if _, err := st.db.Exec("DELETE FROM retention_probe"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES('expired','csrf',?1,?1)", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	before, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	after, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.PagesReleased == 0 || after.DatabaseFreelistPages >= before.DatabaseFreelistPages || after.DatabaseBytes >= before.DatabaseBytes {
		t.Fatalf("incremental vacuum did not release pages: stats=%+v before=%+v after=%+v", stats, before, after)
	}
}

// TestCompactRefusesWhileServiceLockHeld proves compaction is offline-only.
func TestCompactRefusesWhileServiceLockHeld(t *testing.T) {
	path, box := backupTestStore(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := LockService(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockService(path); !errors.Is(err, ErrServiceRunning) {
		t.Fatalf("second service lock err=%v", err)
	}
	if _, err := Compact(context.Background(), path, box, CompactOptions{}); !errors.Is(err, ErrServiceRunning) {
		t.Fatalf("compact while locked err=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused compaction modified the database")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := Compact(context.Background(), path, box, CompactOptions{}); err != nil {
		t.Fatalf("compact after the service stopped: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("compacted database mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestCompactNeverCreatesMigratesOrRewritesForeignDatabases(t *testing.T) {
	box := maintenanceBox(t)
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "tailstate.db")
	if _, err := Compact(ctx, missing, box, CompactOptions{}); !errors.Is(err, ErrDatabaseNotFound) {
		t.Fatalf("missing database err=%v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("compact created a database: %v", err)
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
	if _, err := Compact(ctx, older, box, CompactOptions{}); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("older schema err=%v", err)
	}
	if after, _ := os.ReadFile(older); !bytes.Equal(before, after) {
		t.Fatal("compact modified an older-schema database")
	}
	path, _ := backupTestStore(t)
	wrongBox, err := secret.NewBox([]byte(strings.Repeat("w", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compact(ctx, path, wrongBox, CompactOptions{}); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("wrong key err=%v", err)
	}
}

// TestCompactLeavesDatabaseIntactOnFailure covers the replacement guard: an
// open connection from another process, or a failure before the rename,
// leaves the original database untouched and removes the temporary copy.
func TestCompactLeavesDatabaseIntactOnFailure(t *testing.T) {
	path, box := backupTestStore(t)
	ctx := context.Background()
	other, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := other.QueryRow("SELECT COUNT(*) FROM meta").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err := Compact(ctx, path, box, CompactOptions{}); err == nil || !strings.Contains(err.Error(), "still open") {
		t.Fatalf("compact with another open connection err=%v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { compactBeforeReplace = nil })
	compactBeforeReplace = func(string) error { return errors.New("injected replace failure") }
	if _, err := Compact(ctx, path, box, CompactOptions{}); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("injected failure err=%v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".tailstate-compact-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary compaction files left behind: %v", leftovers)
	}
	st, err := OpenExisting(path, box)
	if err != nil {
		t.Fatalf("database unusable after a failed compaction: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

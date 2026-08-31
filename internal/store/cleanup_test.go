package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCleanupWithOptionsBatchesAndResumes(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 300; i++ {
		if _, err := st.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?)", fmt.Sprintf("expired-%d", i), "csrf", old, old); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 24 * time.Hour, BatchSize: 7, PassBudget: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if stats.SessionsDeleted != 300 || stats.Remaining || stats.Transactions < 44 || stats.TotalRowsChanged() != 300 {
		t.Fatalf("batched cleanup stats=%+v", stats)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("batched cleanup left %d sessions", count)
	}

	for i := 0; i < 4; i++ {
		if _, err := st.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?)", fmt.Sprintf("resume-%d", i), "csrf", old, old); err != nil {
			t.Fatal(err)
		}
	}
	stats, err = st.CleanupWithOptions(ctx, CleanupOptions{Retention: 24 * time.Hour, BatchSize: 1, PassBudget: time.Nanosecond})
	if err != nil || !stats.Remaining || stats.SessionsDeleted != 0 {
		t.Fatalf("budgeted cleanup stats=%+v err=%v", stats, err)
	}
	stats, err = st.CleanupWithOptions(ctx, CleanupOptions{Retention: 24 * time.Hour, BatchSize: 2, PassBudget: time.Second})
	if err != nil || stats.Remaining || stats.SessionsDeleted != 4 {
		t.Fatalf("resumed cleanup stats=%+v err=%v", stats, err)
	}
}

func TestCleanupWithOptionsHonorsCancellation(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup cancellation stats=%+v err=%v", stats, err)
	}
	if stats.Transactions != 0 || stats.Duration < 0 {
		t.Fatalf("canceled cleanup performed work: %+v", stats)
	}
}

func TestCleanupWithOptionsClampsBatchAndBoundsTransactions(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: time.Hour, BatchSize: 2048, TransactionBudget: time.Hour, PassBudget: time.Second}); err != nil {
		t.Fatalf("clamped cleanup failed: %v", err)
	}
	if _, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: time.Hour, BatchSize: 1, TransactionBudget: time.Hour, PassBudget: time.Second}); err != nil {
		t.Fatalf("bounded transaction cleanup failed: %v", err)
	}
}

func TestCleanupWithOptionsReportsFailedPhase(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.db.ExecContext(ctx, "DROP TABLE sessions"); err != nil {
		t.Fatal(err)
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: time.Hour})
	if err == nil || stats.FailedPhase != "sessions" || !strings.Contains(err.Error(), "cleanup sessions") {
		t.Fatalf("failed cleanup stats=%+v err=%v", stats, err)
	}
}

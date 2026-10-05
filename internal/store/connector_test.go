package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func openBudgetedStore(t *testing.T, budget int64) *Store {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenWithLimits(filepath.Join(t.TempDir(), "tailstate.db"), box, StorageLimits{DatabaseBytes: budget})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func assertBudgetEnforced(t *testing.T, st *Store, stage string) {
	t.Helper()
	ctx := context.Background()
	metrics, err := st.StorageMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !metrics.LimitEnforced() {
		t.Fatalf("%s: enforced ceiling %d exceeds configured budget %d", stage, metrics.DatabaseEnforcedLimitBytes, metrics.DatabaseLimitBytes)
	}
	if _, err := st.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS budget_probe(b BLOB)"); err != nil {
		t.Fatalf("%s: create probe table: %v", stage, err)
	}
	_, err = st.db.ExecContext(ctx, "INSERT INTO budget_probe VALUES (zeroblob(?))", 12<<20)
	if !errors.Is(storageWriteError(err), ErrStorageBudgetExceeded) {
		t.Fatalf("%s: 12 MiB write under an 8 MiB budget returned %v, want ErrStorageBudgetExceeded", stage, err)
	}
}

// TestDatabaseBudgetSurvivesInterruptedStatement guards the regression where
// an interrupted statement made database/sql discard the pooled connection
// and the replacement silently reverted to SQLite's default page ceiling.
func TestDatabaseBudgetSurvivesInterruptedStatement(t *testing.T) {
	st := openBudgetedStore(t, 8<<20)
	assertBudgetEnforced(t, st, "before interrupt")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := st.db.ExecContext(ctx, "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c")
	if err == nil {
		t.Fatal("unbounded recursive query was not interrupted")
	}
	assertBudgetEnforced(t, st, "after interrupt")
}

func TestDatabaseBudgetSurvivesPoolReconnect(t *testing.T) {
	st := openBudgetedStore(t, 8<<20)
	st.db.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)
	assertBudgetEnforced(t, st, "after forced reconnect")
	st.db.SetConnMaxLifetime(0)
}

func TestSetStorageLimitsAppliesToLaterConnections(t *testing.T) {
	st := openBudgetedStore(t, 64<<20)
	if err := st.SetStorageLimits(StorageLimits{DatabaseBytes: 8 << 20}); err != nil {
		t.Fatal(err)
	}
	st.db.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)
	assertBudgetEnforced(t, st, "after lowering the budget and reconnecting")
	st.db.SetConnMaxLifetime(0)
}

func TestStorageMetricsLimitEnforced(t *testing.T) {
	cases := []struct {
		name    string
		metrics StorageMetrics
		want    bool
	}{
		{"within budget", StorageMetrics{DatabaseLimitBytes: 8192, DatabaseEnforcedLimitBytes: 8192, DatabasePageSizeBytes: 4096}, true},
		{"sub-page budget rounds up", StorageMetrics{DatabaseLimitBytes: 100, DatabaseEnforcedLimitBytes: 4096, DatabasePageSizeBytes: 4096}, true},
		{"default ceiling", StorageMetrics{DatabaseLimitBytes: 8192, DatabaseEnforcedLimitBytes: 4294967294 * 4096, DatabasePageSizeBytes: 4096}, false},
		{"unknown budget", StorageMetrics{DatabaseEnforcedLimitBytes: 4096, DatabasePageSizeBytes: 4096}, false},
		{"unknown ceiling", StorageMetrics{DatabaseLimitBytes: 8192, DatabasePageSizeBytes: 4096}, false},
	}
	for _, tc := range cases {
		if got := tc.metrics.LimitEnforced(); got != tc.want {
			t.Errorf("%s: LimitEnforced()=%t, want %t", tc.name, got, tc.want)
		}
	}
}

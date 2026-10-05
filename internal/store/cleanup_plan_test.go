package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func cleanupQueryPlan(t *testing.T, st *Store, phase cleanupPhase) []string {
	t.Helper()
	args := append(append([]any(nil), phase.args...), defaultCleanupBatchSize)
	rows, err := st.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+phase.query, args...)
	if err != nil {
		t.Fatalf("explain %s: %v", phase.name, err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan
}

// TestCleanupStatementsUseIndexedPlans asserts that every retention statement
// reaches its rows through an index or primary-key search. A full table scan
// or a temporary sort makes a no-op pass grow with the table and can exceed
// the per-transaction budget on large or slow hosts.
func TestCleanupStatementsUseIndexedPlans(t *testing.T) {
	st := testStore(t)
	var stats CleanupStats
	phases := cleanupPhases(&stats, time.Now().UTC(), 30*24*time.Hour)
	if len(phases) == 0 {
		t.Fatal("no cleanup phases")
	}
	for _, phase := range phases {
		plan := cleanupQueryPlan(t, st, phase)
		if len(plan) == 0 {
			t.Fatalf("%s: empty query plan", phase.name)
		}
		searched := false
		for _, step := range plan {
			if strings.HasPrefix(step, "SCAN ") || strings.Contains(step, "TEMP B-TREE") {
				t.Errorf("%s: plan step %q is a full scan or temporary sort; plan=%q", phase.name, step, plan)
			}
			if strings.HasPrefix(step, "SEARCH ") {
				searched = true
			}
		}
		if !searched {
			t.Errorf("%s: plan has no index search; plan=%q", phase.name, plan)
		}
	}
}

// TestNoOpCleanupOverLargeTablesStaysWithinBudget fills the retention tables
// with 200k rows (20k under -race) that are all inside the retention window and asserts that a
// cleanup pass changes nothing and finishes well inside one per-transaction
// budget (an over-budget statement is cancelled and fails the pass).
func TestNoOpCleanupOverLargeTablesStaysWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("large retention fixture")
	}
	ctx := context.Background()
	st := testStore(t)
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	rows := 200000
	if raceDetectorEnabled {
		// The plan assertions above are the scale-independent guarantee; under
		// the race detector a smaller fixture keeps the suite practical.
		rows = 20000
	}
	const series = `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) `
	// Loading the fixture with every secondary index maintained row by row is
	// slow in the pure-Go SQLite build. Drop the explicit indexes, bulk load,
	// and rebuild them from their stored definitions so the pass runs against
	// exactly the production index set.
	indexRows, err := st.db.QueryContext(ctx, "SELECT name,sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")
	if err != nil {
		t.Fatal(err)
	}
	indexes := map[string]string{}
	for indexRows.Next() {
		var name, definition string
		if err := indexRows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		indexes[name] = definition
	}
	if err := indexRows.Close(); err != nil {
		t.Fatal(err)
	}
	for name := range indexes {
		if _, err := st.db.ExecContext(ctx, "DROP INDEX "+name); err != nil {
			t.Fatal(err)
		}
	}
	for _, fixture := range []struct {
		statement string
		args      []any
	}{
		{series + `INSERT INTO event_batches(id,generation,observed_at,change_count,created_at) SELECT i,1,?,1,? FROM n`, []any{rows, recent, recent}},
		{series + `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) SELECT i,1,?,'devices','changed','r','n','[]' FROM n`, []any{rows, recent}},
		{series + `INSERT INTO event_batch_triggers(batch_id,trigger_id) SELECT i,i FROM n`, []any{rows}},
		{series + `INSERT INTO outbox(batch_id,destination_id,payload,status,next_attempt,first_attempt,created_at,delivered_at) SELECT i,1,'p',CASE i%2 WHEN 0 THEN 'delivered' ELSE 'dead' END,?,?,?,? FROM n`, []any{rows, recent, recent, recent, recent}},
		{series + `INSERT INTO webhook_triggers(body_hash,received_at,event_types_json,collectors_json,status,next_attempt_at) SELECT printf('%064d',i),?,'[]','[]','processed',? FROM n`, []any{rows, recent, recent}},
	} {
		if _, err := st.db.ExecContext(ctx, fixture.statement, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, definition := range indexes {
		if _, err := st.db.ExecContext(ctx, definition); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 30 * 24 * time.Hour, PassBudget: 10 * time.Second})
	if err != nil || stats.Remaining || stats.TotalRowsChanged() != 0 {
		t.Fatalf("no-op cleanup over %d rows stats=%+v err=%v", rows, stats, err)
	}
	if stats.Duration >= defaultCleanupTransactionBudget {
		t.Fatalf("no-op cleanup over %d rows took %s, want well under the %s per-transaction budget", rows, stats.Duration, defaultCleanupTransactionBudget)
	}
}

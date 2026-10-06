package store

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
)

// sameStoredTime reports whether two stored timestamps name the same
// instant, whichever RFC 3339 form each uses.
func sameStoredTime(a, b string) bool {
	left, leftErr := time.Parse(time.RFC3339Nano, a)
	right, rightErr := time.Parse(time.RFC3339Nano, b)
	return leftErr == nil && rightErr == nil && left.Equal(right)
}

// subSecondTimes are instants within, and on either side of, one second,
// in chronological order. The whole second and the values with trailing
// fractional zeros are the ones RFC 3339 (Nano) renders at a shorter width.
func subSecondTimes() []time.Time {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	return []time.Time{
		base.Add(-time.Nanosecond),
		base,
		base.Add(time.Nanosecond),
		base.Add(100 * time.Millisecond),
		base.Add(100*time.Millisecond + time.Nanosecond),
		base.Add(500 * time.Millisecond),
		base.Add(999999999 * time.Nanosecond),
		base.Add(time.Second),
	}
}

func sqliteLessOrEqual(t *testing.T, db *sql.DB, left, right string) bool {
	t.Helper()
	var result bool
	if err := db.QueryRow("SELECT ? <= ?", left, right).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

// TestStoredTimestampsCompareChronologically proves that SQL string
// comparison of timestampLayout values agrees with chronological order for
// every pair of sub-second times, and documents why the variable-width
// RFC 3339 form written before schema 17 did not.
func TestStoredTimestampsCompareChronologically(t *testing.T) {
	st := testStore(t)
	times := subSecondTimes()
	for _, left := range times {
		for _, right := range times {
			formattedLeft, formattedRight := formatTimestamp(left), formatTimestamp(right)
			if len(formattedLeft) != len(timestampLayout) {
				t.Fatalf("%s is not fixed width", formattedLeft)
			}
			want := !left.After(right)
			if got := sqliteLessOrEqual(t, st.db, formattedLeft, formattedRight); got != want {
				t.Fatalf("%s <= %s = %v, want %v", formattedLeft, formattedRight, got, want)
			}
			if parsed, err := time.Parse(time.RFC3339Nano, formattedLeft); err != nil || !parsed.Equal(left) {
				t.Fatalf("%s does not round-trip: %v %v", formattedLeft, parsed, err)
			}
		}
	}
	// The defect schema 17 fixes: a whole second renders as "…:00Z", which
	// sorts after "…:00.1Z" because 'Z' sorts after '.'.
	whole, tenth := times[1], times[3]
	if sqliteLessOrEqual(t, st.db, whole.Format(time.RFC3339Nano), tenth.Format(time.RFC3339Nano)) {
		t.Fatal("the legacy format unexpectedly ordered a whole second before its first tenth")
	}
	// Non-UTC input is stored as UTC.
	if got := formatTimestamp(times[1].In(time.FixedZone("CEST", 2*3600))); got != "2026-10-06T12:00:00.000000000Z" {
		t.Fatalf("formatTimestamp converted to %q", got)
	}
}

// TestObservationBoundOrdersLegacyAndCurrentForms proves that the
// whole-second bound used for observation times (which are signed evidence
// and never rewritten) orders a legacy RFC 3339 value and a timestampLayout
// value of the same instant identically.
func TestObservationBoundOrdersLegacyAndCurrentForms(t *testing.T) {
	st := testStore(t)
	times := subSecondTimes()
	for _, value := range times {
		for _, stored := range []string{value.Format(time.RFC3339Nano), formatTimestamp(value)} {
			for _, bound := range times {
				// "observed_at >= bound" must hold exactly when the value is
				// at or after the start of the bound's second.
				want := !value.Before(bound.Truncate(time.Second))
				var got bool
				if err := st.db.QueryRow("SELECT ? >= ?", stored, observationBound(bound)).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("%s >= bound(%s) = %v, want %v", stored, bound.Format(time.RFC3339Nano), got, want)
				}
			}
		}
	}
}

// TestSubSecondLeaseExpiryAndScheduleComparisons exercises the store's own
// lease, expiry, retry, and schedule comparisons with deadlines on a whole
// second, the case the legacy format misordered: a deadline at "…:SSZ" was
// treated as later than any time within that second.
func TestSubSecondLeaseExpiryAndScheduleComparisons(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}

	// Outbox: an in-flight row whose lease ended on the current whole second
	// is reclaimed, and a row the store rescheduled for that second after a
	// failed attempt is claimed again within it.
	if err := st.EnqueueSystem(ctx, "leased"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "retried"); err != nil {
		t.Fatal(err)
	}
	first, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil || len(first) != 2 {
		t.Fatalf("initial claim=%d err=%v", len(first), err)
	}
	second := time.Now().Truncate(time.Second)
	for _, item := range first {
		if strings.Contains(item.Payload, "retried") {
			if ok, err := st.RetryClaimedResult(ctx, item, second, "failed", false); err != nil || !ok {
				t.Fatalf("retry=%v err=%v", ok, err)
			}
			continue
		}
		if _, err := st.db.Exec("UPDATE outbox SET lease_until=? WHERE id=?", formatTimestamp(second), item.ID); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 2 {
		t.Fatalf("claimed %d rows, want the reclaimed lease and the row due this second", len(claimed))
	}

	// Webhook triggers: a trigger the store rescheduled for a whole second is
	// due from that instant on, and an expired lease is due; checked against
	// a deterministic "now" a fraction of a second either side.
	deadline := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), []string{"nodeCreated"}, nil); err != nil {
		t.Fatal(err)
	}
	claims, err := st.ClaimWebhookTriggers(ctx, 8, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("trigger claims=%d err=%v", len(claims), err)
	}
	if err := st.RetryClaimedWebhookTriggers(ctx, claims, deadline, "failed"); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		at   time.Time
		want bool
	}{
		{deadline.Add(-time.Nanosecond), false},
		{deadline, true},
		{deadline.Add(100 * time.Millisecond), true},
	} {
		if due, err := st.HasDueWebhookTriggers(ctx, check.at); err != nil || due != check.want {
			t.Fatalf("trigger due at %s = %v (%v), want %v", check.at.Format(time.RFC3339Nano), due, err, check.want)
		}
	}
	if _, err := st.db.Exec("UPDATE webhook_triggers SET status='processing',next_attempt_at=?,lease_until=? WHERE id=?", formatTimestamp(deadline.Add(time.Hour)), formatTimestamp(deadline), claims[0].ID); err != nil {
		t.Fatal(err)
	}
	if due, err := st.HasDueWebhookTriggers(ctx, deadline.Add(100*time.Millisecond)); err != nil || !due {
		t.Fatalf("expired trigger lease not due: %v %v", due, err)
	}
	if due, err := st.HasDueWebhookTriggers(ctx, deadline.Add(-100*time.Millisecond)); err != nil || due {
		t.Fatalf("live trigger lease due: %v %v", due, err)
	}

	// Sessions and setup/reset tokens: retention removes rows that expired
	// on the whole second and keeps rows that expire a fraction later.
	now := deadline.Add(100 * time.Millisecond)
	for _, row := range []struct{ token, expires string }{
		{"expired", formatTimestamp(deadline)},
		{"live", formatTimestamp(deadline.Add(200 * time.Millisecond))},
	} {
		if _, err := st.db.Exec("INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?)", secret.HashToken(row.token), secret.HashToken("csrf"), row.expires, formatTimestamp(now), formatTimestamp(now)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec("INSERT INTO auth_tokens(token_hash,kind,created_at,expires_at) VALUES(?,?,?,?)", secret.HashToken(row.token+"-token"), map[string]string{"expired": "setup", "live": "reset"}[row.token], formatTimestamp(now), row.expires); err != nil {
			t.Fatal(err)
		}
	}
	var stats CleanupStats
	budget := cleanupBudget{deadline: time.Now().Add(time.Minute), transaction: time.Minute, batchSize: 64}
	for _, phase := range cleanupPhases(&stats, now, 30*24*time.Hour)[:2] {
		if _, err := st.runCleanupPhase(ctx, &stats, phase, &budget); err != nil {
			t.Fatal(err)
		}
	}
	if stats.SessionsDeleted != 1 || stats.AuthTokensDeleted != 1 {
		t.Fatalf("expiry cleanup removed %d sessions and %d tokens, want 1 and 1", stats.SessionsDeleted, stats.AuthTokensDeleted)
	}
	var remaining int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE token_hash=?", secret.HashToken("live")).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("the live session was removed: %d %v", remaining, err)
	}

	// Collector schedule: a poll due on the current whole second is due.
	if err := st.SetNextPollErr(ctx, generation, []string{"devices"}, time.Now().Truncate(time.Second)); err != nil {
		t.Fatal(err)
	}
	if due, err := st.CollectorDueWithError(ctx, generation, "devices"); err != nil || !due {
		t.Fatalf("collector due on the whole second = %v (%v)", due, err)
	}
	var stored string
	if err := st.db.QueryRow("SELECT next_poll FROM collector_state WHERE generation=? AND collector='devices'", generation).Scan(&stored); err != nil || len(stored) != len(timestampLayout) {
		t.Fatalf("next_poll stored as %q (%v)", stored, err)
	}
}

// TestSchemaV17MigrationRewritesOperationalTimestamps upgrades a schema v16
// database whose operational timestamps use the legacy variable-width form:
// they are rewritten to timestampLayout in bounded chunks, naming the same
// instants, so whole-second leases compare correctly afterwards; signed
// observation times keep their exact bytes and the evidence chain still
// audits; and the rewrite is idempotent.
func TestSchemaV17MigrationRewritesOperationalTimestamps(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	digest := notify.Context{}.Digest
	device := func(name string) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "d1", Type: "device", Name: name, Data: map[string]any{"id": "d1", "name": name}}}}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, device("a"), digest); err != nil {
		t.Fatal(err)
	}
	var headBefore sql.NullString
	if err := st.db.QueryRow("SELECT value FROM meta WHERE key=?", evidenceLedgerHeadMeta).Scan(&headBefore); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, device("b"), digest)
	if err != nil {
		t.Fatal(err)
	}
	if batch.ID == 0 {
		t.Fatal("no change batch was recorded")
	}
	// Rewrite the batch's observation times in the legacy form, as a release
	// before schema 17 wrote them, and sign it afresh in that form.
	legacyObserved := time.Now().UTC().Truncate(time.Second).Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.Exec("UPDATE event_batches SET observed_at=? WHERE id=?", legacyObserved, batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE events SET observed_at=? WHERE batch_id=?", legacyObserved, batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE evidence_ledger SET observed_at=? WHERE batch_id=?", legacyObserved, batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("DELETE FROM evidence_ledger WHERE batch_id=?", batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE sqlite_sequence SET seq=seq-1 WHERE name='evidence_ledger'"); err != nil {
		t.Fatal(err)
	}
	if headBefore.Valid {
		_, err = st.db.Exec("UPDATE meta SET value=? WHERE key=?", headBefore.String, evidenceLedgerHeadMeta)
	} else {
		_, err = st.db.Exec("DELETE FROM meta WHERE key=?", evidenceLedgerHeadMeta)
	}
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.appendEvidenceLedgerTx(ctx, tx, batch.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	ledgerBefore, _, err := evidenceLedgerPayload(ctx, st.db, batch.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Legacy operational values: more sessions than one chunk, a lease that
	// ended on a whole second, a pending row due on that second, and an
	// unparseable value that must be left alone.
	second := time.Now().UTC().Truncate(time.Second)
	legacy := map[string]string{}
	for index := 0; index < migrationChunkSize+6; index++ {
		token := "session-" + strings.Repeat("x", index%3) + string(rune('a'+index%26)) + time.Duration(index).String()
		expires := second.Add(time.Hour + time.Duration(index)*100*time.Millisecond).Format(time.RFC3339Nano)
		legacy[token] = expires
		if _, err := st.db.Exec("INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?)", secret.HashToken(token), secret.HashToken("csrf"), expires, second.Format(time.RFC3339Nano), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EnqueueSystem(ctx, "leased"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "due"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE outbox SET status='processing',lease_until=?,lease_token='old',first_attempt=?,created_at=? WHERE payload LIKE '%leased%'", second.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE outbox SET next_attempt=?,first_attempt=?,created_at=? WHERE payload LIKE '%due%'", second.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("INSERT INTO admin_audit(created_at,event) VALUES(?, 'legacy')", "not a time"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE schema_version SET version=16"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path, box)
	if err != nil {
		t.Fatalf("v16 database did not migrate: %v", err)
	}
	defer st.Close()
	var version int
	if err := st.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	for token, expires := range legacy {
		var stored, lastSeen string
		if err := st.db.QueryRow("SELECT expires_at,last_seen_at FROM sessions WHERE token_hash=?", secret.HashToken(token)).Scan(&stored, &lastSeen); err != nil {
			t.Fatal(err)
		}
		if len(stored) != len(timestampLayout) || !sameStoredTime(stored, expires) {
			t.Fatalf("session expiry %q was rewritten to %q", expires, stored)
		}
		if lastSeen != "" {
			t.Fatalf("an empty last-seen time became %q", lastSeen)
		}
	}
	var unparseable string
	if err := st.db.QueryRow("SELECT created_at FROM admin_audit WHERE event='legacy'").Scan(&unparseable); err != nil || unparseable != "not a time" {
		t.Fatalf("an unparseable value was changed to %q (%v)", unparseable, err)
	}
	var observed string
	if err := st.db.QueryRow("SELECT observed_at FROM event_batches WHERE id=?", batch.ID).Scan(&observed); err != nil || observed != legacyObserved {
		t.Fatalf("a signed observation time changed to %q (%v)", observed, err)
	}
	ledgerAfter, _, err := evidenceLedgerPayload(ctx, st.db, batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ledgerBefore, ledgerAfter) {
		t.Fatalf("ledger payload bytes changed by the migration:\n%s\n%s", ledgerBefore, ledgerAfter)
	}
	auditComplete(t, st)
	// The legacy whole-second lease and due time now compare correctly
	// within the current second.
	claimed, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, item := range claimed {
		for _, payload := range []string{"leased", "due"} {
			if strings.Contains(item.Payload, payload) {
				found[payload] = true
			}
		}
	}
	if !found["leased"] || !found["due"] {
		t.Fatalf("migrated whole-second rows were not claimed: %v", found)
	}

	// Rerunning the rewrite (an interrupted upgrade starting again) changes
	// nothing.
	snapshot := func() string {
		var out strings.Builder
		for _, target := range timestampColumns {
			rows, err := st.db.Query("SELECT rowid," + strings.Join(target.columns, ",") + " FROM " + target.table + " ORDER BY rowid")
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				values := make([]sql.NullString, len(target.columns)+1)
				targets := make([]any, len(values))
				for index := range values {
					targets[index] = &values[index]
				}
				if err := rows.Scan(targets...); err != nil {
					t.Fatal(err)
				}
				for _, value := range values {
					out.WriteString(value.String + "|")
				}
				out.WriteString("\n")
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
		}
		return out.String()
	}
	before := snapshot()
	if _, err := st.db.Exec("UPDATE schema_version SET version=16"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV16ToV17(st.db); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); after != before {
		t.Fatal("rerunning the timestamp rewrite changed stored values")
	}
}

// TestObservationRetentionHandlesLegacyAndCurrentForms runs event retention
// over observation times in both stored forms around the cutoff second.
// Retention resolves to whole seconds: rows in an earlier second are removed
// whatever their form, rows within the cutoff's second are kept (until the
// next pass), and the decision never depends on the form.
func TestObservationRetentionHandlesLegacyAndCurrentForms(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	retention := 24 * time.Hour
	now := time.Now().UTC().Truncate(time.Second).Add(300 * time.Millisecond)
	cutoffSecond := now.Add(-retention).Truncate(time.Second)
	rows := []struct {
		observed string
		kept     bool
	}{
		{cutoffSecond.Add(-500 * time.Millisecond).Format(time.RFC3339Nano), false},
		{formatTimestamp(cutoffSecond.Add(-time.Nanosecond)), false},
		{cutoffSecond.Format(time.RFC3339Nano), true},
		{formatTimestamp(cutoffSecond), true},
		{cutoffSecond.Add(100 * time.Millisecond).Format(time.RFC3339Nano), true},
		{formatTimestamp(cutoffSecond.Add(100 * time.Millisecond)), true},
	}
	for index, row := range rows {
		if _, err := st.db.Exec("INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(NULL,1,?,'devices','changed',?,'n','[]')", row.observed, index); err != nil {
			t.Fatal(err)
		}
	}
	var stats CleanupStats
	budget := cleanupBudget{deadline: time.Now().Add(time.Minute), transaction: time.Minute, batchSize: 64}
	for _, phase := range cleanupPhases(&stats, now, retention) {
		if phase.name != "events" {
			continue
		}
		if _, err := st.runCleanupPhase(ctx, &stats, phase, &budget); err != nil {
			t.Fatal(err)
		}
	}
	for index, row := range rows {
		var count int
		if err := st.db.QueryRow("SELECT COUNT(*) FROM events WHERE resource_id=?", index).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if (count == 1) != row.kept {
			t.Fatalf("event observed at %s kept=%v, want %v", row.observed, count == 1, row.kept)
		}
	}
}

func TestSchemaV16ToV17ReportsErrors(t *testing.T) {
	t.Run("missing table", func(t *testing.T) {
		db := migrationErrorDB(t)
		if err := migrateSchemaV16ToV17(db); err == nil || !strings.Contains(err.Error(), "read sessions timestamps") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("rewrite", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 16)
		if _, err := db.Exec("INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES('h','c','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TRIGGER fail_v17_rewrite BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT,'rewrite failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV16ToV17(db); err == nil || !strings.Contains(err.Error(), "rewrite sessions timestamps") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("schema version", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 16)
		if _, err := db.Exec(`CREATE TRIGGER fail_v17_schema_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV16ToV17(db); err == nil || !strings.Contains(err.Error(), "record timestamp format migration") {
			t.Fatalf("migration error=%v", err)
		}
		var version int
		if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 16 {
			t.Fatalf("failed migration changed schema version to %d err=%v", version, err)
		}
	})
	t.Run("dispatch", func(t *testing.T) {
		box, _ := secret.NewBox(make([]byte, 32))
		db := migrationErrorDB(t)
		if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(16)"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "read sessions timestamps") {
			t.Fatalf("dispatch error=%v", err)
		}
	})
}

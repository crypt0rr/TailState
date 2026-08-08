package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestStoreLifecycleAndCollectorStateBranches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if !st.CollectorDue(ctx, generation, "devices") {
		t.Fatal("collector without state should be due")
	}
	st.SetNextPoll(ctx, generation, []string{"devices"}, time.Now().Add(time.Hour))
	if st.CollectorDue(ctx, generation, "devices") {
		t.Fatal("future collector was marked due")
	}
	st.SetNextPoll(ctx, generation, []string{"devices"}, time.Now().Add(-time.Minute))
	if !st.CollectorDue(ctx, generation, "devices") {
		t.Fatal("past collector was not due")
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE collector_state SET next_poll='not-a-time' WHERE generation=? AND collector=?", generation, "devices"); err != nil {
		t.Fatal(err)
	}
	if !st.CollectorDue(ctx, generation, "devices") {
		t.Fatal("malformed next poll was not treated as due")
	}

	for attempt := 1; attempt <= 3; attempt++ {
		notify, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "temporary failure")
		if err != nil {
			t.Fatal(err)
		}
		if notify != (attempt == 3) {
			t.Fatalf("failure %d notification=%v", attempt, notify)
		}
	}
	if !st.CollectorWasUnhealthy(ctx, generation, "devices") {
		t.Fatal("collector was not marked unhealthy after threshold")
	}
	if notify, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "again"); err != nil || notify {
		t.Fatalf("fourth failure notification=%v err=%v", notify, err)
	}
	if _, err := st.ApplyBatch(ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}
	if st.CollectorWasUnhealthy(ctx, generation, "devices") {
		t.Fatal("successful collection did not clear unhealthy state")
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Ping(ctx); err == nil {
		t.Fatal("Ping succeeded after database close")
	}
}

func TestResetPasswordAndDeleteSessionBranches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.ResetPassword(ctx, "new secure password"); !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("reset before setup error=%v", err)
	}
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "old secure password"); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetPassword(ctx, "short"); err == nil {
		t.Fatal("short password was accepted")
	}
	session, csrf, err := st.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ValidateSession(ctx, session, csrf, true) {
		t.Fatal("session was not valid before reset")
	}
	if err := st.ResetPassword(ctx, "new secure password"); err != nil {
		t.Fatal(err)
	}
	if !st.Authenticate(ctx, "new secure password") || st.Authenticate(ctx, "old secure password") {
		t.Fatal("password reset did not replace credentials")
	}
	if st.ValidateSession(ctx, session, csrf, true) {
		t.Fatal("password reset retained an old session")
	}
	another, anotherCSRF, err := st.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.DeleteSession(ctx, another)
	if st.ValidateSession(ctx, another, anotherCSRF, true) {
		t.Fatal("DeleteSession retained the session")
	}
}

func TestDestinationDeleteAndDeliveredBranches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%#v err=%v", destinations, err)
	}
	destinationID := destinations[0].ID
	if err := st.EnqueueSystem(ctx, "pending payload"); err != nil {
		t.Fatal(err)
	}
	items, err := st.DueOutbox(ctx, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("outbox=%#v err=%v", items, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET last_error='old error' WHERE id=?", items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Delivered(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error FROM outbox WHERE id=?", items[0].ID).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "delivered" || lastError != "" {
		t.Fatalf("delivered row status=%q last_error=%q", status, lastError)
	}
	if err := st.EnqueueSystem(ctx, "will be removed"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDestination(ctx, destinationID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDestination(ctx, destinationID); err == nil {
		t.Fatal("deleting a destination twice succeeded")
	}
	active, err := st.ListDestinations(ctx)
	if err != nil || len(active) != 0 {
		t.Fatalf("deleted destination remained active: %#v err=%v", active, err)
	}
	all, err := st.ListDestinations(ctx, true)
	if err != nil || len(all) != 1 || all[0].DeletedAt == nil {
		t.Fatalf("soft-deleted destination missing: %#v err=%v", all, err)
	}
	var dead int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE status='dead' AND last_error='destination removed'").Scan(&dead); err != nil {
		t.Fatal(err)
	}
	if dead != 1 {
		t.Fatalf("pending row was not dead-lettered on removal: %d", dead)
	}
	if err := st.SetDestinationEnabled(ctx, destinationID, true); err == nil {
		t.Fatal("re-enabling a deleted destination succeeded")
	}
	if err := st.Ping(ctx); err != nil {
		t.Fatalf("store unexpectedly stopped responding: %v", err)
	}
}

func TestStoreValidationBranches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "", ServiceURL: "generic://example.invalid/path"}); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("empty destination name error=%v", err)
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "invalid", ServiceURL: "not-a-shoutrrr-url"}); err == nil {
		t.Fatal("invalid destination URL was accepted")
	}
	invalidSettings := settings()
	invalidSettings.OAuthClientID = ""
	if _, err := st.SaveSettings(ctx, invalidSettings); err == nil {
		t.Fatal("missing OAuth client was accepted")
	}
	invalidSettings = settings()
	invalidSettings.DeviceInterval = time.Second
	if _, err := st.SaveSettings(ctx, invalidSettings); err == nil {
		t.Fatal("short device interval was accepted")
	}
	invalidSettings = settings()
	invalidSettings.WebhookSecret = strings.Repeat("x", 1025)
	if _, err := st.SaveSettings(ctx, invalidSettings); err == nil {
		t.Fatal("oversized webhook secret was accepted")
	}
	if _, _, err := st.RecordWebhookTrigger(ctx, "short", nil, nil); err == nil {
		t.Fatal("short webhook hash was accepted")
	}
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("z", 64), nil, nil); err == nil {
		t.Fatal("non-hex webhook hash was accepted")
	}
	events := make([]string, 101)
	for i := range events {
		events[i] = "event-" + strconv.Itoa(i)
	}
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), events, nil); err == nil {
		t.Fatal("oversized webhook metadata was accepted")
	}
}

func TestCleanupRemovesExpiredOperationalData(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%#v err=%v", destinations, err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES('expired','expired',?,?)`, old, old); err != nil {
		t.Fatal(err)
	}
	result, err := st.db.ExecContext(ctx, `INSERT INTO event_batches(generation,observed_at,change_count,created_at,trigger_id) VALUES(1,?,?,?,1)`, old, 1, old)
	if err != nil {
		t.Fatal(err)
	}
	batchID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,1,?,'devices','changed','device-1','server','[]')`, batchID, old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO event_batch_triggers(batch_id,trigger_id) VALUES(?,1)`, batchID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO webhook_triggers(body_hash,received_at,event_types_json,collectors_json,status,next_attempt_at) VALUES(?,?,?,?,?,?)`, strings.Repeat("e", 64), old, "[]", "[]", "processed", old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO outbox(destination_id,payload,status,next_attempt,first_attempt,last_error,created_at,delivered_at) VALUES(?,?,?, ?,?,?,?,?)`, destinations[0].ID, "old", "delivered", old, old, "", old, old); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	for table := range map[string]bool{"sessions": true, "events": true, "event_batches": true, "event_batch_triggers": true, "webhook_triggers": true, "outbox": true} {
		var count int
		if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("cleanup left %d rows in %s", count, table)
		}
	}
}

func TestHistoryFormattingHelpers(t *testing.T) {
	if got := prettyJSON(nil); got != "" {
		t.Fatalf("prettyJSON(nil)=%q", got)
	}
	if got := prettyJSON([]byte(`{"name":"server"}`)); !strings.Contains(got, "\n  \"name\"") {
		t.Fatalf("prettyJSON valid=%q", got)
	}
	if got := prettyJSON([]byte("not-json")); got != "not-json" {
		t.Fatalf("prettyJSON invalid=%q", got)
	}
	fields := formatHistoryFields([]model.FieldChange{{Field: "name", Old: "old", New: nil}, {Field: "count", Old: nil, New: 2}})
	if len(fields) != 2 || !fields[0].HasOld || fields[0].HasNew || fields[1].HasOld || !fields[1].HasNew {
		t.Fatalf("formatted fields=%#v", fields)
	}
	if parseOptionalTime("") != nil || parseOptionalTime("bad") != nil || parseOptionalTime(time.Now().UTC().Format(time.RFC3339Nano)) == nil {
		t.Fatal("parseOptionalTime branches incorrect")
	}
	if truncate("short", 10) != "short" || !strings.HasSuffix(truncate(strings.Repeat("x", 11), 10), "…") {
		t.Fatal("truncate branches incorrect")
	}
}

func TestClosedStoreReturnsOperationalErrors(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	expectErr := func(name string, call func() error) {
		t.Helper()
		if err := call(); err == nil {
			t.Fatalf("%s unexpectedly succeeded on a closed store", name)
		}
	}
	expectErr("Ping", func() error { return st.Ping(ctx) })
	expectErr("AdminExists", func() error { _, err := st.AdminExists(ctx); return err })
	expectErr("NewSetupToken", func() error { _, err := st.NewSetupToken(ctx); return err })
	expectErr("Claim", func() error { return st.Claim(ctx, "token", "a secure password") })
	if st.Authenticate(ctx, "password") {
		t.Fatal("Authenticate succeeded on a closed store")
	}
	expectErr("ResetPassword", func() error { return st.ResetPassword(ctx, "a secure password") })
	expectErr("NewResetToken", func() error { _, err := st.NewResetToken(ctx); return err })
	expectErr("ResetWithToken", func() error { return st.ResetWithToken(ctx, "token", "a secure password") })
	if _, _, err := st.CreateSession(ctx); err == nil {
		t.Fatal("CreateSession unexpectedly succeeded on a closed store")
	}
	if st.ValidateSession(ctx, "token", "csrf", true) {
		t.Fatal("ValidateSession succeeded on a closed store")
	}
	validSettings := settings()
	expectErr("SaveSettings", func() error { _, err := st.SaveSettings(ctx, validSettings); return err })
	expectErr("Settings", func() error { _, err := st.Settings(ctx); return err })
	expectErr("WebhookSecret", func() error { _, err := st.WebhookSecret(ctx); return err })
	expectErr("RecordWebhookTrigger", func() error { _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), nil, nil); return err })
	expectErr("ClaimWebhookTriggers", func() error { _, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute); return err })
	expectErr("CompleteWebhookTriggers", func() error { return st.CompleteWebhookTriggers(ctx, []int64{1}) })
	expectErr("RetryWebhookTriggers", func() error { return st.RetryWebhookTriggers(ctx, []int64{1}, time.Now(), "error") })
	expectErr("MarkWebhookTriggerProcessed", func() error { return st.MarkWebhookTriggerProcessed(ctx, 1) })
	expectErr("ListDestinations", func() error { _, err := st.ListDestinations(ctx); return err })
	expectErr("SaveDestination", func() error {
		_, err := st.SaveDestination(ctx, NotificationDestination{Name: "test", ServiceURL: "generic://example.invalid"})
		return err
	})
	expectErr("SetDestinationEnabled", func() error { return st.SetDestinationEnabled(ctx, 1, true) })
	expectErr("DeleteDestination", func() error { return st.DeleteDestination(ctx, 1) })
	expectErr("TrackAppVersion", func() error {
		_, err := st.TrackAppVersion(ctx, "1.0.0", func(string, string) string { return "update" })
		return err
	})
	expectErr("ApplyBatch", func() error {
		_, err := st.ApplyBatch(ctx, 1, nil, func([]model.Change) string { return "" })
		return err
	})
	expectErr("ApplyBatchWithBatch", func() error {
		_, err := st.ApplyBatchWithBatch(ctx, 1, nil, func([]model.Change) string { return "" })
		return err
	})
	expectErr("RecordCollectorFailure", func() error { _, _, err := st.RecordCollectorFailure(ctx, 1, "devices", "error"); return err })
	if st.CollectorWasUnhealthy(ctx, 1, "devices") {
		t.Fatal("CollectorWasUnhealthy succeeded on a closed store")
	}
	expectErr("EnqueueSystem", func() error { return st.EnqueueSystem(ctx, "payload") })
	expectErr("DueOutbox", func() error { _, err := st.DueOutbox(ctx, 1); return err })
	expectErr("Delivered", func() error { return st.Delivered(ctx, 1) })
	expectErr("Retry", func() error { return st.Retry(ctx, 1, time.Now(), "error", false) })
	expectErr("Status", func() error { _, err := st.Status(ctx); return err })
	expectErr("Cleanup", func() error { return st.Cleanup(ctx, time.Hour) })
	expectErr("ListHistory", func() error { _, err := st.ListHistory(ctx, HistoryFilter{}); return err })
	expectErr("ExportEvidencePack", func() error { _, err := st.ExportEvidencePack(ctx, HistoryFilter{}); return err })
}

func TestStoreSchemaErrorPaths(t *testing.T) {
	ctx := context.Background()
	dropAndExpect := func(t *testing.T, table string, call func(*Store) error) {
		t.Helper()
		st := testStore(t)
		if _, err := st.db.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
		if err := call(st); err == nil {
			t.Fatalf("operation succeeded after dropping %s", table)
		}
	}
	dropAndExpect(t, "admin", func(st *Store) error { _, err := st.AdminExists(ctx); return err })
	dropAndExpect(t, "meta", func(st *Store) error { _, err := st.NewSetupToken(ctx); return err })
	dropAndExpect(t, "settings", func(st *Store) error { _, err := st.Settings(ctx); return err })
	dropAndExpect(t, "settings", func(st *Store) error { _, err := st.WebhookSecret(ctx); return err })
	dropAndExpect(t, "webhook_triggers", func(st *Store) error {
		_, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), nil, nil)
		return err
	})
	dropAndExpect(t, "webhook_triggers", func(st *Store) error { _, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute); return err })
	dropAndExpect(t, "notification_destinations", func(st *Store) error { _, err := st.ListDestinations(ctx); return err })
	dropAndExpect(t, "outbox", func(st *Store) error { _, err := st.DueOutbox(ctx, 1); return err })
	dropAndExpect(t, "settings", func(st *Store) error { _, err := st.Status(ctx); return err })
	dropAndExpect(t, "event_batches", func(st *Store) error { _, err := st.ListHistory(ctx, HistoryFilter{}); return err })
}

func TestSetupAndWebhookConfigurationErrors(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	withoutDestination := settings()
	withoutDestination.MattermostURL = ""
	if _, err := st.SaveSettings(ctx, withoutDestination); err == nil || !strings.Contains(err.Error(), "enabled notification destination") {
		t.Fatalf("initial setup without destination error=%v", err)
	}
	invalidURL := settings()
	invalidURL.MattermostURL = "ftp://mattermost.example/hooks/token"
	if _, err := st.SaveSettings(ctx, invalidURL); err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("invalid legacy URL error=%v", err)
	}
	if _, err := st.WebhookSecret(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unconfigured webhook secret error=%v", err)
	}
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, "invalid", "a secure password"); err == nil {
		t.Fatal("invalid setup token was accepted")
	}
	if err := st.Claim(ctx, setup, "short"); err == nil {
		t.Fatal("short setup password was accepted")
	}
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if value, err := st.WebhookSecret(ctx); err != nil || value != "" {
		t.Fatalf("empty webhook secret=%q err=%v", value, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE settings SET webhook_secret_enc='invalid-envelope'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.WebhookSecret(ctx); err == nil {
		t.Fatal("malformed webhook secret was accepted")
	}
}

func TestDestinationUpdatesAndTriggerLeaseBranches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%#v err=%v", destinations, err)
	}
	destination := destinations[0]
	updated, err := st.SaveDestination(ctx, NotificationDestination{ID: destination.ID, Name: "renamed", ServiceURL: destination.ServiceURL, Enabled: true})
	if err != nil || updated != destination.ID {
		t.Fatalf("destination update id=%d err=%v", updated, err)
	}
	if err := st.SetDestinationEnabled(ctx, destination.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDestinationEnabled(ctx, destination.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDestinationEnabled(ctx, 99999, true); err == nil {
		t.Fatal("unknown destination was enabled")
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{ID: 99999, Name: "missing", ServiceURL: destination.ServiceURL, Enabled: true}); err == nil {
		t.Fatal("unknown destination was updated")
	}

	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), []string{"policyUpdate"}, []string{"policy"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	claimed, err := st.ClaimWebhookTriggers(ctx, 0, 0)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("default trigger claim=%#v err=%v", claimed, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET lease_until=? WHERE id=?", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), trigger.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err = st.ClaimWebhookTriggers(ctx, 1000, time.Nanosecond)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 2 {
		t.Fatalf("expired lease claim=%#v err=%v", claimed, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET event_types_json='invalid-json' WHERE id=?", trigger.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil); err == nil || !strings.Contains(err.Error(), "decode webhook event metadata") {
		t.Fatalf("invalid trigger metadata error=%v", err)
	}
}

func TestStatusQueryErrorBranches(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"snapshots", "collector_state", "outbox", "notification_destinations", "webhook_triggers"} {
		t.Run(table, func(t *testing.T) {
			st := testStore(t)
			if _, err := st.SaveSettings(ctx, settings()); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Status(ctx); err == nil {
				t.Fatalf("Status succeeded after dropping %s", table)
			}
		})
	}
}

func TestCleanupQueryErrorBranches(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"sessions", "events", "event_batches", "event_batch_triggers", "evidence_ledger", "webhook_triggers", "outbox"} {
		t.Run(table, func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
				t.Fatal(err)
			}
			if err := st.Cleanup(ctx, time.Hour); err == nil {
				t.Fatalf("Cleanup succeeded after dropping %s", table)
			}
		})
	}
}

func TestDestinationMutationQueryErrorBranches(t *testing.T) {
	ctx := context.Background()
	newDestination := func(t *testing.T, st *Store) int64 {
		t.Helper()
		id, err := st.SaveDestination(ctx, NotificationDestination{Name: "test", ServiceURL: "generic://example.invalid/path", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	t.Run("save destination table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "test", ServiceURL: "generic://example.invalid/path", Enabled: true}); err == nil {
			t.Fatal("SaveDestination succeeded without its table")
		}
	})

	t.Run("save disabled outbox", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE outbox"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "test", ServiceURL: "generic://example.invalid/path"}); err == nil {
			t.Fatal("SaveDestination succeeded without outbox")
		}
	})

	t.Run("enable destination table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		if err := st.SetDestinationEnabled(ctx, 1, true); err == nil {
			t.Fatal("SetDestinationEnabled succeeded without its table")
		}
	})

	t.Run("disable destination outbox", func(t *testing.T) {
		st := testStore(t)
		id := newDestination(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE outbox"); err != nil {
			t.Fatal(err)
		}
		if err := st.SetDestinationEnabled(ctx, id, false); err == nil {
			t.Fatal("SetDestinationEnabled succeeded without outbox")
		}
	})

	t.Run("delete destination table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteDestination(ctx, 1); err == nil {
			t.Fatal("DeleteDestination succeeded without its table")
		}
	})

	t.Run("delete destination outbox", func(t *testing.T) {
		st := testStore(t)
		id := newDestination(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE outbox"); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteDestination(ctx, id); err == nil {
			t.Fatal("DeleteDestination succeeded without outbox")
		}
	})
}

func TestTrackAppVersionQueryErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("meta table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE meta"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.0.0", nil); err == nil {
			t.Fatal("TrackAppVersion succeeded without meta")
		}
	})

	newVersionStore := func(t *testing.T) *Store {
		t.Helper()
		st := testStore(t)
		if _, err := st.SaveSettings(ctx, settings()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.0.0", nil); err != nil {
			t.Fatal(err)
		}
		return st
	}
	t.Run("settings query", func(t *testing.T) {
		st := newVersionStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.1.0", nil); err == nil {
			t.Fatal("TrackAppVersion succeeded without settings")
		}
	})
	t.Run("destination query", func(t *testing.T) {
		st := newVersionStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.1.0", nil); err == nil {
			t.Fatal("TrackAppVersion succeeded without destinations")
		}
	})
	t.Run("outbox query", func(t *testing.T) {
		st := newVersionStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE outbox"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.1.0", func(string, string) string { return "version changed" }); err == nil {
			t.Fatal("TrackAppVersion succeeded without outbox")
		}
	})
}

func TestWebhookTriggerCollectorMetadataError(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	bodyHash := strings.Repeat("a", 64)
	if _, _, err := st.RecordWebhookTrigger(ctx, bodyHash, []string{"policyUpdate"}, []string{"policy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET collectors_json='invalid-json' WHERE body_hash=?", bodyHash); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordWebhookTrigger(ctx, bodyHash, nil, nil); err == nil || !strings.Contains(err.Error(), "decode webhook collector metadata") {
		t.Fatalf("collector metadata error=%v", err)
	}
}

func TestWebhookTriggerDurabilityErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("claim dead-letter update", func(t *testing.T) {
		st := testStore(t)
		bodyHash := strings.Repeat("b", 64)
		if _, _, err := st.RecordWebhookTrigger(ctx, bodyHash, nil, nil); err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
		if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=? WHERE body_hash=?", old, bodyHash); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_webhook_dead BEFORE UPDATE OF status ON webhook_triggers WHEN NEW.status='dead' BEGIN SELECT RAISE(ABORT,'dead-letter update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute); err == nil {
			t.Fatal("ClaimWebhookTriggers ignored dead-letter update failure")
		}
	})

	t.Run("claim malformed metadata", func(t *testing.T) {
		st := testStore(t)
		bodyHash := strings.Repeat("c", 64)
		if _, _, err := st.RecordWebhookTrigger(ctx, bodyHash, []string{"policyUpdate"}, []string{"policy"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET event_types_json='invalid-json' WHERE body_hash=?", bodyHash); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute); err == nil || !strings.Contains(err.Error(), "decode webhook event metadata") {
			t.Fatalf("malformed claim metadata error=%v", err)
		}
	})

	t.Run("claim processing update", func(t *testing.T) {
		st := testStore(t)
		if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_webhook_processing BEFORE UPDATE OF status ON webhook_triggers WHEN NEW.status='processing' BEGIN SELECT RAISE(ABORT,'processing update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute); err == nil {
			t.Fatal("ClaimWebhookTriggers ignored processing update failure")
		}
	})

	t.Run("complete update", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE webhook_triggers"); err != nil {
			t.Fatal(err)
		}
		if err := st.CompleteWebhookTriggers(ctx, []int64{1}); err == nil {
			t.Fatal("CompleteWebhookTriggers succeeded without its table")
		}
	})

	t.Run("retry unknown trigger", func(t *testing.T) {
		st := testStore(t)
		if err := st.RetryWebhookTriggers(ctx, []int64{99999}, time.Now(), ""); err != nil {
			t.Fatalf("unknown trigger retry error=%v", err)
		}
	})

	t.Run("retry query failure", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE webhook_triggers"); err != nil {
			t.Fatal(err)
		}
		if err := st.RetryWebhookTriggers(ctx, []int64{1}, time.Now(), "retry"); err == nil {
			t.Fatal("RetryWebhookTriggers succeeded without its table")
		}
	})

	t.Run("retry dead default message", func(t *testing.T) {
		st := testStore(t)
		bodyHash := strings.Repeat("e", 64)
		trigger, _, err := st.RecordWebhookTrigger(ctx, bodyHash, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
		if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=? WHERE id=?", old, trigger.ID); err != nil {
			t.Fatal(err)
		}
		if err := st.RetryWebhookTriggers(ctx, []int64{trigger.ID}, time.Now(), ""); err != nil {
			t.Fatal(err)
		}
		dead, _, err := st.RecordWebhookTrigger(ctx, bodyHash, nil, nil)
		if err != nil || dead.Status != "dead" || dead.LastError == "" {
			t.Fatalf("dead trigger=%#v err=%v", dead, err)
		}
	})

	t.Run("retry update failure", func(t *testing.T) {
		st := testStore(t)
		trigger, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_webhook_retry BEFORE UPDATE OF status ON webhook_triggers BEGIN SELECT RAISE(ABORT,'retry update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.RetryWebhookTriggers(ctx, []int64{trigger.ID}, time.Now(), "retry"); err == nil {
			t.Fatal("RetryWebhookTriggers ignored update failure")
		}
	})
}

func storeWithHistoryBatch(t *testing.T) (*Store, int64) {
	t.Helper()
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"},
	}}}}
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server-new", Data: map[string]any{"hostname": "server-new"},
	}}}}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, changed, func([]model.Change) string { return "changed" })
	if err != nil {
		t.Fatal(err)
	}
	if batch.ID == 0 {
		t.Fatal("changed batch did not create history")
	}
	return st, batch.ID
}

func TestHistoryLoaderQueryErrorBranches(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"event_batch_triggers", "evidence_ledger", "events", "outbox"} {
		t.Run(table, func(t *testing.T) {
			st, _ := storeWithHistoryBatch(t)
			if _, err := st.db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
				t.Fatal(err)
			}
			if _, err := st.ListHistory(ctx, HistoryFilter{}); err == nil {
				t.Fatalf("ListHistory succeeded after dropping %s", table)
			}
		})
	}

	t.Run("malformed fields", func(t *testing.T) {
		st, batchID := storeWithHistoryBatch(t)
		if _, err := st.db.ExecContext(ctx, "UPDATE events SET changes_json='invalid-json' WHERE batch_id=?", batchID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListHistory(ctx, HistoryFilter{}); err == nil || !strings.Contains(err.Error(), "decode history fields") {
			t.Fatalf("malformed history fields error=%v", err)
		}
	})
}

func TestSettingsEncryptionErrorBranches(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "oauth secret", field: "oauth_secret_enc", value: "invalid-envelope"},
		{name: "mattermost URL", field: "mattermost_url_enc", value: "invalid-envelope"},
		{name: "webhook secret", field: "webhook_secret_enc", value: "invalid-envelope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := testStore(t)
			input := settings()
			input.WebhookSecret = "webhook-secret"
			if _, err := st.SaveSettings(ctx, input); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, "UPDATE settings SET "+tt.field+"=?", tt.value); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Settings(ctx); err == nil {
				t.Fatalf("Settings accepted a corrupt %s", tt.name)
			}
		})
	}

	t.Run("save existing secret", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.SaveSettings(ctx, settings()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "UPDATE settings SET oauth_secret_enc='invalid-envelope'"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveSettings(ctx, settings()); err == nil {
			t.Fatal("SaveSettings accepted a corrupt existing secret")
		}
	})

	t.Run("missing settings table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveSettings(ctx, settings()); err == nil {
			t.Fatal("SaveSettings succeeded without settings table")
		}
	})

	for _, table := range []string{"snapshots", "collector_state"} {
		t.Run("generation cleanup "+table, func(t *testing.T) {
			st := testStore(t)
			if _, err := st.SaveSettings(ctx, settings()); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
				t.Fatal(err)
			}
			changed := settings()
			changed.OAuthClientID = "changed-client"
			if _, err := st.SaveSettings(ctx, changed); err == nil {
				t.Fatalf("SaveSettings succeeded after dropping %s", table)
			}
		})
	}
}

func setupCoverageAdmin(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	token, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, token, "a secure password"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationTransactionErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("new setup token meta table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE meta"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.NewSetupToken(ctx); err == nil {
			t.Fatal("NewSetupToken succeeded without meta")
		}
	})

	t.Run("reset password admin table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE admin"); err != nil {
			t.Fatal(err)
		}
		if err := st.ResetPassword(ctx, "a secure password"); err == nil {
			t.Fatal("ResetPassword succeeded without admin")
		}
	})

	t.Run("reset password sessions table", func(t *testing.T) {
		st := testStore(t)
		setupCoverageAdmin(t, st)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE sessions"); err != nil {
			t.Fatal(err)
		}
		if err := st.ResetPassword(ctx, "new secure password"); err == nil {
			t.Fatal("ResetPassword succeeded without sessions")
		}
	})

	t.Run("reset with token admin table", func(t *testing.T) {
		st := testStore(t)
		setupCoverageAdmin(t, st)
		token, err := st.NewResetToken(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "DROP TABLE admin"); err != nil {
			t.Fatal(err)
		}
		if err := st.ResetWithToken(ctx, token, "new secure password"); err == nil {
			t.Fatal("ResetWithToken succeeded without admin")
		}
	})

	t.Run("reset with token sessions table", func(t *testing.T) {
		st := testStore(t)
		setupCoverageAdmin(t, st)
		token, err := st.NewResetToken(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "DROP TABLE sessions"); err != nil {
			t.Fatal(err)
		}
		if err := st.ResetWithToken(ctx, token, "new secure password"); err == nil {
			t.Fatal("ResetWithToken succeeded without sessions")
		}
	})

	t.Run("reset token delete trigger", func(t *testing.T) {
		st := testStore(t)
		setupCoverageAdmin(t, st)
		token, err := st.NewResetToken(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_reset_token_delete BEFORE DELETE ON meta WHEN OLD.key='reset_token_hash' BEGIN SELECT RAISE(ABORT,'reset token delete failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.ResetWithToken(ctx, token, "new secure password"); err == nil {
			t.Fatal("ResetWithToken ignored the meta delete failure")
		}
	})

	t.Run("create session table", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE sessions"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.CreateSession(ctx); err == nil {
			t.Fatal("CreateSession succeeded without sessions")
		}
	})

	t.Run("invalid csrf", func(t *testing.T) {
		st := testStore(t)
		token, csrf, err := st.CreateSession(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.ValidateSession(ctx, token, "wrong", true) {
			t.Fatal("ValidateSession accepted an invalid CSRF token")
		}
		if !st.ValidateSession(ctx, token, csrf, false) {
			t.Fatal("ValidateSession rejected a session without CSRF enforcement")
		}
	})
}

func configuredCoverageStore(t *testing.T) (*Store, int64) {
	t.Helper()
	st := testStore(t)
	generation, err := st.SaveSettings(context.Background(), settings())
	if err != nil {
		t.Fatal(err)
	}
	return st, generation
}

func TestApplyBatchTransactionErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("settings query", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatchWithBatch(ctx, 1, nil, func([]model.Change) string { return "digest" }); err == nil {
			t.Fatal("ApplyBatchWithBatch succeeded without settings")
		}
	})

	t.Run("unsupported collector state", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_unsupported_collector BEFORE INSERT ON collector_state WHEN NEW.supported=0 BEGIN SELECT RAISE(ABORT,'unsupported collector state failed'); END`); err != nil {
			t.Fatal(err)
		}
		unsupported := []model.Collected{{Collector: "log_streaming", Unsupported: true}}
		if _, err := st.ApplyBatchWithBatch(ctx, generation, unsupported, func([]model.Change) string { return "digest" }); err == nil {
			t.Fatal("unsupported collector state write unexpectedly succeeded")
		}
	})

	t.Run("canonicalization error", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		bad := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "bad", Type: "device", Name: "bad", Data: map[string]any{"hostname": make(chan int)}}}}}
		if _, err := st.ApplyBatchWithBatch(ctx, generation, bad, func([]model.Change) string { return "digest" }); err == nil {
			t.Fatal("unsupported resource data was accepted")
		}
	})

	t.Run("snapshots query", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE snapshots"); err != nil {
			t.Fatal(err)
		}
		empty := []model.Collected{{Collector: "devices"}}
		if _, err := st.ApplyBatchWithBatch(ctx, generation, empty, func([]model.Change) string { return "digest" }); err == nil {
			t.Fatal("ApplyBatchWithBatch succeeded without snapshots")
		}
	})

	tests := []struct {
		name  string
		table string
		want  string
	}{
		{name: "event batch insert", table: "event_batches", want: "event batch insert failed"},
		{name: "outbox insert", table: "outbox", want: "outbox insert failed"},
		{name: "evidence ledger", table: "evidence_ledger", want: "evidence ledger"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, generation := configuredCoverageStore(t)
			if tt.table == "event_batches" {
				if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_event_batch BEFORE INSERT ON event_batches BEGIN SELECT RAISE(ABORT,'event batch insert failed'); END`); err != nil {
					t.Fatal(err)
				}
			} else if _, err := st.db.ExecContext(ctx, "DROP TABLE "+tt.table); err != nil {
				t.Fatal(err)
			}
			baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
			if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil && tt.table != "evidence_ledger" {
				// The event batch and outbox cases should fail only on the changed write;
				// the evidence-ledger case also fails during the baseline backfill.
				t.Fatal(err)
			}
			changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "changed", Data: map[string]any{"hostname": "changed"}}}}}
			if _, err := st.ApplyBatchWithBatch(ctx, generation, changed, func([]model.Change) string { return "changed" }); err == nil {
				t.Fatalf("ApplyBatchWithBatch succeeded with broken %s", tt.table)
			}
		})
	}
}

func TestDestinationDecryptionErrorBranches(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc='invalid-envelope'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListDestinations(ctx); err == nil {
		t.Fatal("ListDestinations accepted a corrupt encrypted URL")
	}
	if _, err := st.DueOutbox(ctx, 10); err == nil {
		t.Fatal("DueOutbox accepted a corrupt encrypted URL")
	}
}

func TestDestinationAndVersionWriteErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("destination insert trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_destination_insert BEFORE INSERT ON notification_destinations BEGIN SELECT RAISE(ABORT,'destination insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "test", ServiceURL: "generic://example.invalid/path", Enabled: true}); err == nil {
			t.Fatal("SaveDestination ignored destination insert failure")
		}
	})

	t.Run("destination update trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.SaveSettings(ctx, settings()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_destination_update BEFORE UPDATE OF service_url_enc ON notification_destinations BEGIN SELECT RAISE(ABORT,'destination update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "renamed", ServiceURL: "generic://example.invalid/updated", Enabled: true}); err == nil {
			t.Fatal("SaveDestination ignored destination update failure")
		}
	})

	t.Run("set enabled update trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.SaveSettings(ctx, settings()); err != nil {
			t.Fatal(err)
		}
		id := int64(1)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_destination_enabled BEFORE UPDATE OF enabled ON notification_destinations BEGIN SELECT RAISE(ABORT,'destination enabled update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.SetDestinationEnabled(ctx, id, false); err == nil {
			t.Fatal("SetDestinationEnabled ignored destination update failure")
		}
	})

	t.Run("delete update trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.SaveSettings(ctx, settings()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_destination_delete BEFORE UPDATE OF deleted_at ON notification_destinations BEGIN SELECT RAISE(ABORT,'destination delete update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteDestination(ctx, 1); err == nil {
			t.Fatal("DeleteDestination ignored destination update failure")
		}
	})

	t.Run("track version insert trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_app_version_insert BEFORE INSERT ON meta WHEN NEW.key='app_version' BEGIN SELECT RAISE(ABORT,'app version insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.0.0", nil); err == nil {
			t.Fatal("TrackAppVersion ignored insert failure")
		}
	})

	t.Run("track version update trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.TrackAppVersion(ctx, "1.0.0", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_app_version_update BEFORE UPDATE OF value ON meta WHEN OLD.key='app_version' BEGIN SELECT RAISE(ABORT,'app version update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrackAppVersion(ctx, "1.1.0", nil); err == nil {
			t.Fatal("TrackAppVersion ignored update failure")
		}
	})

	t.Run("settings insert trigger", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_settings_insert BEFORE INSERT ON settings BEGIN SELECT RAISE(ABORT,'settings insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveSettings(ctx, settings()); err == nil {
			t.Fatal("SaveSettings ignored settings insert failure")
		}
	})

	t.Run("collector due query failure", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE collector_state"); err != nil {
			t.Fatal(err)
		}
		if !st.CollectorDue(ctx, 1, "devices") {
			t.Fatal("CollectorDue did not treat a query failure as due")
		}
	})

	t.Run("blank tailnet normalization", func(t *testing.T) {
		st := testStore(t)
		input := settings()
		input.Tailnet = "   "
		if _, err := st.SaveSettings(ctx, input); err != nil {
			t.Fatal(err)
		}
		current, err := st.Settings(ctx)
		if err != nil || current.Tailnet != "-" {
			t.Fatalf("normalized tailnet=%q err=%v", current.Tailnet, err)
		}
	})

	t.Run("initial destination count query", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		input := settings()
		input.MattermostURL = ""
		if _, err := st.SaveSettings(ctx, input); err == nil {
			t.Fatal("SaveSettings succeeded without destination table")
		}
	})
}

func TestApplyBatchWriteErrorBranches(t *testing.T) {
	ctx := context.Background()
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "changed", Data: map[string]any{"hostname": "changed"}}}}}

	t.Run("settings baseline update", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_baseline_update BEFORE UPDATE OF baseline_at ON settings BEGIN SELECT RAISE(ABORT,'baseline update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err == nil {
			t.Fatal("ApplyBatch ignored baseline update failure")
		}
	})

	t.Run("snapshot insert", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_snapshot_insert BEFORE INSERT ON snapshots BEGIN SELECT RAISE(ABORT,'snapshot insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err == nil {
			t.Fatal("ApplyBatch ignored snapshot insert failure")
		}
	})

	t.Run("snapshot update", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_snapshot_update BEFORE UPDATE ON snapshots BEGIN SELECT RAISE(ABORT,'snapshot update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatch(ctx, generation, changed, func([]model.Change) string { return "changed" }); err == nil {
			t.Fatal("ApplyBatch ignored snapshot update failure")
		}
	})

	t.Run("snapshot delete", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatch(ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "missing" }); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_snapshot_delete BEFORE DELETE ON snapshots BEGIN SELECT RAISE(ABORT,'snapshot delete failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatch(ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "removed" }); err == nil {
			t.Fatal("ApplyBatch ignored snapshot delete failure")
		}
	})

	t.Run("collector state update", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_collector_state_update BEFORE UPDATE ON collector_state WHEN NEW.collector='devices' BEGIN SELECT RAISE(ABORT,'collector state update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplyBatch(ctx, generation, changed, func([]model.Change) string { return "changed" }); err == nil {
			t.Fatal("ApplyBatch ignored collector state update failure")
		}
	})

	for _, table := range []string{"event_batch_triggers", "events"} {
		t.Run(table+" insert", func(t *testing.T) {
			st, generation := configuredCoverageStore(t)
			if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
				t.Fatal(err)
			}
			trigger := "fail_" + table + "_insert"
			if _, err := st.db.ExecContext(ctx, "CREATE TRIGGER "+trigger+" BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'"+table+" insert failed'); END"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.ApplyBatchWithBatch(ctx, generation, changed, func([]model.Change) string { return "changed" }, 1); err == nil {
				t.Fatalf("ApplyBatch ignored %s insert failure", table)
			}
		})
	}
}

func TestAuthenticationAndOutboxBoundaryBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("claim admin insert", func(t *testing.T) {
		st := testStore(t)
		token, err := st.NewSetupToken(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_admin_insert BEFORE INSERT ON admin BEGIN SELECT RAISE(ABORT,'admin insert failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.Claim(ctx, token, "a secure password"); err == nil {
			t.Fatal("Claim ignored admin insert failure")
		}
	})

	t.Run("claim setup token delete", func(t *testing.T) {
		st := testStore(t)
		token, err := st.NewSetupToken(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_setup_token_delete BEFORE DELETE ON meta WHEN OLD.key='setup_token_hash' BEGIN SELECT RAISE(ABORT,'setup token delete failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.Claim(ctx, token, "a secure password"); err == nil {
			t.Fatal("Claim ignored setup token delete failure")
		}
	})

	t.Run("reset rows affected zero", func(t *testing.T) {
		st := testStore(t)
		setupCoverageAdmin(t, st)
		token, err := st.NewResetToken(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "DELETE FROM admin WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		if err := st.ResetWithToken(ctx, token, "new secure password"); err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("ResetWithToken rows=0 error=%v", err)
		}
	})

	t.Run("invalid session expiry", func(t *testing.T) {
		st := testStore(t)
		if _, err := st.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?)", "hash", "csrf", "not-a-time", "not-a-time"); err != nil {
			t.Fatal(err)
		}
		if st.ValidateSession(ctx, "token", "csrf", false) {
			t.Fatal("ValidateSession accepted malformed expiry")
		}
		token, csrf, err := st.CreateSession(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, "UPDATE sessions SET expires_at=? WHERE token_hash=?", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), secret.HashToken(token)); err != nil {
			t.Fatal(err)
		}
		if st.ValidateSession(ctx, token, csrf, false) {
			t.Fatal("ValidateSession accepted expired session")
		}
	})

	t.Run("collector failure update", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "first"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_collector_failure_update BEFORE UPDATE ON collector_state BEGIN SELECT RAISE(ABORT,'collector failure update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "second"); err == nil {
			t.Fatal("RecordCollectorFailure ignored update failure")
		}
	})

	t.Run("enqueue destination query", func(t *testing.T) {
		st, _ := configuredCoverageStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE notification_destinations"); err != nil {
			t.Fatal(err)
		}
		if err := st.EnqueueSystem(ctx, "payload"); err == nil {
			t.Fatal("EnqueueSystem succeeded without destinations")
		}
	})

	t.Run("delivered and retry update", func(t *testing.T) {
		st, _ := configuredCoverageStore(t)
		if err := st.EnqueueSystem(ctx, "payload"); err != nil {
			t.Fatal(err)
		}
		items, err := st.DueOutbox(ctx, 1)
		if err != nil || len(items) != 1 {
			t.Fatalf("outbox=%#v err=%v", items, err)
		}
		if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_outbox_delivered BEFORE UPDATE OF status,attempts ON outbox WHEN NEW.status IN ('delivered','pending') BEGIN SELECT RAISE(ABORT,'delivery update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := st.Delivered(ctx, items[0].ID); err == nil {
			t.Fatal("Delivered ignored update failure")
		}
		if err := st.Retry(ctx, items[0].ID, time.Now(), "retry", false); err == nil {
			t.Fatal("Retry ignored update failure")
		}
	})

	t.Run("history limit clamp", func(t *testing.T) {
		st, _ := storeWithHistoryBatch(t)
		page, err := st.ListHistory(ctx, HistoryFilter{Limit: 1000})
		if err != nil || len(page.Batches) != 1 {
			t.Fatalf("clamped history page=%#v err=%v", page, err)
		}
	})

	t.Run("empty webhook lifecycle operations", func(t *testing.T) {
		st := testStore(t)
		if err := st.CompleteWebhookTriggers(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if err := st.RetryWebhookTriggers(ctx, nil, time.Now(), ""); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("collector filter and trigger fallback", func(t *testing.T) {
		st, batchID := storeWithHistoryBatch(t)
		if _, err := st.db.ExecContext(ctx, "DELETE FROM event_batch_triggers WHERE batch_id=?", batchID); err != nil {
			t.Fatal(err)
		}
		page, err := st.ListHistory(ctx, HistoryFilter{Collector: "devices", Limit: 10})
		if err != nil || len(page.Batches) != 1 || len(page.Batches[0].TriggerIDs) != 0 {
			t.Fatalf("collector-filtered history=%#v err=%v", page, err)
		}
		if _, err := st.db.ExecContext(ctx, "UPDATE event_batches SET trigger_id=77 WHERE id=?", batchID); err != nil {
			t.Fatal(err)
		}
		page, err = st.ListHistory(ctx, HistoryFilter{Collector: "devices", Limit: 10})
		if err != nil || len(page.Batches) != 1 || len(page.Batches[0].TriggerIDs) != 1 || page.Batches[0].TriggerIDs[0] != 77 {
			t.Fatalf("trigger fallback history=%#v err=%v", page, err)
		}
	})

	t.Run("collector failure settings query", func(t *testing.T) {
		st, generation := configuredCoverageStore(t)
		if _, err := st.db.ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.RecordCollectorFailure(ctx, generation, "devices", "failure"); err == nil {
			t.Fatal("RecordCollectorFailure succeeded without settings")
		}
	})
}

func TestApplyBatchCreatesNewBaselineResourceChange(t *testing.T) {
	ctx := context.Background()
	st, generation := configuredCoverageStore(t)
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "one", Data: map[string]any{"hostname": "one"}}}}}
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	withNewResource := []model.Collected{{Collector: "devices", Resources: []model.Resource{
		{ID: "device-1", Type: "device", Name: "one", Data: map[string]any{"hostname": "one"}},
		{ID: "device-2", Type: "device", Name: "two", Data: map[string]any{"hostname": "two"}},
	}}}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, withNewResource, func([]model.Change) string { return "created" })
	if err != nil || len(batch.Changes) != 1 || batch.Changes[0].Kind != "created" {
		t.Fatalf("new resource change=%#v err=%v", batch, err)
	}
}

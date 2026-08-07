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

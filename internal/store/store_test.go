package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(filepath.Join(t.TempDir(), "tailstate.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
func settings() Settings {
	return Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}
}

func TestSetupSessionAndSettingsEncryption(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	token, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, token, "a secure password"); err != nil {
		t.Fatal(err)
	}
	if !st.Authenticate(ctx, "a secure password") {
		t.Fatal("authentication failed")
	}
	session, csrf, err := st.CreateSession(ctx)
	if err != nil || !st.ValidateSession(ctx, session, csrf, true) {
		t.Fatal("session failed")
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil || generation != 1 {
		t.Fatalf("save: %d %v", generation, err)
	}
	var enc string
	if err := st.db.QueryRow("SELECT oauth_secret_enc FROM settings").Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if enc == "secret" {
		t.Fatal("secret stored in plaintext")
	}
	changed := settings()
	changed.OAuthClientSecret = "new-secret"
	generation, err = st.SaveSettings(ctx, changed)
	if err != nil || generation != 1 {
		t.Fatalf("credential rotation unexpectedly changed generation: %d %v", generation, err)
	}
}

func TestSaveSettingsReusesUnchangedEncryptedValues(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	configured := settings()
	configured.WebhookSecret = "webhook-secret"
	if _, err := st.SaveSettings(ctx, configured); err != nil {
		t.Fatal(err)
	}
	var oauthBefore, webhookBefore, legacyBefore, destinationBefore string
	if err := st.db.QueryRowContext(ctx, "SELECT oauth_secret_enc,webhook_secret_enc,mattermost_url_enc FROM settings WHERE id=1").Scan(&oauthBefore, &webhookBefore, &legacyBefore); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE name='Mattermost' AND deleted_at IS NULL").Scan(&destinationBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, configured); err != nil {
		t.Fatal(err)
	}
	var oauthAfter, webhookAfter, legacyAfter, destinationAfter string
	if err := st.db.QueryRowContext(ctx, "SELECT oauth_secret_enc,webhook_secret_enc,mattermost_url_enc FROM settings WHERE id=1").Scan(&oauthAfter, &webhookAfter, &legacyAfter); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE name='Mattermost' AND deleted_at IS NULL").Scan(&destinationAfter); err != nil {
		t.Fatal(err)
	}
	if oauthBefore != oauthAfter || webhookBefore != webhookAfter || legacyBefore != legacyAfter || destinationBefore != destinationAfter {
		t.Fatalf("unchanged settings were re-encrypted: oauth=%t webhook=%t legacy=%t destination=%t", oauthBefore != oauthAfter, webhookBefore != webhookAfter, legacyBefore != legacyAfter, destinationBefore != destinationAfter)
	}
}

func TestResetTokenIsSingleUseAndInvalidatesSessions(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "old secure password"); err != nil {
		t.Fatal(err)
	}
	if token, err := st.NewSetupToken(ctx); err == nil || token != "" {
		t.Fatalf("setup token was issued after claim: token=%q err=%v", token, err)
	}
	session, csrf, err := st.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ValidateSession(ctx, session, csrf, true) {
		t.Fatal("session should be valid before reset")
	}
	reset, err := st.NewResetToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ResetWithToken(ctx, reset, "new secure password"); err != nil {
		t.Fatal(err)
	}
	if !st.Authenticate(ctx, "new secure password") || st.Authenticate(ctx, "old secure password") {
		t.Fatal("password was not replaced correctly")
	}
	if st.ValidateSession(ctx, session, csrf, true) {
		t.Fatal("reset did not invalidate the old session")
	}
	if err := st.ResetWithToken(ctx, reset, "another secure password"); err == nil {
		t.Fatal("reset token was reusable")
	}
}

func TestAuthTokensExpireAndPasswordResetRevokesOutstandingToken(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE auth_tokens SET expires_at=? WHERE kind='setup'", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "a secure password"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired setup token error=%v", err)
	}
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_tokens WHERE kind='setup'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired setup token remained: %d", count)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM meta WHERE key='setup_token_hash'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired legacy setup token remained: %d", count)
	}

	setup, err = st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "a secure password"); err != nil {
		t.Fatal(err)
	}
	reset, err := st.NewResetToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ResetPassword(ctx, "another secure password"); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetWithToken(ctx, reset, "third secure password"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("revoked reset token error=%v", err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM meta WHERE key='reset_token_hash'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("revoked legacy reset token remained: %d", count)
	}
}

func TestCleanupDeadLettersExpiredOutboxAndPurgesOldDeadLetters(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "retry payload"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "fresh retry"); err != nil {
		t.Fatal(err)
	}
	items, err := testDueOutbox(st, ctx, 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("outbox=%#v err=%v", items, err)
	}
	var expiredID, freshID int64
	for _, item := range items {
		switch item.Payload {
		case "retry payload":
			expiredID = item.ID
		case "fresh retry":
			freshID = item.ID
		}
	}
	if expiredID == 0 || freshID == 0 {
		t.Fatalf("outbox IDs were not found: %#v", items)
	}
	oldAttempt := time.Now().UTC().Add(-outboxRetryWindow - time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET first_attempt=?,last_error='' WHERE id=?", oldAttempt, expiredID); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error FROM outbox WHERE id=?", expiredID).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || lastError != "delivery retry window expired" {
		t.Fatalf("expired outbox status=%q error=%q", status, lastError)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status FROM outbox WHERE id=?", freshID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("recent outbox status=%q, want pending", status)
	}
	oldCreated := time.Now().UTC().Add(-31 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET created_at=? WHERE id=?", oldCreated, expiredID); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE id=?", expiredID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("old dead-letter row remained: %d", count)
	}
}

func TestCleanupDeadLettersExpiredWebhookTriggersWithoutDeletingActiveLease(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	first, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record pending trigger: %#v created=%v err=%v", first, created, err)
	}
	second, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record processing trigger: %#v created=%v err=%v", second, created, err)
	}
	oldReceived := time.Now().UTC().Add(-webhookTriggerRetryWindow - time.Hour).Format(time.RFC3339Nano)
	activeLease := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=? WHERE id=?", oldReceived, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=?,status='processing',lease_until=?,lease_token='active-lease' WHERE id=?", oldReceived, activeLease, second.ID); err != nil {
		t.Fatal(err)
	}

	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var status, lastError, leaseToken string
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error,lease_token FROM webhook_triggers WHERE id=?", first.ID).Scan(&status, &lastError, &leaseToken); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || lastError != "reconciliation retry window expired" || leaseToken != "" {
		t.Fatalf("expired pending trigger status=%q error=%q lease=%q", status, lastError, leaseToken)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status,lease_token FROM webhook_triggers WHERE id=?", second.ID).Scan(&status, &leaseToken); err != nil {
		t.Fatal(err)
	}
	if status != "processing" || leaseToken != "active-lease" {
		t.Fatalf("active webhook lease was changed during cleanup: status=%q lease=%q", status, leaseToken)
	}

	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET lease_until=? WHERE id=?", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), second.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error,lease_token FROM webhook_triggers WHERE id=?", second.ID).Scan(&status, &lastError, &leaseToken); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || lastError != "reconciliation retry window expired" || leaseToken != "" {
		t.Fatalf("expired processing trigger status=%q error=%q lease=%q", status, lastError, leaseToken)
	}
}

func TestWrongMasterKeyFailsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	firstKey := make([]byte, 32)
	firstKey[0] = 1
	firstBox, _ := secret.NewBox(firstKey)
	st, err := Open(path, firstBox)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	otherBox, _ := secret.NewBox(make([]byte, 32))
	if _, err := Open(path, otherBox); err == nil {
		t.Fatal("database opened with wrong master key")
	}
}

func TestNewerSchemaVersionFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE schema_version SET version=?", currentSchemaVersion+1); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, box); err == nil {
		t.Fatal("database with a newer schema version was accepted")
	}
}

func TestWebhookSecretIsEncryptedAndTriggerBodiesAreDeduplicated(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	settings := settings()
	settings.WebhookSecret = "webhook-secret"
	if _, err := st.SaveSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	var encrypted string
	if err := st.db.QueryRowContext(ctx, "SELECT webhook_secret_enc FROM settings").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "" || strings.Contains(encrypted, settings.WebhookSecret) {
		t.Fatalf("webhook secret was not encrypted: %q", encrypted)
	}
	loaded, err := st.WebhookSecret(ctx)
	if err != nil || loaded != settings.WebhookSecret {
		t.Fatalf("webhook secret round trip failed: %q %v", loaded, err)
	}
	first, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), []string{"policyUpdate"}, []string{"policy"})
	if err != nil || !created || first.ID == 0 {
		t.Fatalf("record first trigger: %#v created=%v err=%v", first, created, err)
	}
	second, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), []string{"different"}, nil)
	if err != nil || created || second.ID != first.ID || len(second.EventTypes) != 1 || second.EventTypes[0] != "policyUpdate" {
		t.Fatalf("deduplication failed: %#v created=%v err=%v", second, created, err)
	}
	if err := testCompleteWebhookTriggers(st, ctx, []int64{first.ID}); err != nil {
		t.Fatal(err)
	}
	processed, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("a", 64), nil, nil)
	if err != nil || processed.Status != "processed" || processed.ProcessedAt == nil {
		t.Fatalf("processed trigger was not retained: %#v err=%v", processed, err)
	}
}

func TestWebhookTriggersAreDurableAndRetryable(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	first, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), []string{"policyUpdate"}, []string{"policy"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", first, created, err)
	}
	if first.Status != "pending" || first.Attempts != 0 || first.NextAttempt.IsZero() {
		t.Fatalf("trigger was not queued durably: %#v", first)
	}
	claimed, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim trigger: %#v err=%v", claimed, err)
	}
	if claimed[0].Status != "processing" || claimed[0].Attempts != 1 || claimed[0].LeaseUntil == nil {
		t.Fatalf("trigger was not leased: %#v", claimed[0])
	}
	if err := testRetryWebhookTriggers(st, ctx, []int64{first.ID}, time.Now().UTC().Add(time.Hour), "temporary collector failure"); err != nil {
		t.Fatal(err)
	}
	if retry, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), nil, nil); err != nil || retry.Status != "pending" || retry.Attempts != 1 {
		t.Fatalf("retry state was not persisted: %#v err=%v", retry, err)
	}
	if due, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute); err != nil || len(due) != 0 {
		t.Fatalf("future retry was claimed early: %#v err=%v", due, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET next_attempt_at=? WHERE id=?", time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), first.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err = st.ClaimWebhookTriggers(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 2 {
		t.Fatalf("retry was not reclaimed: %#v err=%v", claimed, err)
	}
	if err := testCompleteWebhookTriggers(st, ctx, []int64{first.ID}); err != nil {
		t.Fatal(err)
	}
	processed, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), nil, nil)
	if err != nil || processed.Status != "processed" || processed.ProcessedAt == nil {
		t.Fatalf("completed trigger was not retained: %#v err=%v", processed, err)
	}

	dead, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record dead-letter candidate: %#v created=%v err=%v", dead, created, err)
	}
	old := time.Now().UTC().Add(-webhookTriggerRetryWindow - time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=?,next_attempt_at=? WHERE id=?", old, old, dead.ID); err != nil {
		t.Fatal(err)
	}
	if err := testRetryWebhookTriggers(st, ctx, []int64{dead.ID}, time.Now().UTC(), "collector reconciliation failed"); err != nil {
		t.Fatal(err)
	}
	deadState, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), nil, nil)
	if err != nil || deadState.Status != "dead" || deadState.LastError != "collector reconciliation failed" {
		t.Fatalf("expired trigger was not dead-lettered: %#v err=%v", deadState, err)
	}
}

func TestWebhookClaimLeaseFencingAndExpiredRetry(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("8", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	first, claimed, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute)
	if err != nil || !claimed || first.LeaseToken == "" {
		t.Fatalf("first claim: %#v claimed=%v err=%v", first, claimed, err)
	}
	if err := st.CompleteClaimedWebhookTriggers(ctx, []WebhookTrigger{{ID: first.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryClaimedWebhookTriggers(ctx, []WebhookTrigger{{ID: first.ID}}, time.Now().UTC(), "collector reconciliation failed"); err != nil {
		t.Fatal(err)
	}
	if err := testRetryWebhookTriggers(st, ctx, []int64{first.ID}, time.Now().UTC(), "reconciliation retry window expired"); err != nil {
		t.Fatal(err)
	}
	second, claimed, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute)
	if err != nil || !claimed || second.LeaseToken == first.LeaseToken {
		t.Fatalf("second claim did not rotate the lease: %#v claimed=%v err=%v", second, claimed, err)
	}
	if err := st.CompleteClaimedWebhookTriggers(ctx, []WebhookTrigger{first}); err != nil {
		t.Fatal(err)
	}
	current, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("8", 64), nil, nil)
	if err != nil || current.Status != "processing" || current.LeaseToken != second.LeaseToken {
		t.Fatalf("stale completion changed current claim: %#v err=%v", current, err)
	}
	if err := st.CompleteClaimedWebhookTriggers(ctx, []WebhookTrigger{second, second}); err != nil {
		t.Fatal(err)
	}
	current, _, err = st.RecordWebhookTrigger(ctx, strings.Repeat("8", 64), nil, nil)
	if err != nil || current.Status != "processed" {
		t.Fatalf("current completion failed: %#v err=%v", current, err)
	}

	dead, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("9", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record expired trigger: %#v created=%v err=%v", dead, created, err)
	}
	deadClaim, claimed, err := st.ClaimWebhookTrigger(ctx, dead.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim expired trigger: %#v claimed=%v err=%v", deadClaim, claimed, err)
	}
	old := time.Now().UTC().Add(-webhookTriggerRetryWindow - time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=? WHERE id=?", old, dead.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryClaimedWebhookTriggers(ctx, []WebhookTrigger{deadClaim}, time.Now().UTC(), "collector reconciliation failed"); err != nil {
		t.Fatal(err)
	}
	deadState, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("9", 64), nil, nil)
	if err != nil || deadState.Status != "dead" || deadState.LeaseToken != "" {
		t.Fatalf("expired claim was not dead-lettered: %#v err=%v", deadState, err)
	}
}

func TestOutboxClaimLeaseFencingAndExpiredRetry(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if claims, err := st.ClaimDueOutbox(ctx, 0); err != nil || len(claims) != 0 {
		t.Fatalf("empty default outbox claim: %#v err=%v", claims, err)
	}
	if claims, err := st.ClaimDueOutbox(ctx, 100); err != nil || len(claims) != 0 {
		t.Fatalf("empty bounded outbox claim: %#v err=%v", claims, err)
	}
	if err := st.DeliveredClaimed(ctx, OutboxItem{}); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryClaimed(ctx, OutboxItem{}, time.Now(), "ignored", false); err != nil {
		t.Fatal(err)
	}
	if renewed, err := st.RenewClaimed(ctx, OutboxItem{}); err != nil || renewed {
		t.Fatalf("invalid outbox lease was renewed: renewed=%v err=%v", renewed, err)
	}
	if err := st.EnqueueSystem(ctx, "lease-fenced delivery"); err != nil {
		t.Fatal(err)
	}
	firstClaims, err := st.ClaimDueOutbox(ctx, 10, time.Minute)
	if err != nil || len(firstClaims) != 1 || firstClaims[0].LeaseToken == "" {
		t.Fatalf("first outbox claim: %#v err=%v", firstClaims, err)
	}
	statusSnapshot, err := st.Status(ctx)
	if err != nil || statusSnapshot.Pending != 0 || statusSnapshot.Processing != 1 {
		t.Fatalf("processing outbox state was not visible: %#v err=%v", statusSnapshot, err)
	}
	initialLease := firstClaims[0].LeaseUntil
	renewed, err := st.RenewClaimed(ctx, firstClaims[0], 2*time.Minute)
	if err != nil || !renewed {
		t.Fatalf("active outbox lease was not renewed: renewed=%v err=%v", renewed, err)
	}
	var renewedLease string
	if err := st.db.QueryRowContext(ctx, "SELECT lease_until FROM outbox WHERE id=?", firstClaims[0].ID).Scan(&renewedLease); err != nil {
		t.Fatal(err)
	}
	renewedUntil, err := time.Parse(time.RFC3339Nano, renewedLease)
	if err != nil {
		t.Fatal(err)
	}
	if initialLease == nil || !renewedUntil.After(*initialLease) {
		t.Fatalf("renewed lease=%s did not extend initial lease=%v", renewedLease, initialLease)
	}
	if secondClaims, err := st.ClaimDueOutbox(ctx, 10, time.Minute); err != nil || len(secondClaims) != 0 {
		t.Fatalf("active outbox lease was claimed twice: %#v err=%v", secondClaims, err)
	}
	oldLease := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET lease_until=? WHERE id=?", oldLease, firstClaims[0].ID); err != nil {
		t.Fatal(err)
	}
	secondClaims, err := st.ClaimDueOutbox(ctx, 10, time.Minute)
	if err != nil || len(secondClaims) != 1 || secondClaims[0].LeaseToken == firstClaims[0].LeaseToken {
		t.Fatalf("expired outbox lease was not rotated: %#v err=%v", secondClaims, err)
	}
	if renewed, err := st.RenewClaimed(ctx, firstClaims[0], time.Minute); err != nil || renewed {
		t.Fatalf("stale outbox lease was renewed: renewed=%v err=%v", renewed, err)
	}
	if completed, err := st.DeliveredClaimedResult(ctx, firstClaims[0]); err != nil || completed {
		t.Fatalf("stale outbox delivery completion was accepted: completed=%v err=%v", completed, err)
	}
	if retried, err := st.RetryClaimedResult(ctx, firstClaims[0], time.Now().UTC(), "stale delivery failure", false); err != nil || retried {
		t.Fatalf("stale outbox delivery retry was accepted: retried=%v err=%v", retried, err)
	}
	var status, token string
	var attempts int
	if err := st.db.QueryRowContext(ctx, "SELECT status,lease_token,attempts FROM outbox WHERE id=?", firstClaims[0].ID).Scan(&status, &token, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "processing" || token != secondClaims[0].LeaseToken || attempts != 2 {
		t.Fatalf("stale outbox bookkeeping changed current claim: status=%q token=%q attempts=%d", status, token, attempts)
	}
	if err := st.DeliveredClaimed(ctx, secondClaims[0]); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status,lease_token FROM outbox WHERE id=?", firstClaims[0].ID).Scan(&status, &token); err != nil {
		t.Fatal(err)
	}
	if status != "delivered" || token != "" {
		t.Fatalf("current outbox claim did not complete: status=%q token=%q", status, token)
	}

	if err := st.EnqueueSystem(ctx, "expired delivery"); err != nil {
		t.Fatal(err)
	}
	claims, err := st.ClaimDueOutbox(ctx, 10, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("expired candidate claim: %#v err=%v", claims, err)
	}
	oldAttempt := time.Now().UTC().Add(-outboxRetryWindow - time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET first_attempt=? WHERE id=?", oldAttempt, claims[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryClaimed(ctx, claims[0], time.Now().UTC(), "delivery failed", true); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status,lease_token FROM outbox WHERE id=?", claims[0].ID).Scan(&status, &token); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || token != "" {
		t.Fatalf("expired outbox claim was not dead-lettered: status=%q token=%q", status, token)
	}
	if err := st.EnqueueSystem(ctx, "cleanup expired in-flight delivery"); err != nil {
		t.Fatal(err)
	}
	cleanupClaims, err := st.ClaimDueOutbox(ctx, 10, time.Minute)
	if err != nil || len(cleanupClaims) != 1 {
		t.Fatalf("cleanup candidate claim: %#v err=%v", cleanupClaims, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET first_attempt=?,lease_until=? WHERE id=?", oldAttempt, oldLease, cleanupClaims[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status,lease_token FROM outbox WHERE id=?", cleanupClaims[0].ID).Scan(&status, &token); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || token != "" {
		t.Fatalf("cleanup did not dead-letter expired in-flight delivery: status=%q token=%q", status, token)
	}
}

func TestClaimDueOutboxDeadLettersExpiredRowsBeforeDelivery(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "expired pending"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "expired lease"); err != nil {
		t.Fatal(err)
	}
	items, err := testDueOutbox(st, ctx, 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("due outbox=%#v err=%v", items, err)
	}
	oldAttempt := time.Now().UTC().Add(-outboxRetryWindow - time.Minute).Format(time.RFC3339Nano)
	oldLease := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	for _, item := range items {
		if item.Payload == "expired lease" {
			if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET status='processing',first_attempt=?,lease_until=? WHERE id=?", oldAttempt, oldLease, item.ID); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := st.db.ExecContext(ctx, "UPDATE outbox SET first_attempt=? WHERE id=?", oldAttempt, item.ID); err != nil {
			t.Fatal(err)
		}
	}
	claims, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 0 {
		t.Fatalf("expired outbox rows were delivered: %#v", claims)
	}
	rows, err := st.db.QueryContext(ctx, "SELECT status,last_error FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var status, lastError string
		if err := rows.Scan(&status, &lastError); err != nil {
			t.Fatal(err)
		}
		if status != "dead" || lastError != "delivery retry window expired" {
			t.Fatalf("expired outbox row status=%q error=%q", status, lastError)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookRetryMessageIsRedacted(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	secretURL := "https://provider.example/hooks/secret-token?token=credential"
	if err := testRetryWebhookTriggers(st, ctx, []int64{trigger.ID}, time.Now().UTC(), secretURL); err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err := st.db.QueryRowContext(ctx, "SELECT last_error FROM webhook_triggers WHERE id=?", trigger.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persisted, secretURL) || strings.Contains(persisted, "secret-token") || strings.Contains(persisted, "credential") {
		t.Fatalf("webhook retry error leaked into SQLite: %q", persisted)
	}
	if persisted != "notification delivery failed" {
		t.Fatalf("persisted webhook retry error=%q, want bounded reason", persisted)
	}
	stored, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.LastError, secretURL) || strings.Contains(stored.LastError, "secret-token") || strings.Contains(stored.LastError, "credential") {
		t.Fatalf("webhook retry error leaked provider details: %q", stored.LastError)
	}
	if stored.LastError != "notification delivery failed" {
		t.Fatalf("webhook retry error=%q, want bounded reason", stored.LastError)
	}
}

func TestWebhookTriggerMetadataReadIsBoundedAndValidated(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		column  string
		value   func() string
		wantErr string
	}{
		{name: "event null", column: "event_types_json", value: func() string { return "null" }, wantErr: "event metadata must be a JSON array"},
		{name: "collector object", column: "collectors_json", value: func() string { return `{"collector":"devices"}` }, wantErr: "collector metadata must be a JSON array"},
		{name: "event too many values", column: "event_types_json", value: func() string {
			values := make([]string, maxWebhookEventTypes+1)
			for i := range values {
				values[i] = fmt.Sprintf("event-%d", i)
			}
			encoded, _ := json.Marshal(values)
			return string(encoded)
		}, wantErr: "event metadata contains too many values"},
		{name: "collector control value", column: "collectors_json", value: func() string { return `["devices\n"]` }, wantErr: "collector metadata contains an invalid value"},
		{name: "event oversized json", column: "event_types_json", value: func() string { return fmt.Sprintf("[%q]", strings.Repeat("x", maxWebhookMetadataJSONBytes)) }, wantErr: "event metadata JSON is empty or too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := testStore(t)
			bodyHash := strings.Repeat("a", 64)
			if _, _, err := st.RecordWebhookTrigger(ctx, bodyHash, []string{"nodeCreated"}, []string{"devices"}); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET "+tt.column+"=? WHERE body_hash=?", tt.value(), bodyHash); err != nil {
				t.Fatal(err)
			}
			if _, _, err := st.RecordWebhookTrigger(ctx, bodyHash, nil, nil); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("metadata error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestHasDueWebhookTriggersIsReadOnlyAndIncludesExpiredRows(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Now().UTC()
	if due, err := st.HasDueWebhookTriggers(ctx, now); err != nil || due {
		t.Fatalf("empty trigger queue due=%v err=%v", due, err)
	}
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("c", 64), []string{"policyUpdate"}, []string{"policy"})
	if err != nil || !created {
		t.Fatalf("record trigger created=%v err=%v", created, err)
	}
	if due, err := st.HasDueWebhookTriggers(ctx, time.Now().UTC().Add(time.Second)); err != nil || !due {
		t.Fatalf("new trigger due=%v err=%v", due, err)
	}
	var status string
	if err := st.db.QueryRowContext(ctx, "SELECT status FROM webhook_triggers WHERE id=?", trigger.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("read-only due probe changed status to %q", status)
	}
	old := now.Add(-webhookTriggerRetryWindow - time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=?,next_attempt_at=? WHERE id=?", old, now.Add(time.Hour).Format(time.RFC3339Nano), trigger.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := st.HasDueWebhookTriggers(ctx, now); err != nil || !due {
		t.Fatalf("expired trigger was not reported due=%v err=%v", due, err)
	}
}

func TestHasDueWebhookTriggersSkipsActiveProcessingLease(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Now().UTC()
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("8", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record trigger created=%v err=%v", created, err)
	}
	old := now.Add(-webhookTriggerRetryWindow - time.Minute).Format(time.RFC3339Nano)
	activeLease := now.Add(time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, `UPDATE webhook_triggers
		SET status='processing',received_at=?,next_attempt_at=?,lease_until=?,lease_token='active'
		WHERE id=?`, old, old, activeLease, trigger.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := st.HasDueWebhookTriggers(ctx, now); err != nil || due {
		t.Fatalf("active processing lease was reported due=%v err=%v", due, err)
	}
	if due, err := st.HasDueWebhookTriggers(ctx, now.Add(2*time.Minute)); err != nil || !due {
		t.Fatalf("expired processing lease was not reported due=%v err=%v", due, err)
	}
}

func TestFastWebhookClaimIsExclusiveWithDurableClaim(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, claimed, err := st.ClaimWebhookTrigger(ctx, 0, time.Minute); err != nil || claimed {
		t.Fatalf("invalid fast claim was accepted: claimed=%v err=%v", claimed, err)
	}
	trigger, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("d", 64), nil, []string{"devices"})
	if err != nil || !created {
		t.Fatalf("record trigger: %#v created=%v err=%v", trigger, created, err)
	}
	claimed, fast, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Nanosecond)
	if err != nil || !fast {
		t.Fatalf("fast claim failed: %#v claimed=%v err=%v", claimed, fast, err)
	}
	if claimed.Status != "processing" || claimed.Attempts != 1 || claimed.LeaseUntil == nil {
		t.Fatalf("fast claim did not lease trigger: %#v", claimed)
	}
	durable, err := st.ClaimWebhookTriggers(ctx, 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(durable) != 0 {
		t.Fatalf("durable worker stole fast-claimed trigger: %#v", durable)
	}
	if _, fast, err := st.ClaimWebhookTrigger(ctx, trigger.ID, time.Minute); err != nil || fast {
		t.Fatalf("second fast claim unexpectedly acquired trigger: fast=%v err=%v", fast, err)
	}
	if err := testCompleteWebhookTriggers(st, ctx, []int64{trigger.ID}); err != nil {
		t.Fatal(err)
	}
	future, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("e", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record future trigger: %#v created=%v err=%v", future, created, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET next_attempt_at=? WHERE id=?", time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), future.ID); err != nil {
		t.Fatal(err)
	}
	if _, fast, err := st.ClaimWebhookTrigger(ctx, future.ID, time.Minute); err != nil || fast {
		t.Fatalf("future fast trigger was claimed early: fast=%v err=%v", fast, err)
	}
	old, created, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
	if err != nil || !created {
		t.Fatalf("record expired trigger: %#v created=%v err=%v", old, created, err)
	}
	oldValue := time.Now().UTC().Add(-webhookTriggerRetryWindow - time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE webhook_triggers SET received_at=?,next_attempt_at=? WHERE id=?", oldValue, oldValue, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, fast, err := st.ClaimWebhookTrigger(ctx, old.ID, time.Minute); err != nil || fast {
		t.Fatalf("expired fast trigger was claimed: fast=%v err=%v", fast, err)
	}
	dead, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("f", 64), nil, nil)
	if err != nil || dead.Status != "dead" || dead.LastError != "reconciliation retry window expired" {
		t.Fatalf("expired fast trigger was not dead-lettered: %#v err=%v", dead, err)
	}
}

func TestCleanupRemovesExpiredSessions(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(ctx, setup, "a secure password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateSession(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE sessions SET expires_at=?", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired session was not removed: %d", count)
	}
}

func TestUnsupportedCollectorSilentlyBaselinesWhenItReturns(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	unsupported := []model.Collected{{Collector: "contacts", Unsupported: true}}
	if changes, err := testApplyBatch(st, ctx, generation, unsupported, func([]model.Change) string { return "digest" }); err != nil || len(changes) != 0 {
		t.Fatalf("unsupported collector produced changes: %#v %v", changes, err)
	}
	returned := []model.Collected{{Collector: "contacts", Resources: []model.Resource{{ID: "contacts", Type: "contacts", Name: "Tailnet contacts", Data: map[string]any{"email": "owner@example.com"}}}}}
	changes, err := testApplyBatch(st, ctx, generation, returned, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("returning collector did not silently baseline: %#v %v", changes, err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, collector := range status.Collectors {
		if collector.Name == "contacts" {
			found = true
			if !collector.Baseline {
				t.Fatal("returning collector is still marked as baselining")
			}
		}
	}
	if !found {
		t.Fatal("returning collector state was not recorded")
	}
}

func TestBaselinedCollectorRequiresConsecutiveUnsupportedResponses(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "contacts", Resources: []model.Resource{{ID: "contacts", Type: "contacts", Name: "Tailnet contacts", Data: map[string]any{"email": "owner@example.com"}}}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "contacts", Unsupported: true}}, func([]model.Change) string { return "first unsupported" }); err != nil {
		t.Fatal(err)
	}
	var supported, baselineFlag int
	var lastError, nextPoll string
	if err := st.db.QueryRowContext(ctx, "SELECT supported,baseline,last_error,next_poll FROM collector_state WHERE generation=? AND collector='contacts'", generation).Scan(&supported, &baselineFlag, &lastError, &nextPoll); err != nil {
		t.Fatal(err)
	}
	firstRetry, err := time.Parse(time.RFC3339Nano, nextPoll)
	if err != nil {
		t.Fatal(err)
	}
	if supported != 1 || baselineFlag != 1 || lastError != unsupportedConfirmationMessage || time.Until(firstRetry) <= 0 || time.Until(firstRetry) > time.Hour {
		t.Fatalf("first unsupported response demoted a valid baseline: supported=%d baseline=%d error=%q next=%q", supported, baselineFlag, lastError, nextPoll)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "contacts", Unsupported: true}}, func([]model.Change) string { return "second unsupported" }); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT supported,baseline,last_error,next_poll FROM collector_state WHERE generation=? AND collector='contacts'", generation).Scan(&supported, &baselineFlag, &lastError, &nextPoll); err != nil {
		t.Fatal(err)
	}
	confirmedRetry, err := time.Parse(time.RFC3339Nano, nextPoll)
	if err != nil {
		t.Fatal(err)
	}
	if supported != 0 || baselineFlag != 1 || lastError != "unsupported" || time.Until(confirmedRetry) < 5*time.Hour {
		t.Fatalf("second unsupported response did not demote the collector: supported=%d baseline=%d error=%q next=%q", supported, baselineFlag, lastError, nextPoll)
	}
}

func TestDriftAcrossUnsupportedWindowIsReported(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	resource := func(authorized bool) []model.Resource {
		return []model.Resource{{Collector: "devices", ID: "device-1", Type: "device", Name: "server", Data: map[string]any{
			"id": "device-1", "hostname": "server", "authorized": authorized,
		}}}
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: resource(false)}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Unsupported: true}}, func([]model.Change) string { return "unsupported" }); err != nil {
		t.Fatal(err)
	}
	changes, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: resource(true)}}, func([]model.Change) string { return "recovered" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != "changed" {
		t.Fatalf("drift across unsupported window was absorbed: %#v", changes)
	}
}

func TestUnsupportedWindowPreservesRemovalDetection(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	resource := []model.Resource{{Collector: "devices", ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: resource}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Unsupported: true}}, func([]model.Change) string { return "unsupported" }); err != nil {
		t.Fatal(err)
	}
	if changes, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "first recovery" }); err != nil || len(changes) != 0 {
		t.Fatalf("first recovery unexpectedly changed state: %#v err=%v", changes, err)
	}
	changes, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "second recovery" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != "removed" {
		t.Fatalf("removal across unsupported window was lost: %#v", changes)
	}
}

func TestCredentialRotationPreservesInventory(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	firstGeneration, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	if _, err := testApplyBatch(st, ctx, firstGeneration, baseline, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}
	rotated := settings()
	rotated.OAuthClientSecret = "rotated-secret"
	secondGeneration, err := st.SaveSettings(ctx, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if secondGeneration != firstGeneration {
		t.Fatal("credential rotation unexpectedly created a new generation")
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("baseline snapshot was lost after credential rotation: %d", count)
	}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}}}}}
	changes, err := testApplyBatch(st, ctx, secondGeneration, changed, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 1 || changes[0].Kind != "changed" {
		t.Fatalf("change after credential rotation was not detected: %#v %v", changes, err)
	}
}

func TestIdentityChangeDeadLettersPendingEventNotifications(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	firstGeneration, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "new-server"}}}}}
	if _, err := st.ApplyBatchWithBatch(ctx, firstGeneration, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, firstGeneration, changed, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "release notification"); err != nil {
		t.Fatal(err)
	}
	var oldID, systemID int64
	if err := st.db.QueryRowContext(ctx, "SELECT id FROM outbox WHERE batch_id IS NOT NULL ORDER BY id LIMIT 1").Scan(&oldID); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT id FROM outbox WHERE batch_id IS NULL ORDER BY id LIMIT 1").Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	rotated := settings()
	rotated.OAuthClientID = "new-client"
	secondGeneration, err := st.SaveSettings(ctx, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if secondGeneration == firstGeneration {
		t.Fatal("identity change did not create a new generation")
	}
	var oldStatus, oldError, systemStatus string
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error FROM outbox WHERE id=?", oldID).Scan(&oldStatus, &oldError); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "dead" || oldError != "monitoring identity changed" {
		t.Fatalf("old identity notification status=%q error=%q", oldStatus, oldError)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status FROM outbox WHERE id=?", systemID).Scan(&systemStatus); err != nil {
		t.Fatal(err)
	}
	if systemStatus != "pending" {
		t.Fatalf("system notification status=%q, want pending", systemStatus)
	}
}

func TestEarliestCollectorDueHandlesEmptyImmediateAndInvalidRows(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if deadline, found, err := st.EarliestCollectorDue(ctx, generation, nil); err != nil || found || !deadline.IsZero() {
		t.Fatalf("empty collector deadline=%v found=%v err=%v", deadline, found, err)
	}
	if deadline, found, err := st.EarliestCollectorDue(ctx, generation, []string{"missing"}); err != nil || found || !deadline.IsZero() {
		t.Fatalf("missing collector deadline=%v found=%v err=%v", deadline, found, err)
	}
	first := time.Now().UTC().Add(5 * time.Minute)
	second := first.Add(time.Hour)
	if err := st.SetNextPollErr(ctx, generation, []string{"devices"}, first); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNextPollErr(ctx, generation, []string{"users"}, second); err != nil {
		t.Fatal(err)
	}
	deadline, found, err := st.EarliestCollectorDue(ctx, generation, []string{"users", "devices"})
	if err != nil || !found || deadline.Before(first) || deadline.After(first.Add(time.Second)) {
		t.Fatalf("earliest collector deadline=%v found=%v err=%v", deadline, found, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE collector_state SET next_poll='' WHERE generation=? AND collector='devices'", generation); err != nil {
		t.Fatal(err)
	}
	deadline, found, err = st.EarliestCollectorDue(ctx, generation, []string{"devices", "users"})
	if err != nil || !found || !deadline.IsZero() {
		t.Fatalf("immediate collector deadline=%v found=%v err=%v", deadline, found, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE collector_state SET next_poll='not-a-timestamp' WHERE generation=? AND collector='users'", generation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.EarliestCollectorDue(ctx, generation, []string{"users"}); err == nil || !strings.Contains(err.Error(), "parse collector next poll timestamp") {
		t.Fatalf("invalid collector deadline error=%v", err)
	}
}

func TestWebhookSecretCanBeCleared(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	configured := settings()
	configured.WebhookSecret = "webhook-secret"
	if _, err := st.SaveSettings(ctx, configured); err != nil {
		t.Fatal(err)
	}
	cleared := configured
	cleared.WebhookSecret = ""
	cleared.ClearWebhookSecret = true
	if _, err := st.SaveSettings(ctx, cleared); err != nil {
		t.Fatal(err)
	}
	value, err := st.WebhookSecret(ctx)
	if err != nil || value != "" {
		t.Fatalf("webhook secret was not cleared: %q err=%v", value, err)
	}
}

func TestStatusDoesNotDecryptConfiguredSecrets(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE settings SET oauth_secret_enc='invalid-envelope'"); err != nil {
		t.Fatal(err)
	}
	if status, err := st.Status(ctx); err != nil || !status.Configured {
		t.Fatalf("status should remain available without decrypting secrets: %#v %v", status, err)
	}
}

func TestStatusReportsBaselineGraceDegradation(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-baselineGracePeriod - time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE settings SET configured_at=? WHERE id=1", old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,failure_count,next_poll)
		VALUES(?,?,1,0,'',0,?)`, generation, "devices", old); err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.BaselineReady || !status.BaselineDegraded || !strings.Contains(status.BaselineReason, "waiting for: devices") {
		t.Fatalf("baseline grace status=%#v", status)
	}
}

func TestStatusReportsPostBaselineCollectorDegradation(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE settings SET baseline_at=?,configured_at=? WHERE id=1", observed, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,failure_count,partial,partial_error_count,next_poll)
		VALUES(?,?,1,1,'upstream unavailable',2,0,0,?)`, generation, "devices", observed); err != nil {
		t.Fatal(err)
	}
	// A confirmed plan limitation is not a transient health failure and should
	// not make an established baseline appear unavailable.
	if _, err := st.db.ExecContext(ctx, `INSERT INTO collector_state(generation,collector,supported,baseline,last_error,failure_count,partial,partial_error_count,next_poll)
		VALUES(?,?,0,1,'unsupported',0,0,0,?)`, generation, "log_streaming", observed); err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.BaselineReady || !status.BaselineDegraded || status.BaselineReason != "collector health degraded: devices" {
		t.Fatalf("post-baseline failure was hidden: %#v", status)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE collector_state SET failure_count=0,last_error='',partial=1 WHERE generation=? AND collector='devices'", generation); err != nil {
		t.Fatal(err)
	}
	status, err = st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.BaselineDegraded || status.BaselineReason != "collector health degraded: devices" {
		t.Fatalf("partial collector degradation was hidden: %#v", status)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE collector_state SET partial=0 WHERE generation=? AND collector='devices'", generation); err != nil {
		t.Fatal(err)
	}
	status, err = st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.BaselineDegraded || status.BaselineReason != "" {
		t.Fatalf("healthy collectors remained degraded: %#v", status)
	}
}

func TestTrackAppVersionQueuesConfiguredUpdatesOnce(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	format := func(previous, current string) string {
		return "updated " + previous + " to " + current
	}

	notified, err := st.TrackAppVersion(ctx, "0.3.0", format)
	if err != nil || notified {
		t.Fatalf("first tracked version should be silent: notified=%v err=%v", notified, err)
	}
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	notified, err = st.TrackAppVersion(ctx, "0.3.1", format)
	if err != nil || !notified {
		t.Fatalf("configured update was not queued: notified=%v err=%v", notified, err)
	}
	notified, err = st.TrackAppVersion(ctx, "0.3.1", format)
	if err != nil || notified {
		t.Fatalf("same version was queued again: notified=%v err=%v", notified, err)
	}
	items, err := testDueOutbox(st, ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Payload != "updated 0.3.0 to 0.3.1" {
		t.Fatalf("unexpected update outbox: %#v", items)
	}
}

func TestTrackAppVersionIgnoresDevelopmentBuild(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	format := func(previous, current string) string { return previous + " to " + current }
	if notified, err := st.TrackAppVersion(ctx, "0.3.0", format); err != nil || notified {
		t.Fatalf("first tracked version should be silent: notified=%v err=%v", notified, err)
	}
	if notified, err := st.TrackAppVersion(ctx, "dev", format); err != nil || notified {
		t.Fatalf("development version should be ignored: notified=%v err=%v", notified, err)
	}
	if notified, err := st.TrackAppVersion(ctx, "0.3.1", format); err != nil || !notified {
		t.Fatalf("release update after development build was not queued: notified=%v err=%v", notified, err)
	}
	items, err := testDueOutbox(st, ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Payload != "0.3.0 to 0.3.1" {
		t.Fatalf("development build replaced tracked release: %#v", items)
	}
}

func TestBaselineIsSilent(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	first := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"addresses": []any{"100.64.0.1"}}}}}}
	changes, err := testApplyBatch(st, ctx, generation, first, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("baseline emitted changes: %#v %v", changes, err)
	}
	second := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"addresses": []any{"100.64.0.2"}}}}}}
	changes, err = testApplyBatch(st, ctx, generation, second, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 1 || changes[0].Kind != "changed" {
		t.Fatalf("change not detected: %#v %v", changes, err)
	}
	status, _ := st.Status(ctx)
	if status.Pending != 1 {
		t.Fatalf("expected durable outbox, got %d", status.Pending)
	}
}

func TestCollectorPollTelemetryIsVisibleInStatus(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"hostname": "server"}}}}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCollectorPoll(ctx, generation, "devices", 1234*time.Millisecond, true); err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Collectors) != 1 || !status.Collectors[0].Partial || status.Collectors[0].PollDurationMS != 1234 {
		t.Fatalf("collector telemetry=%#v", status.Collectors)
	}
}

func TestCollectorPollTelemetryClampsNegativeDuration(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"hostname": "server"}}}}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCollectorPoll(ctx, generation, "devices", -time.Second, false); err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Collectors) != 1 || status.Collectors[0].PollDurationMS != 0 || status.Collectors[0].Partial {
		t.Fatalf("negative collector telemetry was not normalized: %#v", status.Collectors)
	}
}

func TestRemovalRequiresTwoPolls(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	first := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"addresses": []any{"100.64.0.1"}}}}}}
	if _, err := testApplyBatch(st, ctx, generation, first, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}
	empty := []model.Collected{{Collector: "devices", Resources: nil}}
	changes, err := testApplyBatch(st, ctx, generation, empty, func([]model.Change) string { return "digest" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatal("removed after one missing poll")
	}
	changes, err = testApplyBatch(st, ctx, generation, empty, func([]model.Change) string { return "digest" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != "removed" {
		t.Fatalf("not removed after two polls: %#v", changes)
	}
}

func TestMassRemovalGuardPreservesSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	resources := make([]model.Resource, 4)
	for i := range resources {
		id := fmt.Sprintf("device-%d", i)
		resources[i] = model.Resource{ID: id, Type: "device", Name: id, Collector: "devices", Data: map[string]any{"hostname": id}}
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: resources}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	changes, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "degraded" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("mass removal guard emitted changes: %#v", changes)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots WHERE generation=? AND collector='devices'", generation).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(resources) {
		t.Fatalf("mass removal guard deleted snapshots: %d", count)
	}
	var lastError string
	if err := st.db.QueryRowContext(ctx, "SELECT last_error FROM collector_state WHERE generation=? AND collector='devices'", generation).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastError, "possible mass removal guarded") {
		t.Fatalf("mass removal guard did not record collector health: %q", lastError)
	}
	// A persistent response must eventually be accepted rather than leaving
	// removals suppressed forever. The first two suspicious responses are
	// guarded; the next normal poll starts the ordinary two-poll confirmation.
	for poll := 0; poll < 2; poll++ {
		changes, err = testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "degraded" })
		if err != nil {
			t.Fatal(err)
		}
		if len(changes) != 0 {
			t.Fatalf("mass removal guard emitted changes on confirmation poll %d: %#v", poll, changes)
		}
	}
	changes, err = testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices"}}, func([]model.Change) string { return "degraded" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != len(resources) {
		t.Fatalf("persistent mass removal was not eventually recorded: %#v", changes)
	}
}

func TestMassRemovalGuardProtectsMajorityDisappearance(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	resources := make([]model.Resource, 5)
	for i := range resources {
		id := fmt.Sprintf("device-%d", i)
		resources[i] = model.Resource{ID: id, Type: "device", Name: id, Collector: "devices", Data: map[string]any{"hostname": id}}
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: resources}}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	// Three of five resources disappearing at once is a majority loss, but it
	// is still more likely to be a truncated upstream response than three real
	// deletions. The guard must preserve all five snapshots for confirmation.
	changes, err := testApplyBatch(st, ctx, generation, []model.Collected{{Collector: "devices", Resources: resources[:2]}}, func([]model.Change) string { return "degraded" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("majority disappearance emitted changes: %#v", changes)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots WHERE generation=? AND collector='devices'", generation).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(resources) {
		t.Fatalf("majority disappearance deleted snapshots: %d", count)
	}
	var lastError string
	if err := st.db.QueryRowContext(ctx, "SELECT last_error FROM collector_state WHERE generation=? AND collector='devices'", generation).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastError, "possible mass removal guarded") {
		t.Fatalf("majority disappearance did not record collector health: %q", lastError)
	}
}

func TestFailedCollectorCannotRemoveSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, _ := st.SaveSettings(ctx, settings())
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	_, _ = testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "" })
	failed := []model.Collected{{Collector: "devices", Error: context.DeadlineExceeded}}
	changes, err := testApplyBatch(st, ctx, generation, failed, func([]model.Change) string { return "" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("failed poll changed state: %#v %v", changes, err)
	}
	var count int
	_ = st.db.QueryRow("SELECT COUNT(*) FROM snapshots").Scan(&count)
	if count != 1 {
		t.Fatalf("snapshot lost after failure: %d", count)
	}
}

func TestPartialCollectorCannotRemoveSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, _ := st.SaveSettings(ctx, settings())
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{
		{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}},
		{ID: "2", Type: "device", Name: "router", Data: map[string]any{"hostname": "router"}},
	}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "" }); err != nil {
		t.Fatal(err)
	}
	partial := []model.Collected{{Collector: "devices", Partial: true, PartialError: "detail request failed", PartialErrorCount: 2, Resources: []model.Resource{
		{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"}},
	}}}
	changes, err := testApplyBatch(st, ctx, generation, partial, func([]model.Change) string { return "" })
	if err != nil || len(changes) != 1 || changes[0].Kind != "changed" {
		t.Fatalf("partial change not recorded: %#v %v", changes, err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots WHERE generation=? AND collector='devices'", generation).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("partial poll removed snapshots: %d", count)
	}
	var lastError string
	if err := st.db.QueryRowContext(ctx, "SELECT last_error FROM collector_state WHERE generation=? AND collector='devices'", generation).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if lastError != "detail request failed" {
		t.Fatalf("partial collector error not persisted: %q", lastError)
	}
	var partialErrorCount int
	if err := st.db.QueryRowContext(ctx, "SELECT partial_error_count FROM collector_state WHERE generation=? AND collector='devices'", generation).Scan(&partialErrorCount); err != nil {
		t.Fatal(err)
	}
	if partialErrorCount != 2 {
		t.Fatalf("partial collector error count=%d, want 2", partialErrorCount)
	}
}

func TestOutboxSurvivesRestart(t *testing.T) {
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
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"addresses": []any{"100.64.0.1"}}}}}}
	changed := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"addresses": []any{"100.64.0.2"}}}}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, changed, func([]model.Change) string { return "durable digest" }); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items, err := testDueOutbox(reopened, ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Payload != "durable digest" {
		t.Fatalf("outbox did not survive restart: %#v", items)
	}
}

func TestNewIgnoredFieldsSilentlyRenormalizeExistingSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "device_details", Resources: []model.Resource{{
		ID: "1", Type: "device_details", Name: "server", Data: map[string]any{
			"detail": map[string]any{
				"hostname":            "server",
				"connectedToControl":  false,
				"multipleConnections": false,
				"nodeKey":             "node:old",
			},
			"deviceInvites": []any{
				map[string]any{
					"accepted": true,
					"acceptedBy": map[string]any{
						"id":            float64(123),
						"loginName":     "user@example.com",
						"profilePicUrl": "https://avatars.example.com/old",
					},
				},
			},
		},
	}}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}

	legacy := `{"detail":{"connectedToControl":false,"hostname":"server","multipleConnections":false,"nodeKey":"node:old"},"deviceInvites":[{"accepted":true,"acceptedBy":{"id":123,"loginName":"user@example.com","profilePicUrl":{"redacted_sha256":"old-hash"}}}]}`
	if _, err := st.db.ExecContext(ctx, "UPDATE snapshots SET canonical_json=?,content_hash='legacy-format' WHERE generation=? AND collector='device_details' AND resource_id='1'", legacy, generation); err != nil {
		t.Fatal(err)
	}
	current := []model.Collected{{Collector: "device_details", Resources: []model.Resource{{
		ID: "1", Type: "device_details", Name: "server", Data: map[string]any{
			"deviceInvites": []any{
				map[string]any{
					"accepted": true,
					"acceptedBy": map[string]any{
						"id":            float64(123),
						"loginName":     "user@example.com",
						"profilePicUrl": "https://avatars.example.com/new",
					},
				},
			},
		},
	}}}}
	changes, err := testApplyBatch(st, ctx, generation, current, func([]model.Change) string { return "digest" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("volatile field migration emitted changes: %#v", changes)
	}
	var canonical string
	if err := st.db.QueryRowContext(ctx, "SELECT canonical_json FROM snapshots WHERE generation=? AND collector='device_details' AND resource_id='1'", generation).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(canonical, "connectedToControl") {
		t.Fatalf("snapshot was not silently re-normalized: %s", canonical)
	}
	if strings.Contains(canonical, "profilePicUrl") {
		t.Fatalf("profile picture URL was not removed during migration: %s", canonical)
	}
	if strings.Contains(canonical, "detail") || strings.Contains(canonical, "nodeKey") {
		t.Fatalf("duplicated core device data was not removed during migration: %s", canonical)
	}
}

func TestStoredInviteURLFingerprintMigratesWithoutChange(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	inviteURL := "https://login.tailscale.com/admin/invite/super-secret"
	currentData := map[string]any{
		"deviceInvites": []any{
			map[string]any{
				"accepted":  true,
				"deviceId":  "1",
				"id":        "invite-1",
				"inviteUrl": inviteURL,
			},
		},
	}
	baseline := []model.Collected{{Collector: "device_details", Resources: []model.Resource{{
		ID: "1", Type: "device_details", Name: "server", Data: currentData,
	}}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}

	var storedRaw []byte
	if err := st.db.QueryRowContext(ctx, "SELECT canonical_json FROM snapshots WHERE generation=? AND collector='device_details' AND resource_id='1'", generation).Scan(&storedRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE snapshots SET content_hash='legacy-format' WHERE generation=? AND collector='device_details' AND resource_id='1'", generation); err != nil {
		t.Fatal(err)
	}

	current := []model.Collected{{Collector: "device_details", Resources: []model.Resource{{
		ID: "1", Type: "device_details", Name: "server", Data: currentData,
	}}}}
	changes, err := testApplyBatch(st, ctx, generation, current, func([]model.Change) string { return "digest" })
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("stored invite URL fingerprint migration emitted changes: %#v", changes)
	}
	var migratedRaw []byte
	if err := st.db.QueryRowContext(ctx, "SELECT canonical_json FROM snapshots WHERE generation=? AND collector='device_details' AND resource_id='1'", generation).Scan(&migratedRaw); err != nil {
		t.Fatal(err)
	}
	if string(storedRaw) != string(migratedRaw) {
		t.Fatalf("stored invite fingerprint changed during migration:\n%s\n%s", storedRaw, migratedRaw)
	}
}

func TestDeviceRuntimeMigrationKeepsClientUpdateAlert(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "1", Type: "device", Name: "server", Data: map[string]any{
			"hostname": "server", "multipleConnections": false, "machineKey": "machine:old", "nodeKey": "node:old", "updateAvailable": false,
		},
	}}}}
	if _, err := testApplyBatch(st, ctx, generation, baseline, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}

	legacy := `{"hostname":"server","machineKey":"machine:old","multipleConnections":false,"nodeKey":"node:old","updateAvailable":false}`
	if _, err := st.db.ExecContext(ctx, "UPDATE snapshots SET canonical_json=?,content_hash='legacy-format' WHERE generation=? AND collector='devices' AND resource_id='1'", legacy, generation); err != nil {
		t.Fatal(err)
	}
	runtimeOnly := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "1", Type: "device", Name: "server", Data: map[string]any{
			"hostname": "server", "multipleConnections": true, "machineKey": "machine:new", "nodeKey": "node:new", "updateAvailable": false,
		},
	}}}}
	changes, err := testApplyBatch(st, ctx, generation, runtimeOnly, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("device runtime migration emitted changes: %#v %v", changes, err)
	}

	clientUpdate := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "1", Type: "device", Name: "server", Data: map[string]any{
			"hostname": "server", "multipleConnections": true, "machineKey": "machine:new", "nodeKey": "node:new", "updateAvailable": true,
		},
	}}}}
	changes, err = testApplyBatch(st, ctx, generation, clientUpdate, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 1 || len(changes[0].Fields) != 1 || changes[0].Fields[0].Field != "updateAvailable" {
		t.Fatalf("client update availability was not preserved: %#v %v", changes, err)
	}
}

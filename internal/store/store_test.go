package store

import (
	"context"
	"database/sql"
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
	if err != nil || generation != 2 {
		t.Fatalf("credential change did not rebaseline: %d %v", generation, err)
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
	if _, err := db.Exec("UPDATE schema_version SET version=3"); err != nil {
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
	if changes, err := st.ApplyBatch(ctx, generation, unsupported, func([]model.Change) string { return "digest" }); err != nil || len(changes) != 0 {
		t.Fatalf("unsupported collector produced changes: %#v %v", changes, err)
	}
	returned := []model.Collected{{Collector: "contacts", Resources: []model.Resource{{ID: "contacts", Type: "contacts", Name: "Tailnet contacts", Data: map[string]any{"email": "owner@example.com"}}}}}
	changes, err := st.ApplyBatch(ctx, generation, returned, func([]model.Change) string { return "digest" })
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

func TestCredentialRotationPrunesOldInventoryAndRejectsStalePolls(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	firstGeneration, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	if _, err := st.ApplyBatch(ctx, firstGeneration, baseline, func([]model.Change) string { return "digest" }); err != nil {
		t.Fatal(err)
	}
	rotated := settings()
	rotated.OAuthClientSecret = "rotated-secret"
	secondGeneration, err := st.SaveSettings(ctx, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if secondGeneration == firstGeneration {
		t.Fatal("credential rotation did not create a new generation")
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("old snapshots were retained after rotation: %d", count)
	}
	st.SetNextPoll(ctx, firstGeneration, []string{"devices"}, time.Now().UTC().Add(time.Minute))
	if notify, _, err := st.RecordCollectorFailure(ctx, firstGeneration, "devices", "stale failure"); err != nil || notify {
		t.Fatalf("stale collector failure was not ignored: notify=%v err=%v", notify, err)
	}
	var oldStateCount int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM collector_state WHERE generation=?", firstGeneration).Scan(&oldStateCount); err != nil {
		t.Fatal(err)
	}
	if oldStateCount != 0 {
		t.Fatalf("stale poll recreated old collector state: %d", oldStateCount)
	}
	stale := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "stale", Type: "device", Name: "stale", Data: map[string]any{"hostname": "stale"}}}}}
	changes, err := st.ApplyBatch(ctx, firstGeneration, stale, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("stale poll was not ignored: %#v %v", changes, err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale poll repopulated old snapshots: %d", count)
	}
}

func TestStatusFailsWhenConfiguredSecretsCannotBeDecrypted(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE settings SET oauth_secret_enc='invalid-envelope'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Status(ctx); err == nil {
		t.Fatal("status hid a settings decryption failure")
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
	items, err := st.DueOutbox(ctx, 10)
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
	items, err := st.DueOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Payload != "0.3.0 to 0.3.1" {
		t.Fatalf("development build replaced tracked release: %#v", items)
	}
}

func TestSilentBaselineDiffAndTwoPollRemoval(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	first := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"addresses": []any{"100.64.0.1"}}}}}}
	changes, err := st.ApplyBatch(ctx, generation, first, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("baseline emitted changes: %#v %v", changes, err)
	}
	second := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Collector: "devices", Data: map[string]any{"addresses": []any{"100.64.0.2"}}}}}}
	changes, err = st.ApplyBatch(ctx, generation, second, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 1 || changes[0].Kind != "changed" {
		t.Fatalf("change not detected: %#v %v", changes, err)
	}
	status, _ := st.Status(ctx)
	if status.Pending != 1 {
		t.Fatalf("expected durable outbox, got %d", status.Pending)
	}
	empty := []model.Collected{{Collector: "devices", Resources: nil}}
	changes, _ = st.ApplyBatch(ctx, generation, empty, func([]model.Change) string { return "digest" })
	if len(changes) != 0 {
		t.Fatal("removed after one missing poll")
	}
	changes, _ = st.ApplyBatch(ctx, generation, empty, func([]model.Change) string { return "digest" })
	if len(changes) != 1 || changes[0].Kind != "removed" {
		t.Fatalf("not removed after two polls: %#v", changes)
	}
}

func TestFailedCollectorCannotRemoveSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, _ := st.SaveSettings(ctx, settings())
	baseline := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"}}}}}
	_, _ = st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "" })
	failed := []model.Collected{{Collector: "devices", Error: context.DeadlineExceeded}}
	changes, err := st.ApplyBatch(ctx, generation, failed, func([]model.Change) string { return "" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("failed poll changed state: %#v %v", changes, err)
	}
	var count int
	_ = st.db.QueryRow("SELECT COUNT(*) FROM snapshots").Scan(&count)
	if count != 1 {
		t.Fatalf("snapshot lost after failure: %d", count)
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
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatch(ctx, generation, changed, func([]model.Change) string { return "durable digest" }); err != nil {
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
	items, err := reopened.DueOutbox(ctx, 10)
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
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "digest" }); err != nil {
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
	changes, err := st.ApplyBatch(ctx, generation, current, func([]model.Change) string { return "digest" })
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
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "digest" }); err != nil {
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
	changes, err := st.ApplyBatch(ctx, generation, current, func([]model.Change) string { return "digest" })
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
	if _, err := st.ApplyBatch(ctx, generation, baseline, func([]model.Change) string { return "digest" }); err != nil {
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
	changes, err := st.ApplyBatch(ctx, generation, runtimeOnly, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 0 {
		t.Fatalf("device runtime migration emitted changes: %#v %v", changes, err)
	}

	clientUpdate := []model.Collected{{Collector: "devices", Resources: []model.Resource{{
		ID: "1", Type: "device", Name: "server", Data: map[string]any{
			"hostname": "server", "multipleConnections": true, "machineKey": "machine:new", "nodeKey": "node:new", "updateAvailable": true,
		},
	}}}}
	changes, err = st.ApplyBatch(ctx, generation, clientUpdate, func([]model.Change) string { return "digest" })
	if err != nil || len(changes) != 1 || len(changes[0].Fields) != 1 || changes[0].Fields[0].Field != "updateAvailable" {
		t.Fatalf("client update availability was not preserved: %#v %v", changes, err)
	}
}

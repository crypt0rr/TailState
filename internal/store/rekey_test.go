package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestRekeyPreservesEncryptedStateAndEvidenceIdentity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	oldBox, err := secret.NewBox([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, oldBox)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "oauth-secret", WebhookSecret: "webhook-secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "secondary", ServiceURL: "generic://notify.example/path", Enabled: true}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	keyID, err := st.EvidenceSigningKeyID(ctx)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if generation != 1 {
		st.Close()
		t.Fatalf("generation=%d", generation)
	}
	baseline := model.Collected{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server"},
	}}}
	changed := model.Collected{Collector: "devices", Resources: []model.Resource{{
		ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-new"},
	}}}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{baseline}, func([]model.Change) string { return "baseline" }); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := testApplyBatch(st, ctx, generation, []model.Collected{changed}, func([]model.Change) string { return "changed" }); err != nil {
		st.Close()
		t.Fatal(err)
	}
	evidence, err := st.ExportEvidencePack(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	public, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := VerifyEvidencePackWithKey(evidence, public); err != nil {
		st.Close()
		t.Fatalf("evidence did not verify before rekey: %v", err)
	}
	newBox, err := secret.NewBox([]byte(strings.Repeat("b", 32)))
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Rekey(ctx, newBox); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if got, err := st.EvidenceSigningKeyID(ctx); err != nil || got != keyID {
		t.Fatalf("evidence key changed after rekey: %q/%v", got, err)
	}
	if got, err := st.Settings(ctx); err != nil || got.OAuthClientSecret != "oauth-secret" || got.WebhookSecret != "webhook-secret" {
		t.Fatalf("settings after rekey=%#v err=%v", got, err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 2 {
		t.Fatalf("destinations after rekey=%#v err=%v", destinations, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, oldBox); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatal("old master key still opened the rekeyed database")
	}
	reopened, err := Open(path, newBox)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := reopened.EvidenceSigningKeyID(ctx); err != nil || got != keyID {
		t.Fatalf("reopened evidence key=%q err=%v", got, err)
	}
	if err := VerifyEvidencePackWithKey(evidence, public); err != nil {
		t.Fatalf("evidence signed before rekey no longer verifies: %v", err)
	}
}

func TestRekeyRollsBackWhenAnEncryptedValueIsCorrupt(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc='invalid-envelope'"); err != nil {
		t.Fatal(err)
	}
	newBox, err := secret.NewBox([]byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Rekey(ctx, newBox); err == nil {
		t.Fatal("rekey succeeded with a corrupt destination envelope")
	}
	var encoded string
	if err := st.db.QueryRowContext(ctx, "SELECT oauth_secret_enc FROM settings WHERE id=1").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := st.box.Decrypt(encoded); err != nil {
		t.Fatalf("transaction did not preserve the original key after rollback: %v", err)
	}
}

func TestRekeyFailureLeavesOriginalDatabaseUsable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	oldBox, err := secret.NewBox([]byte(strings.Repeat("d", 32)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, oldBox)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{Name: "secondary", ServiceURL: "generic://notify.example/path", Enabled: true}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	keyID, err := st.EvidenceSigningKeyID(ctx)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_rekey_evidence_key
		BEFORE UPDATE OF value ON meta
		WHEN NEW.key='evidence_signing_private_key_enc'
		BEGIN SELECT RAISE(ABORT,'evidence key rotation failed'); END`); err != nil {
		st.Close()
		t.Fatal(err)
	}
	newBox, err := secret.NewBox([]byte(strings.Repeat("e", 32)))
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Rekey(ctx, newBox); err == nil {
		st.Close()
		t.Fatal("rekey succeeded despite an injected metadata failure")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, oldBox)
	if err != nil {
		t.Fatalf("original master key could not reopen the database after rollback: %v", err)
	}
	defer reopened.Close()
	gotSettings, err := reopened.Settings(ctx)
	if err != nil {
		t.Fatalf("settings after failed rekey: %v", err)
	}
	if gotSettings.OAuthClientSecret != "secret" {
		t.Fatalf("original encrypted settings changed after failed rekey: %q", gotSettings.OAuthClientSecret)
	}
	destinations, err := reopened.ListDestinations(ctx)
	if err != nil {
		t.Fatalf("destinations after failed rekey: %v", err)
	}
	if len(destinations) != 2 {
		t.Fatalf("destinations after failed rekey = %d, want 2", len(destinations))
	}
	if got, err := reopened.EvidenceSigningKeyID(ctx); err != nil || got != keyID {
		t.Fatalf("evidence identity after failed rekey = %q/%v, want %q", got, err, keyID)
	}
}

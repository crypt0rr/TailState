package store

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func bindingFixture(t *testing.T) (*Store, string, *secret.Box, int64, int64) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	input := settings()
	input.WebhookSecret = "webhook-secret"
	if _, err := st.SaveSettings(ctx, input); err != nil {
		t.Fatal(err)
	}
	first, err := st.SaveDestination(ctx, NotificationDestination{Name: "a", ServiceURL: "generic://a.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.SaveDestination(ctx, NotificationDestination{Name: "b", ServiceURL: "generic://b.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return st, path, box, first, second
}

type encryptedValue struct {
	query, binding string
	args           []any
}

func storedEncryptedValues(first, second int64) []encryptedValue {
	return []encryptedValue{
		{query: "SELECT oauth_secret_enc FROM settings WHERE id=1", binding: settingsBinding("oauth_secret_enc")},
		{query: "SELECT mattermost_url_enc FROM settings WHERE id=1", binding: settingsBinding("mattermost_url_enc")},
		{query: "SELECT webhook_secret_enc FROM settings WHERE id=1", binding: settingsBinding("webhook_secret_enc")},
		{query: "SELECT service_url_enc FROM notification_destinations WHERE id=?", binding: destinationBinding(first), args: []any{first}},
		{query: "SELECT service_url_enc FROM notification_destinations WHERE id=?", binding: destinationBinding(second), args: []any{second}},
		{query: "SELECT value FROM meta WHERE key=?", binding: metaBinding(masterKeyCheckMeta), args: []any{masterKeyCheckMeta}},
		{query: "SELECT value FROM meta WHERE key=?", binding: metaBinding(evidenceSigningPrivateKeyMeta), args: []any{evidenceSigningPrivateKeyMeta}},
	}
}

// TestMovedCiphertextFailsAuthentication copies encrypted values between
// rows and columns, which an attacker with database write access could do to
// redirect notifications. Each moved value must fail authentication instead
// of decrypting as the target value.
func TestMovedCiphertextFailsAuthentication(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name   string
		move   string
		args   func(first, second int64) []any
		verify func(*Store) error
	}{
		{
			name:   "destination URL onto another destination",
			move:   "UPDATE notification_destinations SET service_url_enc=(SELECT service_url_enc FROM notification_destinations WHERE id=?) WHERE id=?",
			args:   func(first, second int64) []any { return []any{second, first} },
			verify: func(st *Store) error { return destinationURLsReadable(ctx, st) },
		},
		{
			name:   "signing key into a destination URL",
			move:   "UPDATE notification_destinations SET service_url_enc=(SELECT value FROM meta WHERE key=?) WHERE id=?",
			args:   func(first, _ int64) []any { return []any{evidenceSigningPrivateKeyMeta, first} },
			verify: func(st *Store) error { return destinationURLsReadable(ctx, st) },
		},
		{
			name: "OAuth secret into the webhook secret",
			move: "UPDATE settings SET webhook_secret_enc=oauth_secret_enc WHERE id=?",
			args: func(int64, int64) []any { return []any{1} },
			verify: func(st *Store) error {
				_, err := st.WebhookSecret(ctx)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			st, _, _, first, second := bindingFixture(t)
			if err := test.verify(st); err != nil {
				t.Fatalf("unmodified store failed: %v", err)
			}
			if _, err := st.db.ExecContext(ctx, test.move, test.args(first, second)...); err != nil {
				t.Fatal(err)
			}
			if err := test.verify(st); err == nil {
				t.Fatal("moved ciphertext authenticated at its new location")
			}
		})
	}
}

// destinationURLsReadable fails when any active destination's service URL
// does not decrypt at its location. ListDestinations flags such a URL
// instead of failing, so the destination can still be repaired.
func destinationURLsReadable(ctx context.Context, st *Store) error {
	destinations, err := st.ListDestinations(ctx)
	if err != nil {
		return err
	}
	for _, destination := range destinations {
		if destination.ServiceURLUnreadable || destination.ServiceURL == "" {
			return fmt.Errorf("destination %d service URL is unreadable", destination.ID)
		}
	}
	return nil
}

// TestRekeyUpgradesLegacyEnvelopes downgrades every encrypted value to the
// unbound v1 format written by older releases, checks that those values
// remain readable (including through the startup key preflights), and asserts
// that rekey rewrites every value as a bound v2 envelope.
func TestRekeyUpgradesLegacyEnvelopes(t *testing.T) {
	ctx := context.Background()
	st, path, box, first, second := bindingFixture(t)
	values := storedEncryptedValues(first, second)
	for _, value := range values {
		var encoded string
		if err := st.db.QueryRowContext(ctx, value.query, value.args...).Scan(&encoded); err != nil {
			t.Fatalf("%s: %v", value.binding, err)
		}
		if !secret.IsCurrentEnvelope(encoded) {
			t.Fatalf("%s was not written as a v2 envelope: %.3s", value.binding, encoded)
		}
		plain, err := box.Open(value.binding, encoded)
		if err != nil {
			t.Fatalf("%s: %v", value.binding, err)
		}
		legacy, err := box.EncryptLegacy(plain)
		if err != nil {
			t.Fatal(err)
		}
		update := map[string]string{
			settingsBinding("oauth_secret_enc"):        "UPDATE settings SET oauth_secret_enc=? WHERE id=1",
			settingsBinding("mattermost_url_enc"):      "UPDATE settings SET mattermost_url_enc=? WHERE id=1",
			settingsBinding("webhook_secret_enc"):      "UPDATE settings SET webhook_secret_enc=? WHERE id=1",
			destinationBinding(first):                  "UPDATE notification_destinations SET service_url_enc=? WHERE id=?",
			destinationBinding(second):                 "UPDATE notification_destinations SET service_url_enc=? WHERE id=?",
			metaBinding(masterKeyCheckMeta):            "UPDATE meta SET value=? WHERE key=?",
			metaBinding(evidenceSigningPrivateKeyMeta): "UPDATE meta SET value=? WHERE key=?",
		}[value.binding]
		if _, err := st.db.ExecContext(ctx, update, append([]any{legacy}, value.args...)...); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatalf("reopen with legacy envelopes: %v", err)
	}
	defer func() { st.Close() }()
	if err := verifyLegacyMasterKey(st.db, box); err != nil {
		t.Fatalf("legacy preflight with v1 envelopes: %v", err)
	}
	loaded, err := st.Settings(ctx)
	if err != nil || loaded.OAuthClientSecret != "secret" || loaded.WebhookSecret != "webhook-secret" {
		t.Fatalf("legacy settings=%+v err=%v", loaded, err)
	}
	if list, err := st.ListDestinations(ctx); err != nil || len(list) != 3 {
		t.Fatalf("legacy destinations=%+v err=%v", list, err)
	}

	rotated, _ := secret.NewBox(bytes.Repeat([]byte{9}, 32))
	if err := st.Rekey(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		var encoded string
		if err := st.db.QueryRowContext(ctx, value.query, value.args...).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		if !secret.IsCurrentEnvelope(encoded) {
			t.Fatalf("rekey left %s as a legacy envelope", value.binding)
		}
		if _, err := rotated.Open(value.binding, encoded); err != nil {
			t.Fatalf("rekeyed %s does not open with its binding: %v", value.binding, err)
		}
	}
	if err := verifyLegacyMasterKey(st.db, rotated); err != nil {
		t.Fatalf("legacy preflight with v2 envelopes: %v", err)
	}
	if err := verifyLegacyMasterKey(st.db, box); err == nil {
		t.Fatal("legacy preflight accepted the previous key after rekey")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path, rotated)
	if err != nil {
		t.Fatalf("reopen after upgrade rekey: %v", err)
	}
	if list, err := st.ListDestinations(ctx); err != nil || len(list) != 3 {
		t.Fatalf("destinations after rekey=%+v err=%v", list, err)
	}
}

// TestSavingUnchangedLegacyValuesUpgradesThem keeps ciphertext reuse for
// unchanged values but never preserves an unbound v1 envelope.
func TestSavingUnchangedLegacyValuesUpgradesThem(t *testing.T) {
	ctx := context.Background()
	st, _, box, first, _ := bindingFixture(t)
	legacySecret, _ := box.EncryptLegacy("secret")
	legacyWebhook, _ := box.EncryptLegacy("webhook-secret")
	legacyURL, _ := box.EncryptLegacy("generic://a.example/hook")
	if _, err := st.db.ExecContext(ctx, "UPDATE settings SET oauth_secret_enc=?,webhook_secret_enc=? WHERE id=1", legacySecret, legacyWebhook); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc=? WHERE id=?", legacyURL, first); err != nil {
		t.Fatal(err)
	}
	input := settings()
	input.WebhookSecret = "webhook-secret"
	if _, err := st.SaveSettings(ctx, input); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{ID: first, Name: "a", ServiceURL: "generic://a.example/hook", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, value := range storedEncryptedValues(first, first)[:4] {
		if value.binding == settingsBinding("mattermost_url_enc") {
			continue
		}
		var encoded string
		if err := st.db.QueryRowContext(ctx, value.query, value.args...).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		if !secret.IsCurrentEnvelope(encoded) {
			t.Fatalf("%s kept a legacy envelope after save", value.binding)
		}
	}
}

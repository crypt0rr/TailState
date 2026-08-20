package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

func (s *Store) SaveSettings(ctx context.Context, in Settings) (int64, error) {
	if strings.TrimSpace(in.Tailnet) == "" {
		in.Tailnet = "-"
	}
	in.WebhookSecret = strings.TrimSpace(in.WebhookSecret)
	if len(in.WebhookSecret) > 1024 {
		return 0, errors.New("webhook secret is too long")
	}
	if in.OAuthClientID == "" || in.OAuthClientSecret == "" {
		return 0, errors.New("OAuth credentials are required")
	}
	if in.DeviceInterval < 15*time.Second || in.InventoryInterval < 30*time.Second {
		return 0, errors.New("poll intervals are too short")
	}
	secretEnc, err := s.box.Encrypt(in.OAuthClientSecret)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var oldTailnet, oldClient, oldSecretEnc, oldWebhookSecretEnc string
	var generation int64
	generationChanged := false
	settingsExists := true
	err = tx.QueryRowContext(ctx, "SELECT tailnet,oauth_client_id,oauth_secret_enc,COALESCE(webhook_secret_enc,''),generation FROM settings WHERE id=1").Scan(&oldTailnet, &oldClient, &oldSecretEnc, &oldWebhookSecretEnc, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		settingsExists = false
		generation = 1
	} else if err != nil {
		return 0, err
	} else {
		if _, decryptErr := s.box.Decrypt(oldSecretEnc); decryptErr != nil {
			return 0, decryptErr
		}
		if oldTailnet != in.Tailnet || oldClient != in.OAuthClientID {
			generation++
			generationChanged = true
		}
	}
	webhookSecretEnc := oldWebhookSecretEnc
	if in.ClearWebhookSecret {
		webhookSecretEnc = ""
	} else if in.WebhookSecret != "" {
		webhookSecretEnc, err = s.box.Encrypt(in.WebhookSecret)
		if err != nil {
			return 0, err
		}
	}
	legacyURLEnc := ""
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(mattermost_url_enc,'') FROM settings WHERE id=1").Scan(&legacyURLEnc); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if in.MattermostURL != "" {
		converted, convertErr := notify.ConvertLegacyMattermostURL(in.MattermostURL)
		if convertErr != nil {
			return 0, convertErr
		}
		legacyURLEnc, err = s.box.Encrypt(in.MattermostURL)
		if err != nil {
			return 0, err
		}
		var destinationID int64
		lookupErr := tx.QueryRowContext(ctx, "SELECT id FROM notification_destinations WHERE name=? AND deleted_at IS NULL ORDER BY id LIMIT 1", "Mattermost").Scan(&destinationID)
		if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
			return 0, lookupErr
		}
		if _, err := upsertDestinationTx(ctx, tx, s.box, destinationID, "Mattermost", converted, true); err != nil {
			return 0, err
		}
	}
	if in.MattermostURL == "" && !settingsExists {
		var enabled int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL").Scan(&enabled); err != nil {
			return 0, err
		}
		if enabled == 0 {
			return 0, errors.New("at least one enabled notification destination is required")
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO settings(id,tailnet,oauth_client_id,oauth_secret_enc,mattermost_url_enc,webhook_secret_enc,device_interval_seconds,inventory_interval_seconds,generation,configured_at,baseline_at)
	VALUES(1,?,?,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET tailnet=excluded.tailnet,oauth_client_id=excluded.oauth_client_id,oauth_secret_enc=excluded.oauth_secret_enc,mattermost_url_enc=CASE WHEN excluded.mattermost_url_enc='' THEN settings.mattermost_url_enc ELSE excluded.mattermost_url_enc END,webhook_secret_enc=CASE WHEN excluded.webhook_secret_enc='' THEN settings.webhook_secret_enc ELSE excluded.webhook_secret_enc END,device_interval_seconds=excluded.device_interval_seconds,inventory_interval_seconds=excluded.inventory_interval_seconds,generation=excluded.generation,configured_at=excluded.configured_at,baseline_at=CASE WHEN settings.generation=excluded.generation THEN settings.baseline_at ELSE NULL END`, in.Tailnet, in.OAuthClientID, secretEnc, legacyURLEnc, webhookSecretEnc, int64(in.DeviceInterval.Seconds()), int64(in.InventoryInterval.Seconds()), generation, now)
	if err != nil {
		return 0, err
	}
	if in.ClearWebhookSecret {
		if _, err := tx.ExecContext(ctx, "UPDATE settings SET webhook_secret_enc='' WHERE id=1"); err != nil {
			return 0, err
		}
	}
	if generationChanged {
		if _, err := tx.ExecContext(ctx, "DELETE FROM snapshots WHERE generation<>?", generation); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM collector_state WHERE generation<>?", generation); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return generation, nil
}

func (s *Store) Settings(ctx context.Context) (Settings, error) {
	var out Settings
	var secretEnc, urlEnc, webhookSecretEnc, configured, baseline string
	var device, inventory int64
	err := s.db.QueryRowContext(ctx, "SELECT tailnet,oauth_client_id,oauth_secret_enc,mattermost_url_enc,COALESCE(webhook_secret_enc,''),device_interval_seconds,inventory_interval_seconds,generation,configured_at,COALESCE(baseline_at,'') FROM settings WHERE id=1").Scan(&out.Tailnet, &out.OAuthClientID, &secretEnc, &urlEnc, &webhookSecretEnc, &device, &inventory, &out.Generation, &configured, &baseline)
	if err != nil {
		return Settings{}, err
	}
	out.OAuthClientSecret, err = s.box.Decrypt(secretEnc)
	if err != nil {
		return Settings{}, err
	}
	if urlEnc != "" {
		out.MattermostURL, err = s.box.Decrypt(urlEnc)
		if err != nil {
			return Settings{}, err
		}
	}
	if webhookSecretEnc != "" {
		out.WebhookSecret, err = s.box.Decrypt(webhookSecretEnc)
		if err != nil {
			return Settings{}, err
		}
	}
	out.DeviceInterval = time.Duration(device) * time.Second
	out.InventoryInterval = time.Duration(inventory) * time.Second
	out.Revision = configured
	out.ConfiguredAt, err = time.Parse(time.RFC3339Nano, configured)
	if err != nil {
		return Settings{}, fmt.Errorf("parse settings configured timestamp: %w", err)
	}
	if baseline != "" {
		t, parseErr := time.Parse(time.RFC3339Nano, baseline)
		if parseErr != nil {
			return Settings{}, fmt.Errorf("parse settings baseline timestamp: %w", parseErr)
		}
		out.BaselineAt = &t
	}
	return out, nil
}

func (s *Store) TrackAppVersion(ctx context.Context, current string, notification func(previous, current string) string) (bool, error) {
	current = strings.TrimSpace(current)
	if current == "" || current == "dev" {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='app_version'").Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES('app_version',?)", current); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if previous == current {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, "UPDATE meta SET value=? WHERE key='app_version'", current); err != nil {
		return false, err
	}
	var configured int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM settings").Scan(&configured); err != nil {
		return false, err
	}
	var enabledDestinations int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL").Scan(&enabledDestinations); err != nil {
		return false, err
	}
	notified := configured > 0 && enabledDestinations > 0
	if notified {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		payload := notification(previous, current)
		if err = enqueueOutboxTx(ctx, tx, payload, now, 0); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return notified, nil
}

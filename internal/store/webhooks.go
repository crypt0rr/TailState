package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/notify"
)

// WebhookSecret returns the decrypted Tailscale webhook secret only to the
// request verifier. It is never included in rendered settings data.
func (s *Store) WebhookSecret(ctx context.Context) (string, error) {
	var encrypted string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(webhook_secret_enc,'') FROM settings WHERE id=1").Scan(&encrypted); err != nil {
		return "", err
	}
	if encrypted == "" {
		return "", nil
	}
	return s.box.Decrypt(encrypted)
}

// RecordWebhookTrigger persists verified event metadata and returns whether
// this body hash was newly queued. A unique hash makes provider retries and
// accidental replay harmless while keeping the original body out of SQLite.
func (s *Store) RecordWebhookTrigger(ctx context.Context, bodyHash string, eventTypes, collectors []string) (WebhookTrigger, bool, error) {
	bodyHash = strings.TrimSpace(bodyHash)
	if len(bodyHash) != sha256HexLength {
		return WebhookTrigger{}, false, errors.New("invalid webhook body hash")
	}
	if _, err := hex.DecodeString(bodyHash); err != nil {
		return WebhookTrigger{}, false, errors.New("invalid webhook body hash")
	}
	for _, value := range append(append([]string(nil), eventTypes...), collectors...) {
		if len(value) > maxWebhookMetadataValueSize || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return WebhookTrigger{}, false, errors.New("webhook metadata contains an invalid value")
		}
	}
	eventTypes = sortedUnique(eventTypes)
	collectors = sortedUnique(collectors)
	if len(eventTypes) > maxWebhookEventTypes || len(collectors) > maxWebhookCollectors {
		return WebhookTrigger{}, false, errors.New("webhook metadata is too large")
	}
	eventJSON, err := json.Marshal(eventTypes)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	collectorJSON, err := json.Marshal(collectors)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO webhook_triggers(body_hash,received_at,event_types_json,collectors_json,status,next_attempt_at) VALUES(?,?,?,?, 'pending',?) ON CONFLICT(body_hash) DO NOTHING`, bodyHash, nowValue, eventJSON, collectorJSON, nowValue)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	created := false
	affected, affectedErr := result.RowsAffected()
	if affectedErr != nil {
		return WebhookTrigger{}, false, affectedErr
	}
	created = affected == 1
	trigger, err := readWebhookTrigger(tx.QueryRowContext(ctx, webhookTriggerSelect+" WHERE body_hash=?", bodyHash))
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return WebhookTrigger{}, false, err
	}
	return trigger, created, nil
}

const (
	sha256HexLength             = sha256.Size * 2
	maxWebhookEventTypes        = 100
	maxWebhookCollectors        = 32
	maxWebhookMetadataValueSize = 128
	maxWebhookMetadataJSONBytes = 16 << 10
	webhookTriggerSelect        = `SELECT id,body_hash,received_at,event_types_json,collectors_json,status,attempts,next_attempt_at,COALESCE(lease_until,''),COALESCE(lease_token,''),last_error,COALESCE(processed_at,'') FROM webhook_triggers`
)

type webhookTriggerScanner interface {
	Scan(dest ...any) error
}

func readWebhookTrigger(scanner webhookTriggerScanner) (WebhookTrigger, error) {
	var trigger WebhookTrigger
	var received, eventRaw, collectorRaw, nextAttempt, leaseUntil, processed string
	var err error
	if err := scanner.Scan(&trigger.ID, &trigger.BodyHash, &received, &eventRaw, &collectorRaw, &trigger.Status, &trigger.Attempts, &nextAttempt, &leaseUntil, &trigger.LeaseToken, &trigger.LastError, &processed); err != nil {
		return WebhookTrigger{}, err
	}
	if strings.TrimSpace(trigger.LastError) != "" {
		// Legacy rows may predate the retry persistence boundary or have been
		// edited outside the service. Keep arbitrary provider text out of every
		// monitor/API projection as well as out of newly written rows.
		trigger.LastError = notify.SafeDeliveryMessage(trigger.LastError)
	}
	trigger.ReceivedAt, err = parseWebhookTimestamp(received, "received_at")
	if err != nil {
		return WebhookTrigger{}, err
	}
	trigger.NextAttempt, err = parseWebhookTimestamp(nextAttempt, "next_attempt_at")
	if err != nil {
		return WebhookTrigger{}, err
	}
	if value, parseErr := parseWebhookOptionalTimestamp(leaseUntil, "lease_until"); parseErr != nil {
		return WebhookTrigger{}, parseErr
	} else {
		trigger.LeaseUntil = value
	}
	if value, parseErr := parseWebhookOptionalTimestamp(processed, "processed_at"); parseErr != nil {
		return WebhookTrigger{}, parseErr
	} else {
		trigger.ProcessedAt = value
	}
	trigger.EventTypes, err = decodeWebhookMetadata([]byte(eventRaw), "event", maxWebhookEventTypes)
	if err != nil {
		return WebhookTrigger{}, fmt.Errorf("decode webhook event metadata: %w", err)
	}
	trigger.Collectors, err = decodeWebhookMetadata([]byte(collectorRaw), "collector", maxWebhookCollectors)
	if err != nil {
		return WebhookTrigger{}, fmt.Errorf("decode webhook collector metadata: %w", err)
	}
	return trigger, nil
}

// decodeWebhookMetadata validates metadata read from SQLite before it enters
// the monitor. Rows are normally produced by RecordWebhookTrigger, but a
// damaged or hand-edited database must not be able to inject control characters,
// oversized arrays, or an unexpectedly large JSON value into a reconciliation
// request. The bounded byte check also keeps malformed rows from forcing a
// large allocation during startup or queue recovery.
func decodeWebhookMetadata(raw []byte, kind string, maxValues int) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxWebhookMetadataJSONBytes {
		return nil, fmt.Errorf("%s metadata JSON is empty or too large", kind)
	}
	if trimmed[0] != '[' {
		return nil, fmt.Errorf("%s metadata must be a JSON array", kind)
	}
	var values []string
	if err := json.Unmarshal(trimmed, &values); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, fmt.Errorf("%s metadata must be a JSON array", kind)
	}
	for _, value := range values {
		if len(value) > maxWebhookMetadataValueSize || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%s metadata contains an invalid value", kind)
		}
	}
	values = sortedUnique(values)
	if len(values) > maxValues {
		return nil, fmt.Errorf("%s metadata contains too many values", kind)
	}
	return values, nil
}

func parseWebhookTimestamp(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse webhook %s timestamp: %w", field, err)
	}
	return parsed, nil
}

func parseWebhookOptionalTimestamp(value, field string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := parseWebhookTimestamp(value, field)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// ClaimWebhookTrigger atomically leases one durable trigger for the fast
// in-memory reconciliation path. A durable queue worker may race this call;
// only the path that changes the row from pending to processing owns the
// trigger and may later complete or retry it.
func (s *Store) ClaimWebhookTrigger(ctx context.Context, id int64, lease time.Duration) (WebhookTrigger, bool, error) {
	if id <= 0 {
		return WebhookTrigger{}, false, nil
	}
	if lease < time.Second {
		lease = webhookTriggerLease
	}
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	deadline := now.Add(-webhookTriggerRetryWindow).Format(time.RFC3339Nano)
	leaseValue := now.Add(lease).Format(time.RFC3339Nano)
	leaseToken, err := newWebhookLeaseToken()
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_triggers
		SET status='pending',lease_until=NULL,lease_token=''
		WHERE id=? AND status='processing' AND (lease_until IS NULL OR lease_until<=?)`, id, nowValue); err != nil {
		return WebhookTrigger{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_triggers
		SET status='dead',lease_until=NULL,lease_token='',last_error='reconciliation retry window expired'
		WHERE id=? AND status IN ('pending','processing') AND received_at<=?
			AND (status='pending' OR lease_until IS NULL OR lease_until<=?)`, id, deadline, nowValue); err != nil {
		return WebhookTrigger{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webhook_triggers
		SET status='processing',attempts=attempts+1,lease_until=?,lease_token=?
		WHERE id=? AND status='pending' AND next_attempt_at<=?`, leaseValue, leaseToken, id, nowValue)
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	if changed == 0 {
		if err := tx.Commit(); err != nil {
			return WebhookTrigger{}, false, err
		}
		return WebhookTrigger{}, false, nil
	}
	trigger, err := readWebhookTrigger(tx.QueryRowContext(ctx, webhookTriggerSelect+" WHERE id=?", id))
	if err != nil {
		return WebhookTrigger{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return WebhookTrigger{}, false, err
	}
	trigger.Status = "processing"
	trigger.LeaseToken = leaseToken
	return trigger, true, nil
}

// ClaimWebhookTriggers leases queued triggers for one reconciliation worker.
// Expired leases are returned to the queue, while triggers older than the
// retry horizon become dead letters instead of being retried forever.
func (s *Store) ClaimWebhookTriggers(ctx context.Context, limit int, lease time.Duration) ([]WebhookTrigger, error) {
	if limit <= 0 {
		limit = webhookTriggerBatchSize
	}
	if limit > 64 {
		limit = 64
	}
	if lease < time.Second {
		lease = webhookTriggerLease
	}
	now := time.Now().UTC()
	nowValue := now.Format(time.RFC3339Nano)
	deadline := now.Add(-webhookTriggerRetryWindow).Format(time.RFC3339Nano)
	leaseValue := now.Add(lease).Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_triggers SET status='pending',lease_until=NULL,lease_token='' WHERE status='processing' AND (lease_until IS NULL OR lease_until<=?)`, nowValue); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_triggers SET status='dead',lease_until=NULL,lease_token='',last_error='reconciliation retry window expired' WHERE status IN ('pending','processing') AND received_at<=? AND (status='pending' OR lease_until IS NULL OR lease_until<=?)`, deadline, nowValue); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, webhookTriggerSelect+` WHERE status='pending' AND next_attempt_at<=? ORDER BY id LIMIT ?`, nowValue, limit)
	if err != nil {
		return nil, err
	}
	triggers := make([]WebhookTrigger, 0, limit)
	for rows.Next() {
		trigger, scanErr := readWebhookTrigger(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		triggers = append(triggers, trigger)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range triggers {
		leaseToken, err := newWebhookLeaseToken()
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status='processing',attempts=attempts+1,lease_until=?,lease_token=? WHERE id=? AND status='pending'", leaseValue, leaseToken, triggers[i].ID); err != nil {
			return nil, err
		}
		triggers[i].Status = "processing"
		triggers[i].LeaseToken = leaseToken
		triggers[i].Attempts++
		value := now.Add(lease)
		triggers[i].LeaseUntil = &value
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return triggers, nil
}

// HasDueWebhookTriggers is a read-only safety-net probe. It lets the monitor
// avoid opening the claim transaction when no trigger can be progressed. The
// received-at horizon is included for pending rows so an old trigger with a
// future retry timestamp is still noticed and dead-lettered by
// ClaimWebhookTriggers. A processing row remains invisible while its lease is
// active; reporting it as due would wake the durable worker repeatedly even
// though lease fencing correctly prevents a claim. This does not depend on the
// current webhook secret: a trigger accepted before the secret was cleared
// must remain durable and recoverable after a restart.
func (s *Store) HasDueWebhookTriggers(ctx context.Context, now time.Time) (bool, error) {
	nowValue := now.UTC().Format(time.RFC3339Nano)
	deadline := now.UTC().Add(-webhookTriggerRetryWindow).Format(time.RFC3339Nano)
	var due int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM webhook_triggers
		WHERE (status='pending' AND (next_attempt_at<=? OR received_at<=?))
		   OR (status='processing' AND (lease_until IS NULL OR lease_until<=?))
	)`, nowValue, deadline, nowValue).Scan(&due)
	return due == 1, err
}

// CompleteClaimedWebhookTriggers finalizes only the exact processing claims
// returned by ClaimWebhookTrigger(s). The lease token fences an expired worker
// from completing a newer attempt for the same durable trigger.
func (s *Store) CompleteClaimedWebhookTriggers(ctx context.Context, claims []WebhookTrigger) error {
	claims = validWebhookClaims(claims)
	if len(claims) == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, claim := range claims {
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status='processed',processed_at=?,lease_until=NULL,lease_token='',last_error='' WHERE id=? AND status='processing' AND lease_token=?", now, claim.ID, claim.LeaseToken); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RetryClaimedWebhookTriggers requeues only the exact processing claims that
// failed. A worker whose lease expired cannot move a newer attempt backward.
func (s *Store) RetryClaimedWebhookTriggers(ctx context.Context, claims []WebhookTrigger, next time.Time, message string) error {
	claims = validWebhookClaims(claims)
	if len(claims) == 0 {
		return nil
	}
	message = truncate(strings.TrimSpace(message), 500)
	if message != "" {
		message = notify.SafeDeliveryMessage(message)
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, claim := range claims {
		var received string
		if err := tx.QueryRowContext(ctx, "SELECT received_at FROM webhook_triggers WHERE id=?", claim.ID).Scan(&received); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
		receivedAt, parseErr := parseWebhookTimestamp(received, "received_at")
		if parseErr != nil {
			return parseErr
		}
		dead := now.Sub(receivedAt) >= webhookTriggerRetryWindow
		status := "pending"
		attempt := next.UTC()
		lastError := message
		if dead {
			status = "dead"
			attempt = now
			if lastError == "" {
				lastError = "reconciliation retry window expired"
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_triggers SET status=?,next_attempt_at=?,lease_until=NULL,lease_token='',last_error=? WHERE id=? AND status='processing' AND lease_token=?", status, attempt.Format(time.RFC3339Nano), lastError, claim.ID, claim.LeaseToken); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validWebhookClaims(claims []WebhookTrigger) []WebhookTrigger {
	valid := make([]WebhookTrigger, 0, len(claims))
	seen := make(map[int64]struct{}, len(claims))
	for _, claim := range claims {
		if claim.ID <= 0 || strings.TrimSpace(claim.LeaseToken) == "" {
			continue
		}
		if _, exists := seen[claim.ID]; exists {
			continue
		}
		seen[claim.ID] = struct{}{}
		valid = append(valid, claim)
	}
	return valid
}

func newWebhookLeaseToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate webhook lease token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func uniquePositiveIDs(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	for _, value := range values {
		if value > 0 {
			seen[value] = struct{}{}
		}
	}
	out := make([]int64, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

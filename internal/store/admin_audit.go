package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

// AdminAuditRetention is how long administrative audit records are kept.
// Retention cleanup removes older records in bounded batches.
const AdminAuditRetention = 365 * 24 * time.Hour

// Administrative audit events. The vocabulary is fixed so a record can never
// carry free-form (and therefore possibly secret) text.
const (
	AuditLoginSuccess        = "login_success"
	AuditLoginFailure        = "login_failure"
	AuditLogout              = "logout"
	AuditSetupClaim          = "setup_claim"
	AuditPasswordReset       = "password_reset"
	AuditPasswordChanged     = "password_changed"
	AuditSessionsRevoked     = "sessions_revoked"
	AuditSettingsChanged     = "settings_changed"
	AuditDestinationAdded    = "destination_added"
	AuditDestinationEdited   = "destination_edited"
	AuditDestinationEnabled  = "destination_enabled"
	AuditDestinationDisabled = "destination_disabled"
	AuditDestinationDeleted  = "destination_deleted"
	AuditMuteAdded           = "mute_added"
	AuditMuteRemoved         = "mute_removed"
	AuditReconcileRequested  = "reconcile_requested"
	AuditDeadLettersRetried  = "dead_letters_retried"
	AuditAPITokenCreated     = "api_token_created"
	AuditAPITokenRevoked     = "api_token_revoked"
)

// Audit outcomes.
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
)

var adminAuditLabels = map[string]string{
	AuditLoginSuccess:        "Signed in",
	AuditLoginFailure:        "Sign-in failed",
	AuditLogout:              "Signed out",
	AuditSetupClaim:          "Installation claimed",
	AuditPasswordReset:       "Password reset with a reset token",
	AuditPasswordChanged:     "Password changed",
	AuditSessionsRevoked:     "Other sessions signed out",
	AuditSettingsChanged:     "Monitoring settings changed",
	AuditDestinationAdded:    "Notification destination added",
	AuditDestinationEdited:   "Notification destination edited",
	AuditDestinationEnabled:  "Notification destination enabled",
	AuditDestinationDisabled: "Notification destination disabled",
	AuditDestinationDeleted:  "Notification destination removed",
	AuditMuteAdded:           "Mute rule added",
	AuditMuteRemoved:         "Mute rule removed",
	AuditReconcileRequested:  "Reconciliation requested",
	AuditDeadLettersRetried:  "Dead-lettered notifications retried",
	AuditAPITokenCreated:     "API token created",
	AuditAPITokenRevoked:     "API token revoked",
}

// AdminAuditLabel returns the human-readable description of an event.
func AdminAuditLabel(event string) string {
	if label, ok := adminAuditLabels[event]; ok {
		return label
	}
	return event
}

const (
	maxAdminAuditFields = 16
	maxAdminAuditList   = 200
)

var (
	// Field names and targets are identifiers chosen by TailState, never
	// user input; the patterns make it structurally impossible to store a
	// value such as a URL, secret, or name in either column.
	adminAuditFieldPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	adminAuditTargetPattern = regexp.MustCompile(`^[a-z_]{1,32}:[0-9]{1,19}$`)
	adminAuditRefPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{0,16}$`)
)

// ErrInvalidAdminAudit reports an audit entry outside the fixed vocabulary.
var ErrInvalidAdminAudit = errors.New("invalid administrative audit entry")

// AdminAuditEntry is one administrative action. Fields lists the names of
// changed settings (never their values); Target names the affected object
// as kind:id; SessionRef is SessionRef of the acting session.
type AdminAuditEntry struct {
	ID         int64
	At         time.Time
	Event      string
	Outcome    string
	ClientIP   string
	SessionRef string
	Target     string
	Fields     []string
}

// Label returns the human-readable description of the entry's event.
func (e AdminAuditEntry) Label() string { return AdminAuditLabel(e.Event) }

// AdminNotice is a system notification sent with an audit record to the
// listed destinations (those enabled before the change, minus any already
// notified directly). Destinations that are no longer enabled are skipped.
type AdminNotice struct {
	Message    notify.Message
	Recipients []int64
}

func normalizeAdminAuditEntry(entry AdminAuditEntry) (AdminAuditEntry, error) {
	if _, ok := adminAuditLabels[entry.Event]; !ok {
		return entry, fmt.Errorf("%w: unknown event %q", ErrInvalidAdminAudit, entry.Event)
	}
	if entry.Outcome == "" {
		entry.Outcome = AuditSuccess
	}
	if entry.Outcome != AuditSuccess && entry.Outcome != AuditFailure {
		return entry, fmt.Errorf("%w: unknown outcome", ErrInvalidAdminAudit)
	}
	if entry.ClientIP != "" {
		addr, err := netip.ParseAddr(entry.ClientIP)
		if err != nil {
			return entry, fmt.Errorf("%w: client address", ErrInvalidAdminAudit)
		}
		entry.ClientIP = addr.Unmap().WithZone("").String()
	}
	if !adminAuditRefPattern.MatchString(entry.SessionRef) {
		return entry, fmt.Errorf("%w: session reference", ErrInvalidAdminAudit)
	}
	if entry.Target != "" && !adminAuditTargetPattern.MatchString(entry.Target) {
		return entry, fmt.Errorf("%w: target", ErrInvalidAdminAudit)
	}
	if len(entry.Fields) > maxAdminAuditFields {
		return entry, fmt.Errorf("%w: too many fields", ErrInvalidAdminAudit)
	}
	seen := map[string]bool{}
	fields := make([]string, 0, len(entry.Fields))
	for _, field := range entry.Fields {
		if !adminAuditFieldPattern.MatchString(field) {
			return entry, fmt.Errorf("%w: field name", ErrInvalidAdminAudit)
		}
		if !seen[field] {
			seen[field] = true
			fields = append(fields, field)
		}
	}
	sort.Strings(fields)
	entry.Fields = fields
	return entry, nil
}

// RecordAdminAudit stores one audit record and, when notice is set, queues
// its notification for the notice's recipients in the same transaction, so a
// committed change is never left without both. Every record is also logged as
// a structured "administrative action" line for SIEM collection.
func (s *Store) RecordAdminAudit(ctx context.Context, entry AdminAuditEntry, notice *AdminNotice) (AdminAuditEntry, error) {
	entry, err := normalizeAdminAuditEntry(entry)
	if err != nil {
		return entry, err
	}
	entry.At = time.Now().UTC()
	now := entry.At.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return entry, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO admin_audit(created_at,event,outcome,client_ip,session_ref,target,fields) VALUES(?,?,?,?,?,?,?)", now, entry.Event, entry.Outcome, entry.ClientIP, entry.SessionRef, entry.Target, strings.Join(entry.Fields, ","))
	if err != nil {
		return entry, err
	}
	if entry.ID, err = result.LastInsertId(); err != nil {
		return entry, err
	}
	if notice != nil && len(notice.Recipients) > 0 {
		payloadFormat, payload, err := notify.EncodePayload(notice.Message)
		if err != nil {
			return entry, err
		}
		if err := enqueueOutboxForTx(ctx, tx, payloadFormat, payload, now, notice.Recipients); err != nil {
			return entry, err
		}
	}
	if err := tx.Commit(); err != nil {
		return entry, err
	}
	slog.Info("administrative action", "event", entry.Event, "outcome", entry.Outcome, "client_ip", entry.ClientIP, "session", entry.SessionRef, "target", entry.Target, "fields", strings.Join(entry.Fields, ","), "audit_id", entry.ID)
	return entry, nil
}

// enqueueOutboxForTx queues a system notification for each listed
// destination that is still enabled. It is the targeted counterpart of
// enqueueOutboxTx, which addresses every enabled destination.
func enqueueOutboxForTx(ctx context.Context, tx *sql.Tx, payloadFormat, payload, now string, destinations []int64) error {
	seen := map[int64]bool{}
	for _, id := range destinations {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbox(batch_id,destination_id,payload,payload_format,status,next_attempt,first_attempt,created_at)
			SELECT NULL,id,?,?,'pending',?,?,? FROM notification_destinations WHERE id=? AND enabled=1 AND deleted_at IS NULL`, payload, payloadFormat, now, now, now, id); err != nil {
			return err
		}
	}
	return nil
}

// RecentAdminAudit returns the newest audit records, newest first.
func (s *Store) RecentAdminAudit(ctx context.Context, limit int) ([]AdminAuditEntry, error) {
	if limit <= 0 || limit > maxAdminAuditList {
		limit = maxAdminAuditList
	}
	// A pure read: it uses the read-only pool and never waits behind a write.
	rows, err := s.readDB().QueryContext(ctx, "SELECT id,created_at,event,outcome,client_ip,session_ref,target,fields FROM admin_audit ORDER BY created_at DESC,id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminAuditEntry
	for rows.Next() {
		var entry AdminAuditEntry
		var at, fields string
		if err := rows.Scan(&entry.ID, &at, &entry.Event, &entry.Outcome, &entry.ClientIP, &entry.SessionRef, &entry.Target, &fields); err != nil {
			return nil, err
		}
		if entry.At, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, fmt.Errorf("parse audit timestamp: %w", err)
		}
		if fields != "" {
			entry.Fields = strings.Split(fields, ",")
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

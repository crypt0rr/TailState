package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

// TestAdminAuditAcceptsIdentifiersOnly guards E-011: the audit record can
// only hold the fixed event vocabulary, identifier-shaped field names and
// targets, an IP address, and a session reference, so a value (URL, secret,
// name) can never be persisted by mistake.
func TestAdminAuditAcceptsIdentifiersOnly(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for name, entry := range map[string]AdminAuditEntry{
		"unknown event":   {Event: "something_else"},
		"unknown outcome": {Event: AuditLoginFailure, Outcome: "maybe"},
		"url as field":    {Event: AuditSettingsChanged, Fields: []string{"https://hooks.example/secret"}},
		"value as field":  {Event: AuditSettingsChanged, Fields: []string{"Secret Value"}},
		"too many fields": {Event: AuditSettingsChanged, Fields: strings.Split(strings.Repeat("a,", 17)+"a", ",")},
		"name as target":  {Event: AuditDestinationEdited, Target: "destination:Primary"},
		"client":          {Event: AuditLoginSuccess, ClientIP: "attacker.example"},
		"session":         {Event: AuditLoginSuccess, SessionRef: "this session reference is far too long"},
	} {
		if _, err := st.RecordAdminAudit(ctx, entry, nil); !errors.Is(err, ErrInvalidAdminAudit) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	entry, err := st.RecordAdminAudit(ctx, AdminAuditEntry{Event: AuditSettingsChanged, ClientIP: "::ffff:192.0.2.7", SessionRef: "abc_DEF-123", Target: "destination:7", Fields: []string{"tailnet", "oauth_client_id", "tailnet"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID == 0 || entry.Outcome != AuditSuccess || entry.ClientIP != "192.0.2.7" || strings.Join(entry.Fields, ",") != "oauth_client_id,tailnet" {
		t.Fatalf("entry not normalized: %+v", entry)
	}
	entries, err := st.RecentAdminAudit(ctx, 0)
	if err != nil || len(entries) != 1 || entries[0].Label() != "Monitoring settings changed" || strings.Join(entries[0].Fields, ",") != "oauth_client_id,tailnet" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	if AdminAuditLabel("unknown") != "unknown" {
		t.Fatal("unknown event label")
	}
}

// TestAdminAuditNoticeIsQueuedAtomicallyForListedDestinations guards E-011:
// the notice is queued in the audit record's transaction, only for the
// listed destinations that are still enabled, once each, and as a system
// notification (no batch) that an identity change does not dead-letter.
func TestAdminAuditNoticeIsQueuedAtomicallyForListedDestinations(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	first, err := st.SaveDestination(ctx, NotificationDestination{Name: "First", ServiceURL: "mattermost://TailState@example.invalid/a", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := st.SaveDestination(ctx, NotificationDestination{Name: "Second", ServiceURL: "mattermost://TailState@example.invalid/b", Enabled: true})
	disabled, _ := st.SaveDestination(ctx, NotificationDestination{Name: "Disabled", ServiceURL: "mattermost://TailState@example.invalid/c", Enabled: false})
	message := notify.Context{}.AdminChange("Monitoring settings changed", []string{"oauth_client_id"}, "", "192.0.2.1", time.Now())
	if _, err := st.RecordAdminAudit(ctx, AdminAuditEntry{Event: AuditSettingsChanged, Fields: []string{"oauth_client_id"}}, &AdminNotice{Message: message, Recipients: []int64{first, disabled, first, 0}}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.db.Query("SELECT destination_id,COALESCE(batch_id,0),payload_format FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for rows.Next() {
		var id, batch int64
		var format string
		if err := rows.Scan(&id, &batch, &format); err != nil {
			t.Fatal(err)
		}
		if batch != 0 || format != notify.PayloadMessage {
			t.Fatalf("notice queued as batch %d format %q", batch, format)
		}
		got = append(got, id)
	}
	rows.Close()
	if len(got) != 1 || got[0] != first {
		t.Fatalf("notice recipients=%v want only %d (second=%d is not listed)", got, first, second)
	}

	// A failing insert rolls back the audit record together with the notice.
	if _, err := st.db.Exec("CREATE TRIGGER fail_notice BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'outbox unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	before, _ := st.RecentAdminAudit(ctx, 10)
	if _, err := st.RecordAdminAudit(ctx, AdminAuditEntry{Event: AuditPasswordChanged}, &AdminNotice{Message: message, Recipients: []int64{second}}); err == nil {
		t.Fatal("notice failure was not reported")
	}
	if after, _ := st.RecentAdminAudit(ctx, 10); len(after) != len(before) {
		t.Fatal("audit record committed without its notice")
	}
	if _, err := st.RecordAdminAudit(ctx, AdminAuditEntry{Event: AuditPasswordChanged}, &AdminNotice{Message: notify.Message{Text: "pre-rendered"}, Recipients: []int64{second}}); err == nil {
		t.Fatal("text notice failure was not reported")
	}
}

// TestAdminAuditRetentionKeepsAYear guards E-011's documented retention:
// records older than AdminAuditRetention are removed by the bounded cleanup,
// independently of (and longer than) the 30-day history retention.
func TestAdminAuditRetentionKeepsAYear(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, age := range []time.Duration{AdminAuditRetention + time.Hour, AdminAuditRetention + 2*time.Hour, AdminAuditRetention - time.Hour, 40 * 24 * time.Hour} {
		if _, err := st.db.Exec("INSERT INTO admin_audit(created_at,event) VALUES(?,?)", now.Add(-age).Format(time.RFC3339Nano), AuditLoginSuccess); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.CleanupWithOptions(ctx, CleanupOptions{Retention: 30 * 24 * time.Hour, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if stats.AdminAuditDeleted != 2 || stats.TotalRowsChanged() < 2 {
		t.Fatalf("cleanup stats %+v", stats)
	}
	entries, err := st.RecentAdminAudit(ctx, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("records within the retention period were removed: %+v %v", entries, err)
	}
}

func TestAdminAuditStorageErrors(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.db.Exec("INSERT INTO admin_audit(created_at,event) VALUES('not-a-time','login_success')"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecentAdminAudit(ctx, 5); err == nil {
		t.Fatal("malformed audit timestamp accepted")
	}
	st.Close()
	if _, err := st.RecordAdminAudit(ctx, AdminAuditEntry{Event: AuditLogout}, nil); err == nil {
		t.Fatal("RecordAdminAudit succeeded on a closed store")
	}
	if _, err := st.RecentAdminAudit(ctx, 5); err == nil {
		t.Fatal("RecentAdminAudit succeeded on a closed store")
	}
}

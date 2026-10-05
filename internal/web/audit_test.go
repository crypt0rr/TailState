package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/store"
)

// recordingSender stands in for Shoutrrr in administrative notice tests. It
// records each direct notice together with whether the destination was still
// enabled (and still had its URL) at the moment it was sent.
type recordingSender struct {
	mu    sync.Mutex
	st    *store.Store
	fail  bool
	sends []recordedNotice
}

type recordedNotice struct {
	url, message   string
	stillEnabled   bool
	destinationIDs []int64
}

func (r *recordingSender) Send(ctx context.Context, serviceURL, message string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	notice := recordedNotice{url: serviceURL, message: message}
	if r.st != nil {
		destinations, _ := r.st.ListDestinations(ctx)
		for _, destination := range destinations {
			if destination.ServiceURL == serviceURL && destination.Enabled {
				notice.stillEnabled = true
				notice.destinationIDs = append(notice.destinationIDs, destination.ID)
			}
		}
	}
	r.sends = append(r.sends, notice)
	if r.fail {
		return errors.New("provider unavailable")
	}
	return nil
}

func (r *recordingSender) Test(context.Context, string) error { return nil }

func (r *recordingSender) notices() []recordedNotice {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedNotice(nil), r.sends...)
}

// auditServer is a configured-for-testing server with a mock Tailscale API,
// a recording notice sender, and a signed-in administrator.
type auditFixture struct {
	server  *Server
	st      *store.Store
	db      *sql.DB
	sender  *recordingSender
	cookies []*http.Cookie
	csrf    string
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	server, st, db, token := accountServer(t, boot.Config{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/devices", "/api/v2/tailnet/other.example/devices":
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	server.config.TailscaleBase = api.URL + "/api/v2"
	server.config.OAuthTokenURL = api.URL + "/oauth/token"
	sender := &recordingSender{st: st}
	server.noticeSender = sender
	cookies := sessionOnly(claimCoverageAdmin(t, server, token))
	return &auditFixture{server: server, st: st, db: db, sender: sender, cookies: cookies, csrf: csrfFrom(t, cookies)}
}

func (f *auditFixture) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("_csrf", f.csrf)
	return coveragePost(t, f.server, path, form, f.cookies)
}

func (f *auditFixture) addDestination(t *testing.T, name, serviceURL string) int64 {
	t.Helper()
	response := f.post(t, "/settings/destinations", url.Values{"action": {"save"}, "name": {name}, "service_url": {serviceURL}, "enabled": {"on"}})
	if response.Code != http.StatusSeeOther {
		t.Fatalf("add destination %d: %s", response.Code, response.Body.String())
	}
	destinations, err := f.st.ListDestinations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return destinations[len(destinations)-1].ID
}

func (f *auditFixture) audit(t *testing.T) []store.AdminAuditEntry {
	t.Helper()
	entries, err := f.st.RecentAdminAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// adminNotices returns the queued administrative notices by destination.
func (f *auditFixture) adminNotices(t *testing.T) map[int64][]string {
	t.Helper()
	rows, err := f.db.Query("SELECT destination_id,status FROM outbox WHERE batch_id IS NULL AND payload LIKE '%TailState configuration changed%' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var status string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		out[id] = append(out[id], status)
	}
	return out
}

func (f *auditFixture) clearNotices(t *testing.T) {
	t.Helper()
	if _, err := f.db.Exec("DELETE FROM outbox"); err != nil {
		t.Fatal(err)
	}
}

const (
	auditDestinationSecret = "hook-credential-0123456789"
	auditOAuthSecret       = "oauth-secret-value-abcdef"
	auditWebhookSecret     = "webhook-secret-value-ghijk"
)

func auditDestinationURL(suffix string) string {
	return "mattermost://TailState@example.invalid/" + auditDestinationSecret + suffix + "?disabletls=true"
}

func settingsForm(clientID, secret, webhookSecret, device string) url.Values {
	return url.Values{"tailnet": {"-"}, "client_id": {clientID}, "client_secret": {secret}, "webhook_secret": {webhookSecret}, "device_interval": {device}, "inventory_interval": {"300"}}
}

// TestEveryAdministrativeActionIsAuditedOnceWithoutSecrets guards E-011:
// each listed action produces exactly one audit record with the field names
// it changed, and neither the records nor the structured log lines contain a
// secret, URL, or password.
func TestEveryAdministrativeActionIsAuditedOnceWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	f := newAuditFixture(t)
	seen := len(f.audit(t))
	if seen != 1 || f.audit(t)[0].Event != store.AuditSetupClaim || f.audit(t)[0].SessionRef != store.SessionRef(sessionFrom(t, f.cookies)) {
		t.Fatalf("setup claim not audited with its session: %+v", f.audit(t))
	}
	expect := func(step, event string, fields ...string) store.AdminAuditEntry {
		t.Helper()
		entries := f.audit(t)
		if len(entries) != seen+1 {
			t.Fatalf("%s: %d new audit records, want exactly 1: %+v", step, len(entries)-seen, entries[:len(entries)-seen])
		}
		seen = len(entries)
		latest := entries[0]
		if latest.Event != event || strings.Join(latest.Fields, ",") != strings.Join(fields, ",") {
			t.Fatalf("%s: audit %s %v, want %s %v", step, latest.Event, latest.Fields, event, fields)
		}
		if latest.ClientIP != "192.0.2.1" {
			t.Fatalf("%s: client address %q", step, latest.ClientIP)
		}
		return latest
	}

	id := f.addDestination(t, "Primary", auditDestinationURL("a"))
	if entry := expect("add destination", store.AuditDestinationAdded, "enabled", "name", "service_url"); entry.Target != destinationTarget(id) {
		t.Fatalf("destination target %q", entry.Target)
	}
	if response := f.post(t, "/settings", settingsForm("client", auditOAuthSecret, "", "60")); response.Code != http.StatusSeeOther {
		t.Fatalf("initial settings %d: %s", response.Code, response.Body.String())
	}
	// The first save records every setting it establishes.
	expect("initial settings", store.AuditSettingsChanged, "device_interval", "expiry_tag_filter", "expiry_warning_days", "inventory_interval", "oauth_client_id", "oauth_client_secret", "oauth_scopes", "tailnet")
	if response := f.post(t, "/settings", settingsForm("client", auditOAuthSecret+"-rotated", auditWebhookSecret, "90")); response.Code != http.StatusSeeOther {
		t.Fatalf("settings update %d", response.Code)
	}
	expect("rotate secret", store.AuditSettingsChanged, "device_interval", "oauth_client_secret", "webhook_secret")
	if response := f.post(t, "/settings", settingsForm("client", "", "", "90")); response.Code != http.StatusSeeOther {
		t.Fatalf("unchanged settings %d", response.Code)
	}
	if len(f.audit(t)) != seen {
		t.Fatal("a save that changed nothing was audited")
	}
	clear := settingsForm("client", "", "", "90")
	clear.Set("clear_webhook_secret", "on")
	f.post(t, "/settings", clear)
	expect("clear webhook secret", store.AuditSettingsChanged, "webhook_secret_cleared")
	// Expiry warning and OAuth scope options are audited by name. Restating
	// the defaults in a different order or spelling changes nothing.
	options := settingsForm("client", "", "", "90")
	options.Set("expiry_warning_days", "30, 3")
	options.Set("expiry_tag_filter", "tag:server")
	f.post(t, "/settings", options)
	expect("expiry settings", store.AuditSettingsChanged, "expiry_tag_filter", "expiry_warning_days")
	options.Set("oauth_scopes", "devices:core:read")
	f.post(t, "/settings", options)
	expect("OAuth scopes", store.AuditSettingsChanged, "oauth_scopes")
	options.Set("expiry_warning_days", "3 30 3")
	f.post(t, "/settings", options)
	if len(f.audit(t)) != seen {
		t.Fatal("restating the same options in another order was audited")
	}

	idText := strconv.FormatInt(id, 10)
	f.post(t, "/settings/destinations", url.Values{"action": {"save"}, "id": {idText}, "name": {"Renamed"}, "service_url": {""}, "enabled": {"on"}})
	expect("rename destination", store.AuditDestinationEdited, "name")
	f.post(t, "/settings/destinations", url.Values{"action": {"save"}, "id": {idText}, "name": {"Renamed"}, "enabled": {"on"}, "routing": {"1"}, "min_severity": {"high"}, "message_format": {"plain"}})
	expect("routing change", store.AuditDestinationEdited, "message_format", "routing")
	f.post(t, "/settings/destinations/disable", url.Values{"id": {idText}})
	expect("disable", store.AuditDestinationDisabled, "enabled")
	f.post(t, "/settings/destinations/enable", url.Values{"id": {idText}})
	expect("enable", store.AuditDestinationEnabled, "enabled")
	f.post(t, "/settings/mutes", url.Values{"action": {"add"}, "kind": {"collector"}, "value": {"dns"}})
	mute := expect("add mute", store.AuditMuteAdded, "kind", "value")
	f.post(t, "/settings/mutes", url.Values{"action": {"delete"}, "id": {strings.TrimPrefix(mute.Target, "mute:")}})
	expect("remove mute", store.AuditMuteRemoved)

	// Operator actions on the status page.
	f.server.engine = newWebTestEngine(f.st, f.server.config)
	if response := f.post(t, "/status/reconcile", url.Values{}); response.Code != http.StatusSeeOther {
		t.Fatalf("reconcile %d", response.Code)
	}
	expect("reconcile now", store.AuditReconcileRequested)
	if response := f.post(t, "/status/reconcile", url.Values{}); response.Code != http.StatusSeeOther {
		t.Fatalf("throttled reconcile %d", response.Code)
	}
	if len(f.audit(t)) != seen {
		t.Fatal("a reconcile refused by the cooldown was audited")
	}
	seedDeadDelivery(t, f.db, id, "delivery retry window expired")
	f.post(t, "/status/destinations/retry", url.Values{"id": {idText}})
	if entry := expect("retry dead letters", store.AuditDeadLettersRetried); entry.Target != destinationTarget(id) {
		t.Fatalf("retry target %q", entry.Target)
	}
	f.post(t, "/status/destinations/retry", url.Values{"id": {idText}})
	if len(f.audit(t)) != seen {
		t.Fatal("a retry that requeued nothing was audited")
	}

	loginCookies(t, f.server, testAdminPassword)
	expect("login", store.AuditLoginSuccess)
	if failed := coveragePost(t, f.server, "/login", url.Values{"password": {"not the password"}}, nil); failed.Code == http.StatusSeeOther {
		t.Fatal("wrong password signed in")
	}
	if entry := expect("failed login", store.AuditLoginFailure); entry.Outcome != store.AuditFailure || entry.SessionRef != "" {
		t.Fatalf("failed login record %+v", entry)
	}
	f.post(t, "/settings/sessions/revoke-others", url.Values{})
	expect("revoke sessions", store.AuditSessionsRevoked)
	const newPassword = "violet harbor lantern"
	f.post(t, "/settings/password", url.Values{"current_password": {testAdminPassword}, "password": {newPassword}, "confirm": {newPassword}})
	expect("change password", store.AuditPasswordChanged)
	f.post(t, "/settings/destinations/delete", url.Values{"id": {idText}})
	if len(f.audit(t)) != seen {
		t.Fatal("an unconfirmed removal was audited")
	}
	f.post(t, "/settings/destinations/delete", url.Values{"id": {idText}, "confirm": {"remove"}})
	expect("delete destination", store.AuditDestinationDeleted)
	if response := f.post(t, "/logout", url.Values{}); response.Code != http.StatusSeeOther {
		t.Fatalf("logout %d", response.Code)
	}
	expect("logout", store.AuditLogout)
	resetToken, err := f.st.NewResetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const resetPassword = "amber meadow compass"
	if response := coveragePost(t, f.server, "/reset", url.Values{"token": {resetToken}, "password": {resetPassword}, "confirm": {resetPassword}}, nil); response.Code != http.StatusSeeOther {
		t.Fatalf("reset %d: %s", response.Code, response.Body.String())
	}
	expect("password reset", store.AuditPasswordReset)

	var stored bytes.Buffer
	rows, err := f.db.Query("SELECT created_at,event,outcome,client_ip,session_ref,target,fields FROM admin_audit")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var columns [7]string
		if err := rows.Scan(&columns[0], &columns[1], &columns[2], &columns[3], &columns[4], &columns[5], &columns[6]); err != nil {
			t.Fatal(err)
		}
		stored.WriteString(strings.Join(columns[:], "|") + "\n")
	}
	rows.Close()
	for _, secret := range []string{auditDestinationSecret, auditOAuthSecret, auditWebhookSecret, testAdminPassword, newPassword, resetPassword, resetToken, "example.invalid", "Renamed", "Primary", "dns"} {
		if strings.Contains(stored.String(), secret) {
			t.Fatalf("audit table contains the value %q:\n%s", secret, stored.String())
		}
		if secret != "dns" && secret != "Primary" && secret != "Renamed" && strings.Contains(logs.String(), secret) {
			t.Fatalf("log output contains %q", secret)
		}
	}
	if !strings.Contains(logs.String(), `msg="administrative action" event=destination_disabled`) {
		t.Fatal("audit records are not emitted as structured log lines")
	}
}

// TestDisablingOrRemovingLastDestinationNotifiesItFirst guards E-011: the
// final enabled destination receives the notice before it is disabled or
// removed, while it can still receive it.
func TestDisablingOrRemovingLastDestinationNotifiesItFirst(t *testing.T) {
	f := newAuditFixture(t)
	serviceURL := auditDestinationURL("last")
	id := f.addDestination(t, "Only", serviceURL)
	idText := strconv.FormatInt(id, 10)
	f.post(t, "/settings/destinations/disable", url.Values{"id": {idText}})
	notices := f.sender.notices()
	if len(notices) != 1 || notices[0].url != serviceURL || !notices[0].stillEnabled || !strings.Contains(notices[0].message, "Notification destination disabled") {
		t.Fatalf("last destination was not notified before being disabled: %+v", notices)
	}
	if queued := f.adminNotices(t); len(queued) != 0 {
		t.Fatalf("disabled destination was also given an undeliverable queued notice: %v", queued)
	}
	f.post(t, "/settings/destinations/enable", url.Values{"id": {idText}})
	if len(f.sender.notices()) != 1 {
		t.Fatal("enabling a destination sent a direct notice")
	}
	f.post(t, "/settings/destinations/delete", url.Values{"id": {idText}, "confirm": {"remove"}})
	notices = f.sender.notices()
	if len(notices) != 2 || notices[1].url != serviceURL || !notices[1].stillEnabled || !strings.Contains(notices[1].message, "Notification destination removed") {
		t.Fatalf("last destination was not notified before removal: %+v", notices)
	}
	if active, _ := f.st.ListDestinations(context.Background()); len(active) != 0 {
		t.Fatal("destination was not removed")
	}

	// A disabled destination is not notified when it is removed, and a
	// failed direct notice never blocks the change.
	f.sender.fail = true
	second := f.addDestination(t, "Second", auditDestinationURL("second"))
	f.post(t, "/settings/destinations/disable", url.Values{"id": {strconv.FormatInt(second, 10)}})
	if destinations, _ := f.st.ListDestinations(context.Background()); len(destinations) != 1 || destinations[0].Enabled {
		t.Fatal("a failed notice blocked disabling the destination")
	}
	before := len(f.sender.notices())
	f.post(t, "/settings/destinations/delete", url.Values{"id": {strconv.FormatInt(second, 10)}, "confirm": {"remove"}})
	if len(f.sender.notices()) != before {
		t.Fatal("a disabled destination was notified about its removal")
	}
}

// TestHighRiskChangesNotifyDestinationsEnabledBeforeTheChange guards E-011:
// disabling one destination tells the others through the durable outbox, an
// OAuth identity change notifies every enabled destination (and the notice
// survives the identity change's dead-lettering), and a URL change tells the
// old endpoint.
func TestHighRiskChangesNotifyDestinationsEnabledBeforeTheChange(t *testing.T) {
	f := newAuditFixture(t)
	first := f.addDestination(t, "First", auditDestinationURL("1"))
	second := f.addDestination(t, "Second", auditDestinationURL("2"))
	disabled := f.addDestination(t, "Disabled", auditDestinationURL("3"))
	f.post(t, "/settings/destinations/disable", url.Values{"id": {strconv.FormatInt(disabled, 10)}})
	queued := f.adminNotices(t)
	if len(queued[first]) != 1 || len(queued[second]) != 1 || len(queued[disabled]) != 0 {
		t.Fatalf("disable notice recipients: %v", queued)
	}
	if notices := f.sender.notices(); len(notices) != 1 || notices[0].destinationIDs[0] != disabled {
		t.Fatalf("disabled destination not notified directly: %+v", notices)
	}
	f.clearNotices(t)

	if response := f.post(t, "/settings", settingsForm("client", auditOAuthSecret, "", "60")); response.Code != http.StatusSeeOther {
		t.Fatalf("initial settings %d", response.Code)
	}
	f.clearNotices(t)
	if response := f.post(t, "/settings", settingsForm("another-client", auditOAuthSecret, "", "60")); response.Code != http.StatusSeeOther {
		t.Fatalf("identity change %d: %s", response.Code, response.Body.String())
	}
	queued = f.adminNotices(t)
	if len(queued) != 2 || len(queued[first]) != 1 || len(queued[second]) != 1 || queued[first][0] != "pending" || queued[second][0] != "pending" {
		t.Fatalf("OAuth identity change did not notify every enabled destination: %v", queued)
	}
	if entry := f.audit(t)[0]; entry.Event != store.AuditSettingsChanged || !containsField(entry.Fields, "oauth_client_id") {
		t.Fatalf("identity change audit %+v", entry)
	}
	f.clearNotices(t)

	oldURL := auditDestinationURL("1")
	f.post(t, "/settings/destinations", url.Values{"action": {"save"}, "id": {strconv.FormatInt(first, 10)}, "name": {"First"}, "service_url": {auditDestinationURL("moved")}, "enabled": {"on"}})
	notices := f.sender.notices()
	if last := notices[len(notices)-1]; last.url != oldURL || !strings.Contains(last.message, "service_url") {
		t.Fatalf("old endpoint not notified of the URL change: %+v", last)
	}
	if queued := f.adminNotices(t); len(queued[second]) != 1 || len(queued[first]) != 0 {
		t.Fatalf("URL change notice recipients: %v", queued)
	}
	page := authenticatedGet(t, f.server, "/settings", f.cookies).Body.String()
	if !strings.Contains(page, "Recent administrative activity") || !strings.Contains(page, "Notification destination edited") || strings.Contains(page, auditDestinationSecret) {
		t.Fatal("settings does not show recent administrative activity safely")
	}
}

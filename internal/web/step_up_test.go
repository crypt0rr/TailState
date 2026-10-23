package web

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
)

// stepUpCase is one persistence-granting submission. prepare creates what the
// submission needs and returns it without a current password; stored
// summarizes what the database holds, so a refused submission can be shown to
// have changed nothing.
type stepUpCase struct {
	name    string
	event   string
	prepare func(t *testing.T, f *auditFixture) (string, url.Values)
	stored  func(t *testing.T, f *auditFixture) string
}

var stepUpCases = []stepUpCase{
	{
		name:  "API token creation",
		event: store.AuditAPITokenCreated,
		prepare: func(t *testing.T, f *auditFixture) (string, url.Values) {
			return "/settings/api-tokens", url.Values{"action": {"create"}, "name": {"Export"}, "scopes": {store.ScopeStatusRead}, "expires_days": {"30"}}
		},
		stored: func(t *testing.T, f *auditFixture) string {
			tokens, err := f.st.ListAPITokens(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("%d API tokens", len(tokens))
		},
	},
	{
		name:  "destination added",
		event: store.AuditDestinationAdded,
		prepare: func(t *testing.T, f *auditFixture) (string, url.Values) {
			return "/settings/destinations", url.Values{"action": {"save"}, "name": {"Added"}, "service_url": {auditDestinationURL("added")}, "enabled": {"on"}}
		},
		stored: destinationsStored,
	},
	{
		name:  "destination re-pointed",
		event: store.AuditDestinationEdited,
		prepare: func(t *testing.T, f *auditFixture) (string, url.Values) {
			id := f.addDestination(t, "First", auditDestinationURL("1"))
			return "/settings/destinations", url.Values{"action": {"save"}, "id": {strconv.FormatInt(id, 10)}, "name": {"First"}, "service_url": {auditDestinationURL("moved")}, "enabled": {"on"}}
		},
		stored: destinationsStored,
	},
	{
		name:  "webhook secret cleared",
		event: store.AuditSettingsChanged,
		prepare: func(t *testing.T, f *auditFixture) (string, url.Values) {
			f.addDestination(t, "Primary", auditDestinationURL("1"))
			if response := f.post(t, "/settings", settingsForm("client", auditOAuthSecret, auditWebhookSecret, "60")); response.Code != http.StatusSeeOther {
				t.Fatalf("configuring the webhook secret: %d %s", response.Code, response.Body.String())
			}
			form := settingsForm("client", "", "", "60")
			form.Set("clear_webhook_secret", "on")
			return "/settings", form
		},
		stored: func(t *testing.T, f *auditFixture) string {
			settings, err := f.st.Settings(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("webhook secret stored: %t", settings.WebhookSecret != "")
		},
	},
	{
		name:  "mute rule added",
		event: store.AuditMuteAdded,
		prepare: func(t *testing.T, f *auditFixture) (string, url.Values) {
			return "/settings/mutes", url.Values{"action": {"add"}, "kind": {"collector"}, "value": {"dns"}}
		},
		stored: func(t *testing.T, f *auditFixture) string {
			rules, err := f.st.ListMuteRules(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("%d mute rules", len(rules))
		},
	},
}

// destinationsStored summarizes every saved destination by count and URL.
func destinationsStored(t *testing.T, f *auditFixture) string {
	t.Helper()
	destinations, err := f.st.ListDestinations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	urls := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		urls = append(urls, destination.ServiceURL)
	}
	return fmt.Sprintf("%d destinations: %s", len(destinations), strings.Join(urls, " "))
}

// shown returns the message a submission displays: the flash on the page it
// redirects to, or the page itself when the form is re-rendered.
func (f *auditFixture) shown(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	if response.Code == http.StatusSeeOther {
		return followFlash(t, f.server, f.cookies, response)
	}
	return response.Body.String()
}

// TestStepUpRequiredForPersistenceGrantingActions guards the step-up for
// creating an API token, adding or re-pointing a notification destination,
// clearing the webhook secret, and adding a mute rule. A missing or wrong
// current password stores nothing, announces nothing, and is audited as a
// failed attempt; the right password stores the change and records the
// step-up. Neither password appears in the audit trail or the logs.
func TestStepUpRequiredForPersistenceGrantingActions(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const wrongPassword = "not the password!"
	for _, c := range stepUpCases {
		t.Run(c.name, func(t *testing.T) {
			f := newAuditFixture(t)
			path, form := c.prepare(t, f)
			stored := c.stored(t, f)
			audited := len(f.audit(t))
			notices := len(f.sender.notices())
			queued := len(f.adminNotices(t))
			sessionRef := store.SessionRef(sessionFrom(t, f.cookies))

			for _, attempt := range []struct {
				step     string
				password string
			}{
				{"without the current password", ""},
				{"with a wrong current password", wrongPassword},
			} {
				submitted := cloneForm(form)
				if attempt.password != "" {
					submitted.Set("current_password", attempt.password)
				}
				if message := f.shown(t, f.post(t, path, submitted)); !strings.Contains(message, "the current password is missing or incorrect") {
					t.Fatalf("%s: refusal not shown: %s", attempt.step, message)
				}
				if got := c.stored(t, f); got != stored {
					t.Fatalf("%s: stored %q, want %q", attempt.step, got, stored)
				}
				entries := f.audit(t)
				if len(entries) != audited+1 {
					t.Fatalf("%s: %d audit records, want exactly the refusal", attempt.step, len(entries)-audited)
				}
				if entry := entries[0]; entry.Event != c.event || entry.Outcome != store.AuditFailure || !containsField(entry.Fields, stepUpField) || entry.SessionRef != sessionRef {
					t.Fatalf("%s: refusal audited as %+v", attempt.step, entry)
				}
				audited = len(entries)
				if len(f.sender.notices()) != notices || len(f.adminNotices(t)) != queued {
					t.Fatalf("%s: a refused change was announced", attempt.step)
				}
			}

			submitted := cloneForm(form)
			submitted.Set("current_password", testAdminPassword)
			if response := f.post(t, path, submitted); response.Code != http.StatusSeeOther {
				t.Fatalf("with the current password: %d %s", response.Code, response.Body.String())
			}
			if got := c.stored(t, f); got == stored {
				t.Fatalf("with the current password nothing was stored: %s", got)
			}
			entries := f.audit(t)
			if len(entries) != audited+1 {
				t.Fatalf("with the current password: %d audit records, want one", len(entries)-audited)
			}
			if entry := entries[0]; entry.Event != c.event || entry.Outcome != store.AuditSuccess || !containsField(entry.Fields, stepUpField) {
				t.Fatalf("step-up not recorded on the change: %+v", entry)
			}
			for _, entry := range f.audit(t) {
				if text := fmt.Sprintf("%+v", entry); strings.Contains(text, testAdminPassword) || strings.Contains(text, wrongPassword) {
					t.Fatalf("audit record contains a password: %s", text)
				}
			}
		})
	}
	for _, password := range []string{testAdminPassword, wrongPassword} {
		if strings.Contains(logs.String(), password) {
			t.Fatalf("log output contains a password: %q", password)
		}
	}
}

// TestStepUpWrongPasswordIsThrottled guards the step-up against guessing: a
// wrong current password counts against the same per-client throttle as the
// password change form. Once the limit is spent, a step-up is refused before
// its password is checked, even with the right one, and the password change
// form is refused as well. Refused submissions are not audited again.
func TestStepUpWrongPasswordIsThrottled(t *testing.T) {
	f := newAuditFixture(t)
	mute := url.Values{"action": {"add"}, "kind": {"collector"}, "value": {"dns"}}
	audited := len(f.audit(t))
	for attempt := 1; attempt <= loginFailuresPerClient; attempt++ {
		submitted := cloneForm(mute)
		submitted.Set("current_password", fmt.Sprintf("wrong guess %d", attempt))
		if message := f.shown(t, f.post(t, "/settings/mutes", submitted)); !strings.Contains(message, "the current password is missing or incorrect") {
			t.Fatalf("wrong password %d not refused: %s", attempt, message)
		}
	}
	if got := len(f.audit(t)) - audited; got != loginFailuresPerClient {
		t.Fatalf("%d wrong passwords audited, want %d", got, loginFailuresPerClient)
	}

	right := cloneForm(mute)
	right.Set("current_password", testAdminPassword)
	if message := f.shown(t, f.post(t, "/settings/mutes", right)); !strings.Contains(message, "too many incorrect current passwords") {
		t.Fatalf("throttled step-up not refused: %s", message)
	}
	if rules, err := f.st.ListMuteRules(context.Background()); err != nil || len(rules) != 0 {
		t.Fatalf("throttled step-up stored a rule: %+v err=%v", rules, err)
	}
	if got := len(f.audit(t)) - audited; got != loginFailuresPerClient {
		t.Fatalf("a throttled step-up was audited: %d new records", got)
	}

	change := f.post(t, "/settings/password", url.Values{"current_password": {testAdminPassword}, "password": {"violet harbor lantern"}, "confirm": {"violet harbor lantern"}})
	if message := f.shown(t, change); !strings.Contains(message, "Too many incorrect current passwords") {
		t.Fatalf("password change does not share the step-up throttle: %s", message)
	}
	if !f.st.Authenticate(context.Background(), testAdminPassword) {
		t.Fatal("a throttled password change was applied")
	}
}

// TestStepUpRefusesWhileAuthenticationIsBusy checks that a step-up shares the
// bounded password-checking slots: with every slot taken it is refused at
// once, and the refusal neither records a failure nor stores anything.
func TestStepUpRefusesWhileAuthenticationIsBusy(t *testing.T) {
	f := newAuditFixture(t)
	f.server.authWork <- struct{}{}
	f.server.authWork <- struct{}{}
	mute := url.Values{"action": {"add"}, "current_password": {testAdminPassword}, "kind": {"collector"}, "value": {"dns"}}
	audited := len(f.audit(t))
	if message := f.shown(t, f.post(t, "/settings/mutes", mute)); !strings.Contains(message, "the server is busy checking passwords") {
		t.Fatalf("busy step-up not refused: %s", message)
	}
	if got := len(f.audit(t)); got != audited {
		t.Fatalf("a busy step-up was audited: %d new records", got-audited)
	}
	<-f.server.authWork
	<-f.server.authWork

	if message := f.shown(t, f.post(t, "/settings/mutes", mute)); !strings.Contains(message, "Mute rule added.") {
		t.Fatalf("step-up with the right password after the busy refusal: %s", message)
	}
}

// TestStepUpNarrowlyScopedToPersistenceActions guards the scope of the
// step-up: renaming a destination, changing its routing, disabling and
// re-enabling it, and saving monitoring settings that keep the webhook secret
// all work without the current password and record no step-up.
func TestStepUpNarrowlyScopedToPersistenceActions(t *testing.T) {
	f := newAuditFixture(t)
	id := f.addDestination(t, "Primary", auditDestinationURL("a"))
	idText := strconv.FormatInt(id, 10)
	if response := f.post(t, "/settings", settingsForm("client", auditOAuthSecret, auditWebhookSecret, "60")); response.Code != http.StatusSeeOther {
		t.Fatalf("initial settings %d: %s", response.Code, response.Body.String())
	}
	for _, step := range []struct {
		name  string
		path  string
		form  url.Values
		event string
	}{
		{"rename", "/settings/destinations", url.Values{"action": {"save"}, "id": {idText}, "name": {"Renamed"}, "service_url": {""}, "enabled": {"on"}}, store.AuditDestinationEdited},
		{"routing", "/settings/destinations", url.Values{"action": {"save"}, "id": {idText}, "name": {"Renamed"}, "enabled": {"on"}, "routing": {"1"}, "min_severity": {"high"}, "message_format": {"plain"}}, store.AuditDestinationEdited},
		{"disable", "/settings/destinations/disable", url.Values{"id": {idText}}, store.AuditDestinationDisabled},
		{"enable", "/settings/destinations/enable", url.Values{"id": {idText}}, store.AuditDestinationEnabled},
		{"monitoring settings", "/settings", settingsForm("client", auditOAuthSecret, "", "90"), store.AuditSettingsChanged},
	} {
		before := len(f.audit(t))
		response := f.post(t, step.path, step.form)
		entries := f.audit(t)
		if response.Code != http.StatusSeeOther || len(entries) != before+1 || entries[0].Event != step.event || entries[0].Outcome != store.AuditSuccess || containsField(entries[0].Fields, stepUpField) {
			t.Fatalf("%s: status %d with %d new audit records; want one unstepped %s", step.name, response.Code, len(entries)-before, step.event)
		}
	}
	destinations, err := f.st.ListDestinations(context.Background())
	if err != nil || len(destinations) != 1 || destinations[0].Name != "Renamed" || !destinations[0].Enabled {
		t.Fatalf("the narrow edits were not stored: %+v err=%v", destinations, err)
	}
}

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

type fakeTester struct {
	err      error
	prepared notify.Prepared
}

func (f *fakeTester) SendPrepared(_ context.Context, _ string, message notify.Prepared) error {
	f.prepared = message
	return f.err
}

// TestDestinationTestWarnsAboutDiscordSplitLines covers R-046's operator
// warning: the Settings test and the deployment diagnostics flag a Discord
// URL that forces splitlines=yes, whatever the test's outcome, without
// echoing the URL.
func TestDestinationTestWarnsAboutDiscordSplitLines(t *testing.T) {
	server, st, token := testServer(t)
	tester := &fakeTester{}
	server.destinationTester = tester
	cookies := claimCoverageAdmin(t, server, token)
	csrf := coverageCSRF(t, cookies)
	forced := "discord://secret-token@123456789?splitlines=yes"
	response := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "service_url": {forced}}, cookies)
	result := followFlash(t, server, cookies, response)
	if response.Code != http.StatusSeeOther || !strings.Contains(result, "Notification test sent. Warning:") || !strings.Contains(result, "splitlines=yes") || strings.Contains(result, "secret-token") {
		t.Fatalf("forced splitlines flash: %s", result)
	}
	if tester.prepared.Title == "" || strings.Contains(tester.prepared.Message(), "TailState test ·") {
		t.Fatalf("test message was not prepared with a separate title: %+v", tester.prepared)
	}
	tester.err = errors.New("dial tcp: connection refused")
	failed := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "service_url": {forced}}, cookies)
	if result := followFlash(t, server, cookies, failed); !strings.Contains(result, "Notification test failed") || !strings.Contains(result, "Warning:") {
		t.Fatalf("failed test flash: %s", result)
	}
	tester.err = nil
	plain := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "service_url": {"discord://secret-token@123456789"}}, cookies)
	if result := followFlash(t, server, cookies, plain); !strings.Contains(result, "Notification test sent.") || strings.Contains(result, "Warning") {
		t.Fatalf("default Discord test flash: %s", result)
	}

	if _, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "corp.example", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/token", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(context.Background(), store.NotificationDestination{Name: "Discord", ServiceURL: forced, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	report := server.diagnosticReport(context.Background(), nil)
	found := false
	for _, finding := range report.Findings {
		if finding.Code == "discord_splitlines_forced" {
			found = true
			if strings.Contains(finding.Summary+finding.Remediation, "secret-token") {
				t.Fatalf("finding leaks the URL: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("diagnostics did not flag the forced splitlines: %+v", report.Findings)
	}
}

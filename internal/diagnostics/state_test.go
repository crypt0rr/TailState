package diagnostics

import (
	"testing"

	"github.com/crypt0rr/tailstate/internal/boot"
)

func TestNotificationStateFor(t *testing.T) {
	for _, test := range []struct {
		configured            bool
		destinations, enabled int
		want                  NotificationState
		paused                bool
		noDestinationsFinding bool
		pausedFinding         bool
	}{
		{false, 0, 0, NotificationsUnconfigured, false, false, false},
		{false, 1, 0, NotificationsUnconfigured, false, false, false},
		{false, 1, 1, NotificationsActive, false, false, false},
		{true, 0, 0, NotificationsNoDestinations, true, true, false},
		{true, 2, 0, NotificationsPaused, true, false, true},
		{true, 2, 1, NotificationsActive, false, false, false},
	} {
		got := NotificationStateFor(test.configured, test.destinations, test.enabled)
		if got != test.want || got.Paused() != test.paused {
			t.Fatalf("NotificationStateFor(%v,%d,%d)=%s paused=%v", test.configured, test.destinations, test.enabled, got, got.Paused())
		}
		report := Build(boot.Config{ListenAddr: "127.0.0.1:8080"}, Runtime{Configured: test.configured, BaselineReady: true, Destinations: test.destinations, EnabledDestinations: test.enabled}, nil)
		_, noDestinations := finding(report, "notifications_no_destinations")
		_, paused := finding(report, "notifications_paused")
		if noDestinations != test.noDestinationsFinding || paused != test.pausedFinding {
			t.Fatalf("state %s findings: no_destinations=%v paused=%v", got, noDestinations, paused)
		}
	}
}

// TestContainerDefaultListenerIsInformational proves the official image's
// wildcard listener (bounded by Compose's loopback publish) keeps the default
// deployment at state "ok", while the same listener outside a container, or
// an explicit non-wildcard address in one, still warns.
func TestContainerDefaultListenerIsInformational(t *testing.T) {
	for _, test := range []struct {
		name     string
		config   boot.Config
		state    string
		code     string
		severity Severity
	}{
		{"container wildcard IPv4", boot.Config{ListenAddr: "0.0.0.0:8080", Container: true}, "ok", "container_listener", SeverityInfo},
		{"container wildcard IPv6", boot.Config{ListenAddr: "[::]:8080", Container: true}, "ok", "container_listener", SeverityInfo},
		{"container empty host", boot.Config{ListenAddr: ":8080", Container: true}, "ok", "container_listener", SeverityInfo},
		{"standalone wildcard", boot.Config{ListenAddr: "0.0.0.0:8080"}, "warning", "plaintext_public_listener", SeverityWarning},
		{"container explicit address", boot.Config{ListenAddr: "192.0.2.10:8080", Container: true}, "warning", "plaintext_public_listener", SeverityWarning},
		{"container hostname", boot.Config{ListenAddr: "tailstate.example:8080", Container: true}, "warning", "plaintext_public_listener", SeverityWarning},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := Build(test.config, Runtime{DatabaseMissing: true}, nil)
			if report.State != test.state {
				t.Fatalf("state=%q, want %q (%#v)", report.State, test.state, report.Findings)
			}
			got, ok := finding(report, test.code)
			if !ok || got.Severity != test.severity {
				t.Fatalf("finding %s=%#v ok=%v", test.code, got, ok)
			}
		})
	}
	if (boot.Config{ListenAddr: "bad", Container: true}).ContainerWildcardListener() {
		t.Fatal("malformed listener treated as container wildcard")
	}
	if (boot.Config{ListenAddr: "0.0.0.0:8080", Container: true, CookieSecure: true}).ContainerWildcardListener() {
		t.Fatal("secure-cookie deployment reported as plaintext container listener")
	}
}

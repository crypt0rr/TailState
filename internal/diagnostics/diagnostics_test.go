package diagnostics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/boot"
)

func finding(report Report, code string) (Finding, bool) {
	for _, candidate := range report.Findings {
		if candidate.Code == code {
			return candidate, true
		}
	}
	return Finding{}, false
}

func TestBuildReportsPlaintextListenerAndPausedNotifications(t *testing.T) {
	report := Build(boot.Config{ListenAddr: "0.0.0.0:8080"}, Runtime{
		Configured:          true,
		BaselineReady:       true,
		Destinations:        2,
		EnabledDestinations: 0,
	}, nil)
	if report.State != "warning" {
		t.Fatalf("report state=%q, want warning", report.State)
	}
	if _, ok := finding(report, "plaintext_public_listener"); !ok {
		t.Fatal("plaintext listener finding missing")
	}
	if _, ok := finding(report, "notifications_paused"); !ok {
		t.Fatal("paused notification finding missing")
	}
}

func TestBuildReportsUntrustedForwardedHTTPSWithoutLeakingHeaders(t *testing.T) {
	config := boot.Config{
		ListenAddr:     "127.0.0.1:8080",
		CookieSecure:   true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	request := httptest.NewRequest(http.MethodGet, "http://public.example/settings", nil)
	request.RemoteAddr = "198.51.100.20:1234"
	request.Host = "public.example"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-For", "203.0.113.5")
	request.Header.Set("Origin", "https://secret-token@attacker.example/private")
	report := Build(config, Runtime{Configured: true}, request)
	if report.Request.Origin != "http://public.example" {
		t.Fatalf("request origin=%q, want sanitized effective origin", report.Request.Origin)
	}
	if report.Request.PeerTrustedProxy {
		t.Fatal("untrusted peer was accepted as a proxy")
	}
	if _, ok := finding(report, "untrusted_forwarded_headers"); !ok {
		t.Fatal("untrusted forwarded-header finding missing")
	}
	if _, ok := finding(report, "https_forward_missing"); !ok {
		t.Fatal("missing HTTPS finding missing")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-token") || strings.Contains(string(encoded), "attacker.example") {
		t.Fatalf("report leaked raw origin metadata: %s", encoded)
	}
}

func TestBuildAcceptsTrustedHTTPSProxy(t *testing.T) {
	config := boot.Config{
		ListenAddr:     "127.0.0.1:8080",
		CookieSecure:   true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	request := httptest.NewRequest(http.MethodGet, "http://tailstate.internal/settings", nil)
	request.RemoteAddr = "10.0.0.4:1234"
	request.Host = "tailstate.example.com"
	request.Header.Set("X-Forwarded-Proto", "https")
	report := Build(config, Runtime{Configured: true, BaselineReady: true, Destinations: 1, EnabledDestinations: 1}, request)
	if report.State != "ok" {
		t.Fatalf("report state=%q, findings=%#v", report.State, report.Findings)
	}
	if report.Request.Origin != "https://tailstate.example.com" || !report.Request.PeerTrustedProxy {
		t.Fatalf("unexpected request info: %#v", report.Request)
	}
}

func TestBuildReportsUnclaimedInstallation(t *testing.T) {
	report := Build(boot.Config{ListenAddr: "127.0.0.1:8080"}, Runtime{}, nil)
	if report.State != "ok" {
		t.Fatalf("unclaimed installation state=%q, want ok", report.State)
	}
	if _, ok := finding(report, "installation_incomplete"); !ok {
		t.Fatal("unclaimed installation finding missing")
	}
}

func TestBuildReportsReadOnlyDatabaseState(t *testing.T) {
	missing := Build(boot.Config{ListenAddr: "127.0.0.1:8080"}, Runtime{
		DatabaseMissing: true,
		Storage:         StorageRuntime{ConfiguredProfile: &StorageProfile{DatabaseLimitBytes: 512 << 20}},
	}, nil)
	if missing.State != "ok" {
		t.Fatalf("missing database state=%q, want ok", missing.State)
	}
	if _, ok := finding(missing, "database_missing"); !ok {
		t.Fatal("missing database finding missing")
	}
	pending := Build(boot.Config{ListenAddr: "127.0.0.1:8080"}, Runtime{
		SchemaVersion:          11,
		SchemaMigrationPending: true,
		Storage: StorageRuntime{
			ConfiguredProfile: &StorageProfile{DatabaseLimitBytes: 512 << 20},
			PersistedProfile:  &StorageProfile{DatabaseLimitBytes: 256 << 20},
		},
	}, nil)
	if pending.State != "warning" {
		t.Fatalf("pending database state=%q, want warning", pending.State)
	}
	if _, ok := finding(pending, "database_migration_pending"); !ok {
		t.Fatal("migration pending finding missing")
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || !strings.Contains(string(encoded), "configured_profile") || !strings.Contains(string(encoded), "persisted_profile") {
		t.Fatalf("database diagnostics missing safe profile data or leaking credentials: %s", encoded)
	}
}

func TestBuildReportsStoragePressureWithoutPayloads(t *testing.T) {
	report := Build(boot.Config{ListenAddr: "127.0.0.1:8080"}, Runtime{
		Configured: true,
		Storage: StorageRuntime{
			SnapshotLimitBytes:    1024,
			EventValueLimitBytes:  1024,
			HistoryPageLimitBytes: 4096,
			DatabaseLimitBytes:    100,
			DatabaseBytes:         95,
			DatabaseFileBytes:     80,
			DatabaseWALBytes:      10,
			DatabaseSHMBytes:      5,
			DatabasePhysicalBytes: 95,
			StoragePressure:       0.95,
		},
	}, nil)
	if _, ok := finding(report, "storage_pressure"); !ok || report.State != "warning" {
		t.Fatalf("storage pressure finding missing: %#v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "provider") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("storage diagnostics contain payload material: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"DatabasePhysicalBytes":95`) {
		t.Fatalf("physical storage diagnostics missing: %s", encoded)
	}
	errorReport := Build(boot.Config{ListenAddr: "127.0.0.1:8080"}, Runtime{Configured: true, Storage: StorageRuntime{DatabaseLimitBytes: 100, DatabaseBytes: 100, StoragePressure: 1}}, nil)
	if finding, ok := finding(errorReport, "storage_pressure"); !ok || finding.Severity != SeverityError || errorReport.State != "error" {
		t.Fatalf("storage pressure error finding missing: %#v", errorReport)
	}
}

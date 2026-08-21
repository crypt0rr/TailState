package boot

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigDatabasePathAndMasterKeyFormats(t *testing.T) {
	config := Config{DataDir: "/var/lib/tailstate"}
	if got := config.DatabasePath(); got != filepath.Join("/var/lib/tailstate", "tailstate.db") {
		t.Fatalf("database path=%q", got)
	}
	dir := t.TempDir()
	missing := Config{MasterKeyFile: filepath.Join(dir, "missing")}
	if _, err := missing.MasterKey(); err == nil {
		t.Fatal("missing master key was accepted")
	}
	rawPath := filepath.Join(dir, "raw")
	rawKey := []byte(strings.Repeat("!", 32))
	if err := os.WriteFile(rawPath, append(rawKey, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := (Config{MasterKeyFile: rawPath}).MasterKey()
	if err != nil || string(key) != string(rawKey) {
		t.Fatalf("raw master key=%q err=%v", key, err)
	}
	encodedPath := filepath.Join(dir, "encoded")
	encoded := base64.StdEncoding.EncodeToString(rawKey)
	if err := os.WriteFile(encodedPath, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err = (Config{MasterKeyFile: encodedPath}).MasterKey()
	if err != nil || string(key) != string(rawKey) {
		t.Fatalf("encoded master key=%q err=%v", key, err)
	}
	wrongPath := filepath.Join(dir, "wrong")
	if err := os.WriteFile(wrongPath, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Config{MasterKeyFile: wrongPath}).MasterKey(); err == nil || !strings.Contains(err.Error(), "exactly 32") {
		t.Fatalf("wrong-length master key error=%v", err)
	}
}

func TestLoadRejectsCookieAndEndpointEdgeCases(t *testing.T) {
	if err := validateEndpoint("test", "ftp://example.com"); err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("non-http endpoint error=%v", err)
	}
	t.Setenv("TAILSTATE_COOKIE_SECURE", "maybe")
	if _, err := Load("test"); err == nil || !strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Fatalf("invalid cookie secure setting error=%v", err)
	}
	t.Setenv("TAILSTATE_COOKIE_SECURE", "false")
	t.Setenv("TAILSTATE_TRUSTED_PROXIES", "")
	t.Setenv("TAILSTATE_COOKIE_SECURE", "true")
	if _, err := Load("test"); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
		t.Fatalf("secure cookies without a trusted proxy were accepted: %v", err)
	}
	t.Setenv("TAILSTATE_TRUSTED_PROXIES", "127.0.0.1")
	if _, err := Load("test"); err != nil {
		t.Fatalf("secure cookies with a trusted proxy were rejected: %v", err)
	}
	t.Setenv("TAILSTATE_COOKIE_SECURE", "false")
	t.Setenv("TAILSTATE_DATA_DIR", "")
	if _, err := Load("test"); err == nil || !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("empty data directory error=%v", err)
	}
	t.Setenv("TAILSTATE_DATA_DIR", t.TempDir())
	t.Setenv("TAILSTATE_TS_API_URL", "https://example.com/api#fragment")
	if _, err := Load("test"); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("fragment endpoint error=%v", err)
	}
}

func TestInsecureHTTPListenerDiagnostic(t *testing.T) {
	cases := []struct {
		name   string
		config Config
		want   bool
	}{
		{name: "loopback IPv4", config: Config{ListenAddr: "127.0.0.1:8080"}},
		{name: "loopback IPv6", config: Config{ListenAddr: "[::1]:8080"}},
		{name: "localhost", config: Config{ListenAddr: "localhost:8080"}},
		{name: "wildcard", config: Config{ListenAddr: "0.0.0.0:8080"}, want: true},
		{name: "remote", config: Config{ListenAddr: "192.0.2.10:8080"}, want: true},
		{name: "hostname", config: Config{ListenAddr: "tailstate.internal:8080"}, want: true},
		{name: "secure proxy", config: Config{ListenAddr: "0.0.0.0:8080", CookieSecure: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.InsecureHTTPListener(); got != tc.want {
				t.Fatalf("InsecureHTTPListener()=%v, want %v", got, tc.want)
			}
		})
	}
}

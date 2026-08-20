package boot

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr     string
	DataDir        string
	MasterKeyFile  string
	CookieSecure   bool
	MetricsToken   string
	TrustedProxies []netip.Prefix
	LogLevel       string
	TailscaleBase  string
	OAuthTokenURL  string
	Version        string
}

func Load(version string) (Config, error) {
	c := Config{
		ListenAddr:    env("TAILSTATE_LISTEN_ADDR", "0.0.0.0:8080"),
		DataDir:       env("TAILSTATE_DATA_DIR", "/data"),
		MasterKeyFile: env("TAILSTATE_MASTER_KEY_FILE", "/run/secrets/tailstate_master_key"),
		MetricsToken:  strings.TrimSpace(env("TAILSTATE_METRICS_TOKEN", "")),
		LogLevel:      env("TAILSTATE_LOG_LEVEL", "info"),
		TailscaleBase: strings.TrimRight(env("TAILSTATE_TS_API_URL", "https://api.tailscale.com/api/v2"), "/"),
		OAuthTokenURL: env("TAILSTATE_TS_OAUTH_URL", "https://api.tailscale.com/api/v2/oauth/token"),
		Version:       version,
	}
	secure, err := strconv.ParseBool(env("TAILSTATE_COOKIE_SECURE", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("TAILSTATE_COOKIE_SECURE: %w", err)
	}
	c.CookieSecure = secure
	trustedProxies, err := parseTrustedProxies(env("TAILSTATE_TRUSTED_PROXIES", ""))
	if err != nil {
		return Config{}, err
	}
	c.TrustedProxies = trustedProxies
	if c.DataDir == "" || c.ListenAddr == "" {
		return Config{}, errors.New("data directory and listen address are required")
	}
	if c.LogLevel != "info" && c.LogLevel != "debug" {
		return Config{}, fmt.Errorf("TAILSTATE_LOG_LEVEL must be info or debug, got %q", c.LogLevel)
	}
	if len(c.MetricsToken) > 256 || strings.ContainsAny(c.MetricsToken, "\r\n\t ") {
		return Config{}, errors.New("TAILSTATE_METRICS_TOKEN must be a single token of at most 256 characters")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return Config{}, fmt.Errorf("TAILSTATE_LISTEN_ADDR must be host:port: %w", err)
	}
	if err := validateEndpoint("TAILSTATE_TS_API_URL", c.TailscaleBase); err != nil {
		return Config{}, err
	}
	if err := validateEndpoint("TAILSTATE_TS_OAUTH_URL", c.OAuthTokenURL); err != nil {
		return Config{}, err
	}
	return c, nil
}

func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return nil, errors.New("TAILSTATE_TRUSTED_PROXIES may contain at most 32 entries")
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, errors.New("TAILSTATE_TRUSTED_PROXIES contains an empty entry")
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("TAILSTATE_TRUSTED_PROXIES contains invalid address %q", value)
		}
		bits := addr.BitLen()
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
	}
	return prefixes, nil
}

func validateEndpoint(name, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an http(s) URL with a host and no credentials or fragment", name)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https", name)
	}
	return nil
}

func (c Config) DatabasePath() string { return filepath.Join(c.DataDir, "tailstate.db") }

func (c Config) MasterKey() ([]byte, error) {
	return ReadMasterKeyFile(c.MasterKeyFile)
}

// ReadMasterKeyFile reads a raw 32-byte or base64-encoded 32-byte key from a
// file. It is shared by the service loader and the administrative rekey
// command so both paths enforce the same validation.
func ReadMasterKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read master key %s: %w", path, err)
	}
	value := strings.TrimSpace(string(raw))
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		key = []byte(value)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes or base64-encoded 32 bytes, got %d", len(key))
	}
	return key, nil
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

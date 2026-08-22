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
		// Standalone binaries should not expose the authenticated UI beyond the
		// local machine by default. The container image and Compose file set an
		// explicit wildcard listener because their host/network boundary is
		// configured separately.
		ListenAddr:    env("TAILSTATE_LISTEN_ADDR", "127.0.0.1:8080"),
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
	if c.CookieSecure && len(c.TrustedProxies) == 0 {
		return Config{}, errors.New("TAILSTATE_COOKIE_SECURE requires at least one TAILSTATE_TRUSTED_PROXIES entry")
	}
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

// InsecureHTTPListener reports whether the authenticated UI is served over
// plaintext HTTP on a non-loopback listener. This is intentionally a warning,
// not a hard rejection: a container or a local development proxy may own the
// network boundary, but operators should get an explicit diagnostic when they
// choose that deployment shape.
func (c Config) InsecureHTTPListener() bool {
	if c.CookieSecure {
		return false
	}
	host, _, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return host == ""
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		// A hostname can resolve to a remote interface, so treat it as
		// externally reachable unless the operator enables secure cookies.
		return true
	}
	return !address.IsLoopback()
}

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
	// Prefer an exact raw 32-byte file before trying textual encodings. A raw
	// key is allowed to contain only Base64 characters; decoding such a key
	// first would turn it into a shorter value and reject an otherwise valid
	// master key.
	if len(raw) == 32 {
		return append([]byte(nil), raw...), nil
	}
	value := strings.TrimSpace(string(raw))
	if len(value) == 32 {
		return []byte(value), nil
	}
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

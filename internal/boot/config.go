package boot

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr    string
	DataDir       string
	MasterKeyFile string
	CookieSecure  bool
	LogLevel      string
	TailscaleBase string
	OAuthTokenURL string
	Version       string
}

func Load(version string) (Config, error) {
	c := Config{
		ListenAddr:    env("TAILSTATE_LISTEN_ADDR", "0.0.0.0:8080"),
		DataDir:       env("TAILSTATE_DATA_DIR", "/data"),
		MasterKeyFile: env("TAILSTATE_MASTER_KEY_FILE", "/run/secrets/tailstate_master_key"),
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
	if c.DataDir == "" || c.ListenAddr == "" {
		return Config{}, errors.New("data directory and listen address are required")
	}
	return c, nil
}

func (c Config) DatabasePath() string { return filepath.Join(c.DataDir, "tailstate.db") }

func (c Config) MasterKey() ([]byte, error) {
	raw, err := os.ReadFile(c.MasterKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read master key %s: %w", c.MasterKeyFile, err)
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

package boot

import (
	"net/netip"
	"testing"
)

func TestLoadRejectsInvalidBootstrapValues(t *testing.T) {
	tests := []struct {
		name string
		set  map[string]string
	}{
		{name: "log level", set: map[string]string{"TAILSTATE_LOG_LEVEL": "trace"}},
		{name: "listen address", set: map[string]string{"TAILSTATE_LISTEN_ADDR": "127.0.0.1"}},
		{name: "API URL", set: map[string]string{"TAILSTATE_TS_API_URL": "file:///tmp/api"}},
		{name: "OAuth URL credentials", set: map[string]string{"TAILSTATE_TS_OAUTH_URL": "https://user:pass@example.com/token"}},
		{name: "plaintext public URL", set: map[string]string{"TAILSTATE_PUBLIC_URL": "http://tailstate.example"}},
		{name: "public URL with query", set: map[string]string{"TAILSTATE_PUBLIC_URL": "https://tailstate.example/?next=1"}},
		{name: "instance label control", set: map[string]string{"TAILSTATE_INSTANCE_LABEL": "prod\nlab"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.set {
				t.Setenv(name, value)
			}
			if _, err := Load("test"); err == nil {
				t.Fatal("expected invalid bootstrap configuration to fail")
			}
		})
	}
}

func TestLoadAcceptsHTTPMockEndpoints(t *testing.T) {
	t.Setenv("TAILSTATE_LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("TAILSTATE_TS_API_URL", "http://127.0.0.1:1234/api/v2")
	t.Setenv("TAILSTATE_TS_OAUTH_URL", "http://127.0.0.1:1234/oauth/token")
	config, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if config.TailscaleBase != "http://127.0.0.1:1234/api/v2" {
		t.Fatalf("unexpected API URL: %s", config.TailscaleBase)
	}
}

func TestTrustedProxyConfiguration(t *testing.T) {
	t.Setenv("TAILSTATE_TRUSTED_PROXIES", "127.0.0.1, 10.0.0.0/8")
	config, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.TrustedProxies) != 2 || !config.TrustedProxies[0].Contains(netip.MustParseAddr("127.0.0.1")) || !config.TrustedProxies[1].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatalf("unexpected trusted proxies: %#v", config.TrustedProxies)
	}
	for _, value := range []string{"bad", "127.0.0.1,,10.0.0.0/8"} {
		t.Setenv("TAILSTATE_TRUSTED_PROXIES", value)
		if _, err := Load("test"); err == nil {
			t.Fatalf("invalid trusted proxy %q was accepted", value)
		}
	}
}

func TestLoadNormalizesNotificationContext(t *testing.T) {
	t.Setenv("TAILSTATE_PUBLIC_URL", "https://tailstate.example/ops/")
	t.Setenv("TAILSTATE_INSTANCE_LABEL", "  prod-eu ")
	config, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if config.PublicURL != "https://tailstate.example/ops" || config.InstanceLabel != "prod-eu" {
		t.Fatalf("public URL=%q label=%q", config.PublicURL, config.InstanceLabel)
	}
}

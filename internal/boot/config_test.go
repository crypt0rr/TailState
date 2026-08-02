package boot

import "testing"

func TestLoadRejectsInvalidBootstrapValues(t *testing.T) {
	tests := []struct {
		name string
		set  map[string]string
	}{
		{name: "log level", set: map[string]string{"TAILSTATE_LOG_LEVEL": "trace"}},
		{name: "listen address", set: map[string]string{"TAILSTATE_LISTEN_ADDR": "127.0.0.1"}},
		{name: "API URL", set: map[string]string{"TAILSTATE_TS_API_URL": "file:///tmp/api"}},
		{name: "OAuth URL credentials", set: map[string]string{"TAILSTATE_TS_OAUTH_URL": "https://user:pass@example.com/token"}},
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

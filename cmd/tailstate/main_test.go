package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

func configureCommandEnvironment(t *testing.T, dataDir string) string {
	t.Helper()
	keyPath := filepath.Join(dataDir, "master.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAILSTATE_DATA_DIR", dataDir)
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", keyPath)
	t.Setenv("TAILSTATE_LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("TAILSTATE_COOKIE_SECURE", "false")
	t.Setenv("TAILSTATE_TS_API_URL", "http://127.0.0.1:1234/api/v2")
	t.Setenv("TAILSTATE_TS_OAUTH_URL", "http://127.0.0.1:1234/oauth/token")
	return keyPath
}

func TestRunCommandDispatchAndHealthcheck(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	for _, command := range []string{"version", "--version", "-version"} {
		os.Args = []string{"tailstate", command}
		if err := run(); err != nil {
			t.Fatalf("%s returned error: %v", command, err)
		}
	}
	os.Args = []string{"tailstate", "admin"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "admin reset") {
		t.Fatalf("invalid admin command error=%v", err)
	}
	os.Args = []string{"tailstate", "unknown"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command error=%v", err)
	}
	os.Args = []string{"tailstate", "evidence"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "evidence verify") {
		t.Fatalf("invalid evidence command error=%v", err)
	}

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer health.Close()
	if err := healthcheck([]string{"-url", health.URL}); err != nil {
		t.Fatal(err)
	}
	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer failure.Close()
	if err := healthcheck([]string{"-url", failure.URL}); err == nil || !strings.Contains(err.Error(), "returned 503") {
		t.Fatalf("unhealthy endpoint error=%v", err)
	}
	if err := healthcheck([]string{"-bad-flag"}); err == nil {
		t.Fatal("invalid healthcheck flag was accepted")
	}
}

func TestMainAndServeRejectInvalidConfiguration(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"tailstate", "version"}
	main()

	t.Setenv("TAILSTATE_DATA_DIR", t.TempDir())
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", filepath.Join(t.TempDir(), "missing-master.key"))
	t.Setenv("TAILSTATE_LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("TAILSTATE_COOKIE_SECURE", "false")
	os.Args = []string{"tailstate", "serve"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("serve with invalid configuration error=%v", err)
	}
	if err := serve(); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("direct serve with invalid configuration error=%v", err)
	}
}

func TestServeContextCompletesWhenCanceled(t *testing.T) {
	configureCommandEnvironment(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	timer := time.AfterFunc(500*time.Millisecond, cancel)
	t.Cleanup(func() { timer.Stop() })
	if err := serveContext(ctx); err != nil {
		t.Fatalf("serveContext returned error: %v", err)
	}
}

func TestLoadAndAdminResetWithConfiguredKey(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	config, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if config.DatabasePath() != filepath.Join(dataDir, "tailstate.db") {
		t.Fatalf("database path=%q", config.DatabasePath())
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := adminReset(); err != nil {
		t.Fatal(err)
	}
	_, reopened, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsMissingMasterKey(t *testing.T) {
	t.Setenv("TAILSTATE_DATA_DIR", t.TempDir())
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("TAILSTATE_LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("TAILSTATE_COOKIE_SECURE", "false")
	if _, _, err := load(); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("missing master key error=%v", err)
	}
}

func TestEvidenceVerifyCommand(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	pack, err := st.ExportEvidencePack(context.Background(), store.HistoryFilter{})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	public, err := st.EvidenceSigningPublicKey(context.Background())
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	packPath := filepath.Join(dataDir, "evidence.json")
	keyPath := filepath.Join(dataDir, "evidence.key")
	if err := os.WriteFile(packPath, pack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.RawStdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evidenceVerify([]string{"-file", packPath}); err != nil {
		t.Fatalf("embedded-key verification failed: %v", err)
	}
	if err := evidenceVerify([]string{"-file", packPath, "-public-key", keyPath}); err != nil {
		t.Fatalf("trusted-key verification failed: %v", err)
	}
}

func TestCommandDispatchesConfiguredOperations(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	os.Args = []string{"tailstate", "healthcheck", "-url", health.URL}
	if err := run(); err != nil {
		health.Close()
		t.Fatalf("healthcheck dispatch failed: %v", err)
	}
	health.Close()

	os.Args = []string{"tailstate", "admin", "reset"}
	if err := run(); err != nil {
		t.Fatalf("admin reset dispatch failed: %v", err)
	}
	os.Args = []string{"tailstate", "evidence", "public-key"}
	if err := run(); err != nil {
		t.Fatalf("evidence public-key dispatch failed: %v", err)
	}
}

func TestEvidenceVerifyReadsStandardInputAndReportsReadErrors(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	pack, err := st.ExportEvidencePack(context.Background(), store.HistoryFilter{})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(pack); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		reader.Close()
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = originalStdin
		reader.Close()
	})
	if err := evidenceVerify(nil); err != nil {
		t.Fatalf("stdin evidence verification failed: %v", err)
	}

	if err := evidenceVerify([]string{"-file", filepath.Join(dataDir, "missing.json")}); err == nil || !strings.Contains(err.Error(), "read evidence pack") {
		t.Fatalf("missing evidence file error = %v", err)
	}
	badKey := filepath.Join(dataDir, "bad.key")
	if err := os.WriteFile(badKey, []byte("not-a-public-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	packPath := filepath.Join(dataDir, "pack.json")
	if err := os.WriteFile(packPath, pack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evidenceVerify([]string{"-file", packPath, "-public-key", badKey}); err == nil || !strings.Contains(err.Error(), "parse evidence public key") {
		t.Fatalf("bad public key error = %v", err)
	}
}

func TestHealthcheckReportsTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	if err := healthcheck([]string{"-url", url}); err == nil {
		t.Fatal("healthcheck against a closed server unexpectedly succeeded")
	}
}

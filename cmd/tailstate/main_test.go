package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

func commandDB(t *testing.T, dataDir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "tailstate.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open command database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

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

func claimCommandAdmin(t *testing.T, st *store.Store) {
	t.Helper()
	token, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Claim(context.Background(), token, "a secure password"); err != nil {
		t.Fatal(err)
	}
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
	os.Args = []string{"tailstate", "evidence", "verify", "-file", filepath.Join(t.TempDir(), "missing-evidence.json")}
	if err := run(); err == nil || !strings.Contains(err.Error(), "read evidence pack") {
		t.Fatalf("evidence verify dispatch error=%v", err)
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
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	if err := doctor([]string{"-json"}); err != nil {
		t.Fatalf("doctor returned error: %v", err)
	}
	if err := doctor([]string{"-bad-flag"}); err == nil {
		t.Fatal("invalid doctor flag was accepted")
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
	t.Setenv("TAILSTATE_LOG_LEVEL", "debug")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	timer := time.AfterFunc(500*time.Millisecond, cancel)
	t.Cleanup(func() { timer.Stop() })
	if err := serveContext(ctx); err != nil {
		t.Fatalf("serveContext returned error: %v", err)
	}
}

func TestEvidenceVerifyReportsTrustedKeyAndPackErrors(t *testing.T) {
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
	packPath := filepath.Join(dataDir, "pack.json")
	if err := os.WriteFile(packPath, pack, 0o600); err != nil {
		t.Fatal(err)
	}
	badPackPath := filepath.Join(dataDir, "bad-pack.json")
	if err := os.WriteFile(badPackPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evidenceVerify([]string{"-file", badPackPath}); err == nil || !strings.Contains(err.Error(), "decode evidence pack") {
		t.Fatalf("bad evidence pack error=%v", err)
	}
	keyPath := filepath.Join(dataDir, "wrong.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evidenceVerify([]string{"-file", packPath, "-public-key", keyPath}); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("wrong trusted key error=%v", err)
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
	claimCommandAdmin(t, st)
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

func TestLoadRejectsMalformedMasterKeyAndStorePath(t *testing.T) {
	dataDir := t.TempDir()
	keyPath := configureCommandEnvironment(t, dataDir)
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write malformed key: %v", err)
	}
	if _, _, err := load(); err == nil || !strings.Contains(err.Error(), "master key must be exactly 32 bytes") {
		t.Fatalf("load with malformed key error = %v", err)
	}

	dataFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(dataFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write data path: %v", err)
	}
	validKeyPath := filepath.Join(t.TempDir(), "master.key")
	validKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := os.WriteFile(validKeyPath, []byte(validKey), 0o600); err != nil {
		t.Fatalf("write valid key: %v", err)
	}
	t.Setenv("TAILSTATE_DATA_DIR", dataFile)
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", validKeyPath)
	if _, _, err := load(); err == nil {
		t.Fatal("load with a file as data directory succeeded")
	}
}

func TestAdminResetReportsStoreError(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatalf("initialize store: %v", err)
	}
	claimCommandAdmin(t, st)
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	db := commandDB(t, dataDir)
	if _, err := db.Exec(`CREATE TRIGGER fail_reset_token BEFORE INSERT ON meta
		WHEN NEW.key = 'reset_token_hash'
		BEGIN SELECT RAISE(ABORT, 'reset token insert failed'); END`); err != nil {
		t.Fatalf("create reset trigger: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close trigger database: %v", err)
	}
	if err := adminReset(); err == nil || !strings.Contains(err.Error(), "reset token insert failed") {
		t.Fatalf("adminReset error = %v", err)
	}
}

func TestServeContextReportsSetupTokenError(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatalf("initialize store: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	db := commandDB(t, dataDir)
	if _, err := db.Exec(`DROP TABLE admin`); err != nil {
		t.Fatalf("drop admin table: %v", err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_setup_token BEFORE INSERT ON meta
		WHEN NEW.key = 'setup_token_hash'
		BEGIN SELECT RAISE(ABORT, 'setup token insert failed'); END`); err != nil {
		t.Fatalf("create setup trigger: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close trigger database: %v", err)
	}
	if err := serveContext(context.Background()); err == nil || !strings.Contains(err.Error(), "setup token insert failed") {
		t.Fatalf("serveContext error = %v", err)
	}
}

func TestServeContextReportsVersionTrackingError(t *testing.T) {
	previousVersion := version
	version = "test"
	t.Cleanup(func() { version = previousVersion })
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatalf("initialize store: %v", err)
	}
	setupToken, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatalf("create setup token: %v", err)
	}
	if err := st.Claim(context.Background(), setupToken, "a sufficiently strong test password"); err != nil {
		t.Fatalf("claim setup token: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	db := commandDB(t, dataDir)
	if _, err := db.Exec(`CREATE TRIGGER fail_app_version BEFORE INSERT ON meta
		WHEN NEW.key = 'app_version'
		BEGIN SELECT RAISE(ABORT, 'app version insert failed'); END`); err != nil {
		t.Fatalf("create version trigger: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close trigger database: %v", err)
	}
	if err := serveContext(context.Background()); err == nil || !strings.Contains(err.Error(), "app version insert failed") {
		t.Fatalf("serveContext error = %v", err)
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
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	claimCommandAdmin(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
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

func TestEvidenceVerifyRejectsOversizedInputs(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	oversizedPack := filepath.Join(dataDir, "oversized.json")
	if err := os.WriteFile(oversizedPack, make([]byte, store.EvidencePackLimitBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evidenceVerify([]string{"-file", oversizedPack}); !errors.Is(err, store.ErrEvidencePackTooLarge) {
		t.Fatalf("oversized evidence pack error=%v", err)
	}
	smallPack := filepath.Join(dataDir, "small.json")
	if err := os.WriteFile(smallPack, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedKey := filepath.Join(dataDir, "oversized.key")
	if err := os.WriteFile(oversizedKey, make([]byte, store.EvidencePublicKeyLimitBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evidenceVerify([]string{"-file", smallPack, "-public-key", oversizedKey}); err == nil || !strings.Contains(err.Error(), "evidence public key exceeds") {
		t.Fatalf("oversized evidence public key error=%v", err)
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

func TestAdminRekeyRotatesConfiguredStore(t *testing.T) {
	dataDir := t.TempDir()
	oldKeyPath := configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(context.Background(), store.Settings{
		Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret",
		MattermostURL:  "https://mattermost.example/hooks/token",
		DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute,
	}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	newKeyPath := filepath.Join(dataDir, "master.key.new")
	newKey := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(newKeyPath, []byte(base64.StdEncoding.EncodeToString(newKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adminRekey(nil); err == nil || !strings.Contains(err.Error(), "new-key-file is required") {
		t.Fatal("adminRekey accepted a missing replacement key path")
	}
	if err := adminRekey([]string{"-new-key-file", newKeyPath}); err != nil {
		t.Fatalf("adminRekey failed: %v", err)
	}
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", newKeyPath)
	_, reopened, err := load()
	if err != nil {
		t.Fatalf("reopen with rotated key failed: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Settings(context.Background()); err != nil {
		t.Fatalf("rotated settings could not be decrypted: %v", err)
	}
	if _, err := os.Stat(oldKeyPath); err != nil {
		t.Fatalf("original key file disappeared during rekey: %v", err)
	}
}

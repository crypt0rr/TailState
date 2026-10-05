package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestHelpExitsZeroAtEveryLevel proves that help is reachable from the top
// level, every command group, and every command, prints usage on standard
// output, succeeds, and never touches the data directory.
func TestHelpExitsZeroAtEveryLevel(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	cases := [][]string{
		{"help"}, {"-h"}, {"--help"}, {"-help"},
		{"help", "help"}, {"help", "serve"}, {"help", "doctor"}, {"help", "admin"}, {"help", "admin", "backup"}, {"help", "evidence"}, {"help", "evidence", "verify"}, {"help", "version"},
		{"serve", "-h"}, {"serve", "--help"},
		{"healthcheck", "-h"}, {"healthcheck", "--help"},
		{"doctor", "-h"}, {"doctor", "--help"},
		{"admin", "-h"}, {"admin", "--help"}, {"admin", "help"},
		{"admin", "reset", "-h"}, {"admin", "rekey", "--help"}, {"admin", "backup", "-h"},
		{"evidence", "-h"}, {"evidence", "help"},
		{"evidence", "verify", "-h"}, {"evidence", "audit", "--help"}, {"evidence", "public-key", "-h"},
		{"version", "-h"},
	}
	for _, args := range cases {
		os.Args = append([]string{"tailstate"}, args...)
		output, err := captureStdout(t, run)
		if err != nil || exitCode(err) != exitOK {
			t.Fatalf("%q returned %v (exit %d)", args, err, exitCode(err))
		}
		if !strings.Contains(output, "Usage: tailstate") {
			t.Fatalf("%q printed no usage on stdout: %q", args, output)
		}
	}
	if output, _ := captureStdout(t, func() error { os.Args = []string{"tailstate", "doctor", "-h"}; return run() }); !strings.Contains(output, "-json") {
		t.Fatalf("doctor help omitted its options: %q", output)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tailstate.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("help created a database: %v", err)
	}
}

func TestUsageErrorsReportExitCodeTwo(t *testing.T) {
	configureCommandEnvironment(t, t.TempDir())
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	cases := [][]string{
		{"unknown"}, {"admin"}, {"admin", "unknown"}, {"evidence"}, {"evidence", "unknown"},
		{"doctor", "-bad-flag"}, {"doctor", "extra"}, {"healthcheck", "-bad"}, {"serve", "extra"},
		{"admin", "backup"}, {"admin", "rekey"}, {"admin", "reset", "extra"}, {"evidence", "public-key", "extra"},
		{"help", "nonexistent"}, {"version", "extra"},
	}
	for _, args := range cases {
		os.Args = append([]string{"tailstate"}, args...)
		output, err := captureStdout(t, run)
		if exitCode(err) != exitUsage {
			t.Fatalf("%q returned %v (exit %d), want usage exit", args, err, exitCode(err))
		}
		if output != "" {
			t.Fatalf("%q wrote to stdout on a usage error: %q", args, output)
		}
		var stderr bytes.Buffer
		if code := reportError(&stderr, err); code != exitUsage || !strings.Contains(stderr.String(), "Usage: tailstate") {
			t.Fatalf("%q reported code %d with %q", args, code, stderr.String())
		}
	}
}

func TestExitCodeClassification(t *testing.T) {
	if exitCode(nil) != exitOK || exitCode(errors.New("boom")) != exitRuntime {
		t.Fatal("nil or plain errors are misclassified")
	}
	wrapped := errors.Join(errors.New("context"), findingsError(errors.New("tampered")))
	if exitCode(wrapped) != exitFindings {
		t.Fatalf("wrapped findings error exit=%d", exitCode(wrapped))
	}
	var buffer bytes.Buffer
	configureLogging(&buffer)
	t.Cleanup(func() { configureLogging(os.Stderr) })
	if code := reportError(&buffer, findingsError(errors.New("doctor found blocking deployment issues"))); code != exitFindings {
		t.Fatalf("findings exit=%d", code)
	}
	var record map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil || record["exit_code"] != float64(exitFindings) {
		t.Fatalf("runtime error log is not JSON with an exit code: %q (%v)", buffer.String(), err)
	}
}

// TestCLIHelperProcess is re-executed by TestCLIProcessExitCodes to observe
// real process exit codes; it does nothing in a normal test run.
func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("TAILSTATE_CLI_HELPER") != "1" {
		t.Skip("helper process only")
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("TAILSTATE_CLI_ARGS")), &args); err != nil {
		os.Exit(99)
	}
	os.Args = append([]string{"tailstate"}, args...)
	main()
	os.Exit(0)
}

// TestCLIProcessExitCodes verifies the documented exit-code contract end to
// end: 0 success/help, 1 runtime error, 2 usage error, 3 failed check.
func TestCLIProcessExitCodes(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	pack, err := st.ExportEvidencePack(context.Background(), store.HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(pack, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["content_sha256"] = strings.Repeat("0", 64)
	tampered, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(dataDir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		args   []string
		env    []string
		code   int
		stdout string
		stderr string
	}{
		{name: "help", args: []string{"help"}, code: exitOK, stdout: "Exit codes:"},
		{name: "doctor -h", args: []string{"doctor", "-h"}, code: exitOK, stdout: "Usage: tailstate doctor"},
		{name: "unknown command", args: []string{"bogus"}, code: exitUsage, stderr: "Usage: tailstate"},
		{name: "backup without -out", args: []string{"admin", "backup"}, code: exitUsage, stderr: "-out is required"},
		{name: "missing evidence file", args: []string{"evidence", "verify", "-file", filepath.Join(dataDir, "missing.json")}, code: exitRuntime, stderr: `"exit_code":1`},
		{name: "tampered evidence", args: []string{"evidence", "verify", "-file", tamperedPath}, code: exitFindings, stderr: `"exit_code":3`},
		{name: "doctor blocking finding", args: []string{"doctor"}, env: []string{"TAILSTATE_DATABASE_LIMIT_BYTES=4096"}, code: exitFindings, stdout: "storage_pressure"},
		{name: "invalid configuration", args: []string{"admin", "reset"}, env: []string{"TAILSTATE_MASTER_KEY_FILE=" + filepath.Join(dataDir, "missing.key")}, code: exitRuntime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, _ := json.Marshal(tc.args)
			command := exec.Command(os.Args[0], "-test.run=^TestCLIHelperProcess$")
			command.Env = append(append(os.Environ(), "TAILSTATE_CLI_HELPER=1", "TAILSTATE_CLI_ARGS="+string(encoded)), tc.env...)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.code {
				t.Fatalf("exit=%d want %d stdout=%q stderr=%q", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.stdout) || !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stdout=%q (want %q) stderr=%q (want %q)", stdout.String(), tc.stdout, stderr.String(), tc.stderr)
			}
		})
	}
}

// TestEarlyStartupLogsAreJSON proves the JSON handler and configured level are
// installed before the store opens, so schema migration logs are structured.
func TestEarlyStartupLogsAreJSON(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	t.Setenv("TAILSTATE_LOG_LEVEL", "debug")
	writeOlderSchemaDatabase(t, filepath.Join(dataDir, "tailstate.db"))
	originalArgs, originalContext := os.Args, serveBaseContext
	t.Cleanup(func() {
		os.Args, serveBaseContext = originalArgs, originalContext
		configureLogging(os.Stderr)
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	timer := time.AfterFunc(time.Second, cancel)
	t.Cleanup(func() { timer.Stop() })
	serveBaseContext = func() context.Context { return ctx }
	os.Args = []string{"tailstate", "serve"}
	output, err := captureStdout(t, run)
	if err != nil {
		t.Fatalf("serve returned %v; output=%q", err, output)
	}
	sawMigration := false
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("serve emitted a non-JSON log line %q: %v", line, err)
		}
		if message, _ := record["msg"].(string); strings.Contains(message, "migration") {
			sawMigration = true
		}
	}
	if !sawMigration {
		t.Fatalf("no JSON migration log in %q", output)
	}
}

func TestHealthcheckURLFollowsListenAddress(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8080":     "http://127.0.0.1:8080/healthz",
		"0.0.0.0:9090":       "http://127.0.0.1:9090/healthz",
		":7070":              "http://127.0.0.1:7070/healthz",
		"[::]:6060":          "http://[::1]:6060/healthz",
		"[::1]:5050":         "http://[::1]:5050/healthz",
		"192.0.2.10:8443":    "http://192.0.2.10:8443/healthz",
		"localhost:8081":     "http://localhost:8081/healthz",
		" 0.0.0.0:8082 ":     "http://127.0.0.1:8082/healthz",
		"[::ffff:0.0.0.0]:1": "http://127.0.0.1:1/healthz",
	}
	for listen, want := range cases {
		got, err := healthcheckURL(listen)
		if err != nil || got != want {
			t.Fatalf("healthcheckURL(%q)=%q,%v want %q", listen, got, err, want)
		}
	}
	for _, invalid := range []string{"8080", "127.0.0.1:", ""} {
		if _, err := healthcheckURL(invalid); err == nil {
			t.Fatalf("healthcheckURL(%q) accepted an invalid address", invalid)
		}
	}
}

// TestHealthcheckFollowsCustomPort proves a changed TAILSTATE_LISTEN_ADDR
// (including the container's wildcard host) keeps the healthcheck working
// without a -url override, and that -url still overrides it.
func TestHealthcheckFollowsCustomPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

	t.Setenv("TAILSTATE_LISTEN_ADDR", "0.0.0.0:"+port)
	if err := healthcheck(nil); err != nil {
		t.Fatalf("healthcheck on wildcard custom port failed: %v", err)
	}
	t.Setenv("TAILSTATE_LISTEN_ADDR", "127.0.0.1:"+port)
	if err := healthcheck(nil); err != nil {
		t.Fatalf("healthcheck on loopback custom port failed: %v", err)
	}
	t.Setenv("TAILSTATE_LISTEN_ADDR", "not-an-address")
	if err := healthcheck(nil); err == nil || !strings.Contains(err.Error(), "TAILSTATE_LISTEN_ADDR") {
		t.Fatalf("invalid listen address error=%v", err)
	}
	if err := healthcheck([]string{"-url", "http://127.0.0.1:" + port + "/healthz"}); err != nil {
		t.Fatalf("-url override failed: %v", err)
	}
	if err := os.Unsetenv("TAILSTATE_LISTEN_ADDR"); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck([]string{"-url", "http://127.0.0.1:" + port + "/missing"}); err == nil {
		t.Fatal("-url override was ignored")
	}
}

// TestServePortConflictExitsBeforePolling proves the listener is bound before
// the engine starts: an occupied port stops serve before any collector poll,
// delivery, setup-token write, or update notification.
func TestServePortConflictExitsBeforePolling(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	t.Setenv("TAILSTATE_LISTEN_ADDR", occupied.Addr().String())
	originalStart := startEngine
	t.Cleanup(func() { startEngine = originalStart })
	var started bool
	startEngine = func(context.Context, *monitor.Engine) { started = true }

	err = serveContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("serve on an occupied port returned %v", err)
	}
	if started {
		t.Fatal("engine started before the listener was bound")
	}
	db := commandDB(t, dataDir)
	for _, table := range []string{"auth_tokens", "outbox"} {
		var rows int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 0 {
			t.Fatalf("%s has %d rows after a port conflict", table, rows)
		}
	}
}

func TestServeStartsEngineAfterBinding(t *testing.T) {
	configureCommandEnvironment(t, t.TempDir())
	originalStart := startEngine
	t.Cleanup(func() { startEngine = originalStart })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startEngine = func(ctx context.Context, engine *monitor.Engine) {
		engine.Run(ctx)
		cancel()
	}
	if err := serveContext(ctx); err != nil {
		t.Fatalf("serve returned %v", err)
	}
}

// TestAdminBackupProducesRestorableSnapshotWhileServing takes online
// snapshots while another handle writes continuously, then proves each
// snapshot matches its checksum and opens as a working TailState database.
func TestAdminBackupProducesRestorableSnapshotWhileServing(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, serving, err := load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serving.Close() })
	claimCommandAdmin(t, serving)
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var servingErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			hash := make([]byte, 32)
			_, _ = rand.Read(hash)
			if _, _, err := serving.RecordWebhookTrigger(ctx, hex.EncodeToString(hash), []string{"nodeCreated"}, nil); err != nil {
				servingErr = err
				return
			}
		}
	}()
	backupDir := t.TempDir()
	var snapshots []string
	for i := range 3 {
		out := filepath.Join(backupDir, "snapshot-"+strconv.Itoa(i)+".db")
		output, err := captureStdout(t, func() error { return adminBackup([]string{"-out", out}) })
		if err != nil || !strings.Contains(output, "TailState backup written") {
			close(stop)
			wg.Wait()
			t.Fatalf("admin backup during serve writes output=%q err=%v", output, err)
		}
		snapshots = append(snapshots, out)
	}
	close(stop)
	wg.Wait()
	if servingErr != nil {
		t.Fatalf("serve writes failed during backup: %v", servingErr)
	}
	box, err := storeBoxFromCommandKey(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range snapshots {
		data, err := os.ReadFile(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot mode=%v, want 0600", info.Mode().Perm())
		}
		checksum, err := os.ReadFile(snapshot + ".sha256")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if want := hex.EncodeToString(sum[:]) + "  " + filepath.Base(snapshot) + "\n"; string(checksum) != want {
			t.Fatalf("checksum file=%q want %q", checksum, want)
		}
		restoreDir := t.TempDir()
		restored := filepath.Join(restoreDir, "tailstate.db")
		if err := os.WriteFile(restored, data, 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(restored, box)
		if err != nil {
			t.Fatalf("restore snapshot %s: %v", snapshot, err)
		}
		exists, err := st.AdminExists(ctx)
		if closeErr := st.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil || !exists {
			t.Fatalf("restored snapshot lost the administrator: exists=%t err=%v", exists, err)
		}
	}
	if _, err := captureStdout(t, func() error { return adminBackup([]string{"-out", snapshots[0]}) }); !errors.Is(err, store.ErrBackupTargetExists) || exitCode(err) != exitRuntime {
		t.Fatalf("backup over an existing snapshot err=%v", err)
	}
}

// TestAdminBackupNeverCreatesOrMigratesDatabases proves backup leaves a
// missing database missing and an older-schema database byte-identical.
func TestAdminBackupNeverCreatesOrMigratesDatabases(t *testing.T) {
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	out := filepath.Join(t.TempDir(), "backup.db")
	if _, err := captureStdout(t, func() error { return adminBackup([]string{"-out", out}) }); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing database backup err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tailstate.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created a database: %v", err)
	}
	path := filepath.Join(dataDir, "tailstate.db")
	before := writeOlderSchemaDatabase(t, path)
	if _, err := captureStdout(t, func() error { return adminBackup([]string{"-out", out}) }); err != nil {
		t.Fatalf("older-schema backup failed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("backup modified an older-schema database")
	}
	t.Setenv("TAILSTATE_MASTER_KEY_FILE", filepath.Join(dataDir, "missing.key"))
	if _, err := captureStdout(t, func() error { return adminBackup([]string{"-out", out + ".2"}) }); err == nil || !strings.Contains(err.Error(), "admin backup") {
		t.Fatalf("missing key backup err=%v", err)
	}
}

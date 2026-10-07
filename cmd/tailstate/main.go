package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
	webui "github.com/crypt0rr/tailstate/internal/web"
)

var version = "dev"

func main() {
	restrictFileCreationMask()
	if err := run(); err != nil {
		os.Exit(reportError(os.Stderr, err))
	}
}

// run dispatches os.Args. Logging is configured first so every later log
// record, including configuration errors and store migration progress, is
// JSON at the configured level. serve logs to standard output as before;
// other commands log to standard error so their standard output stays
// machine-readable.
func run() error {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "serve" {
		configureLogging(os.Stdout)
	} else {
		configureLogging(os.Stderr)
	}
	return dispatch(args)
}

func load() (boot.Config, *store.Store, error) {
	config, err := boot.Load(version)
	if err != nil {
		return boot.Config{}, nil, err
	}
	key, err := config.MasterKey()
	if err != nil {
		return boot.Config{}, nil, err
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return boot.Config{}, nil, err
	}
	st, err := store.OpenWithLimits(config.DatabasePath(), box, store.StorageLimits{
		SnapshotBytes:    config.StorageLimits.SnapshotBytes,
		EventValueBytes:  config.StorageLimits.EventValueBytes,
		HistoryPageBytes: config.StorageLimits.HistoryPageBytes,
		RejectBytes:      config.StorageLimits.RejectBytes,
		DatabaseBytes:    config.StorageLimits.DatabaseBytes,
	})
	return config, st, err
}

// serveBaseContext and startEngine are test seams for the serve lifecycle.
var (
	serveBaseContext = context.Background
	startEngine      = func(ctx context.Context, engine *monitor.Engine) { engine.Run(ctx) }
)

func serve() error {
	ctx, stop := signal.NotifyContext(serveBaseContext(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serveContext(ctx)
}

func serveContext(ctx context.Context) error {
	// Hold the service lock for the process lifetime so offline maintenance
	// (admin compact) refuses to run while the service is up. The kernel
	// drops it if the process dies.
	config, err := boot.Load(version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.DataDir, 0o700); err != nil {
		return err
	}
	lock, err := store.LockService(config.DatabasePath())
	if err != nil {
		return err
	}
	defer lock.Release()
	config, st, err := load()
	if err != nil {
		return err
	}
	defer st.Close()
	if config.ContainerWildcardListener() {
		slog.Info("container listener accepts connections on all container interfaces; the published host port controls exposure")
	} else if config.InsecureHTTPListener() {
		slog.Warn("authenticated UI is exposed on a non-loopback plaintext listener; configure TAILSTATE_COOKIE_SECURE=true behind a trusted HTTPS proxy or bind TAILSTATE_LISTEN_ADDR to loopback")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	engine := monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, version)
	engine.ConfigureNotifications(config.InstanceLabel, config.PublicURL)
	server, err := webui.New(config, st, engine)
	if err != nil {
		return err
	}
	// Bind before any startup write or engine work: an address conflict
	// must stop the process before a collector polls or a notification is
	// delivered (or the version-update notification is queued).
	listener, err := server.Listen()
	if err != nil {
		return err
	}
	serving := false
	defer func() {
		if !serving {
			_ = listener.Close()
		}
	}()
	exists, err := st.AdminExists(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	if !exists {
		token, err := st.NewSetupToken(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		slog.Warn("installation is unclaimed; open /setup and use the one-time setup token", "setup_token", token)
	}
	// The tailnet is only needed for the update notification's context; an
	// unconfigured installation queues no notification.
	messages := notify.Context{Label: config.InstanceLabel, PublicURL: config.PublicURL, Version: version}
	if settings, settingsErr := st.Settings(ctx); settingsErr == nil {
		messages.Tailnet = settings.Tailnet
	}
	notified, err := st.TrackAppVersion(ctx, version, func(previous, current string) notify.Message {
		return messages.Update(previous, current, time.Now())
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("track TailState version: %w", err)
	}
	if notified {
		slog.Info("TailState update notification queued", "version", version)
	}
	startEngine(ctx, engine)
	defer func() {
		cancel()
		engine.Wait()
	}()
	serving = true
	if err := server.ServeListener(ctx, listener); errors.Is(err, context.Canceled) {
		return nil
	} else {
		return err
	}
}

func healthcheck(args []string) error {
	flags := newFlagSet("healthcheck")
	url := flags.String("url", "", "health endpoint URL (default: derived from TAILSTATE_LISTEN_ADDR)")
	if done, err := parseFlags("healthcheck", flags, args); done {
		return err
	}
	target := strings.TrimSpace(*url)
	if target == "" {
		listen, ok := os.LookupEnv("TAILSTATE_LISTEN_ADDR")
		if !ok {
			listen = "127.0.0.1:8080"
		}
		derived, err := healthcheckURL(listen)
		if err != nil {
			return err
		}
		target = derived
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %d", resp.StatusCode)
	}
	return nil
}

func doctor(args []string) error {
	flags := newFlagSet("doctor")
	jsonOutput := flags.Bool("json", false, "write the report as JSON")
	if done, err := parseFlags("doctor", flags, args); done {
		return err
	}
	config, err := boot.Load(version)
	if err != nil {
		return fmt.Errorf("doctor configuration: %w", err)
	}
	configuredProfile := store.StorageLimits{
		SnapshotBytes:    config.StorageLimits.SnapshotBytes,
		EventValueBytes:  config.StorageLimits.EventValueBytes,
		HistoryPageBytes: config.StorageLimits.HistoryPageBytes,
		RejectBytes:      config.StorageLimits.RejectBytes,
		DatabaseBytes:    config.StorageLimits.DatabaseBytes,
	}
	configuredLimits, err := store.NormalizeStorageLimits(configuredProfile)
	if err != nil {
		return fmt.Errorf("doctor storage limits: %w", err)
	}
	runtime := diagnostics.Runtime{
		Storage: diagnostics.StorageRuntime{
			SnapshotLimitBytes:    configuredLimits.SnapshotBytes,
			EventValueLimitBytes:  configuredLimits.EventValueBytes,
			HistoryPageLimitBytes: configuredLimits.HistoryPageBytes,
			RejectLimitBytes:      configuredLimits.RejectBytes,
			DatabaseLimitBytes:    configuredLimits.DatabaseBytes,
			ConfiguredProfile:     diagnosticsStorageProfile(configuredLimits),
		},
	}
	if _, err := os.Stat(config.DatabasePath()); errors.Is(err, os.ErrNotExist) {
		runtime.DatabaseMissing = true
		return writeDoctorReport(diagnostics.Build(config, runtime, nil), *jsonOutput)
	} else if err != nil {
		return fmt.Errorf("doctor database path: %w", err)
	}
	key, err := config.MasterKey()
	if err != nil {
		return fmt.Errorf("doctor master key: %w", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return fmt.Errorf("doctor master key: %w", err)
	}
	st, inspection, err := store.OpenReadOnly(config.DatabasePath(), box, configuredProfile)
	if err != nil {
		return fmt.Errorf("doctor database: %w", err)
	}
	defer st.Close()

	runtime.SchemaVersion = inspection.SchemaVersion
	runtime.SchemaMigrationPending = inspection.SchemaMigrationPending
	runtime.Storage = diagnostics.StorageRuntime{
		SnapshotLimitBytes:    inspection.EffectiveStorageLimits.SnapshotBytes,
		EventValueLimitBytes:  inspection.EffectiveStorageLimits.EventValueBytes,
		HistoryPageLimitBytes: inspection.EffectiveStorageLimits.HistoryPageBytes,
		RejectLimitBytes:      inspection.EffectiveStorageLimits.RejectBytes,
		DatabaseLimitBytes:    inspection.EffectiveStorageLimits.DatabaseBytes,
		ConfiguredProfile:     diagnosticsStorageProfile(inspection.ConfiguredStorageLimits),
	}
	if inspection.PersistedStorageFound {
		runtime.Storage.PersistedProfile = diagnosticsStorageProfile(inspection.PersistedStorageLimits)
	}
	if inspection.SchemaVersionPresent && !inspection.SchemaMigrationPending {
		status, statusErr := st.Status(context.Background())
		if statusErr != nil {
			return fmt.Errorf("doctor status: %w", statusErr)
		}
		runtime.Configured = status.Configured
		runtime.BaselineReady = status.BaselineReady
		runtime.BaselineDegraded = status.BaselineDegraded
		runtime.BaselineReason = status.BaselineReason
		runtime.Destinations = status.Destinations
		runtime.EnabledDestinations = status.EnabledDestinations
	}
	if storage, storageErr := st.StorageMetrics(context.Background()); storageErr == nil {
		runtime.Storage.DatabaseLimitBytes = storage.DatabaseLimitBytes
		runtime.Storage.DatabaseBytes = storage.DatabaseBytes
		runtime.Storage.DatabaseUsedBytes = storage.DatabaseUsedBytes
		runtime.Storage.DatabaseFreelistPages = storage.DatabaseFreelistPages
		runtime.Storage.DatabaseFreeBytes = storage.DatabaseFreeBytes
		runtime.Storage.DatabaseFileBytes = storage.DatabaseFileBytes
		runtime.Storage.DatabaseWALBytes = storage.DatabaseWALBytes
		runtime.Storage.DatabaseSHMBytes = storage.DatabaseSHMBytes
		runtime.Storage.DatabasePhysicalBytes = storage.DatabasePhysicalBytes
		runtime.Storage.StoragePressure = storage.PressureRatio()
		runtime.Storage.SnapshotTruncations = storage.SnapshotTruncations
		runtime.Storage.EventValueTruncations = storage.EventValueTruncations
		runtime.Storage.HistoryPageTruncations = storage.HistoryPageTruncations
		runtime.Storage.OversizedWritesRejected = storage.OversizedWritesRejected
	}
	return writeDoctorReport(diagnostics.Build(config, runtime, nil), *jsonOutput)
}

func diagnosticsStorageProfile(limits store.StorageLimits) *diagnostics.StorageProfile {
	return &diagnostics.StorageProfile{
		SnapshotLimitBytes:    limits.SnapshotBytes,
		EventValueLimitBytes:  limits.EventValueBytes,
		HistoryPageLimitBytes: limits.HistoryPageBytes,
		RejectLimitBytes:      limits.RejectBytes,
		DatabaseLimitBytes:    limits.DatabaseBytes,
	}
}

func writeDoctorReport(report diagnostics.Report, jsonOutput bool) error {
	if jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return fmt.Errorf("write doctor report: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stdout, "TailState deployment doctor: %s\n", report.State)
		fmt.Fprintf(os.Stdout, "Listener: %s\n", report.Listener)
		fmt.Fprintf(os.Stdout, "Secure cookies: %t\n", report.CookieSecure)
		fmt.Fprintf(os.Stdout, "Trusted proxies: %d\n", report.TrustedProxyCount)
		if report.DatabaseMissing {
			fmt.Fprintln(os.Stdout, "Database: not initialized")
		} else if report.SchemaVersion > 0 {
			fmt.Fprintf(os.Stdout, "Database schema: %d\n", report.SchemaVersion)
		}
		fmt.Fprintf(os.Stdout, "Storage: %d/%d bytes used (snapshot limit %d, event limit %d, history page limit %d)\n", report.Storage.DatabaseUsedBytes, report.Storage.DatabaseLimitBytes, report.Storage.SnapshotLimitBytes, report.Storage.EventValueLimitBytes, report.Storage.HistoryPageLimitBytes)
		fmt.Fprintf(os.Stdout, "Allocated: %d bytes, of which %d bytes in %d free pages\n", report.Storage.DatabaseBytes, report.Storage.DatabaseFreeBytes, report.Storage.DatabaseFreelistPages)
		if report.Storage.ConfiguredProfile != nil {
			fmt.Fprintf(os.Stdout, "Configured storage profile: snapshot %d, event %d, history page %d, reject %d, database %d bytes\n", report.Storage.ConfiguredProfile.SnapshotLimitBytes, report.Storage.ConfiguredProfile.EventValueLimitBytes, report.Storage.ConfiguredProfile.HistoryPageLimitBytes, report.Storage.ConfiguredProfile.RejectLimitBytes, report.Storage.ConfiguredProfile.DatabaseLimitBytes)
		}
		if report.Storage.PersistedProfile != nil {
			fmt.Fprintf(os.Stdout, "Persisted storage profile: snapshot %d, event %d, history page %d, reject %d, database %d bytes\n", report.Storage.PersistedProfile.SnapshotLimitBytes, report.Storage.PersistedProfile.EventValueLimitBytes, report.Storage.PersistedProfile.HistoryPageLimitBytes, report.Storage.PersistedProfile.RejectLimitBytes, report.Storage.PersistedProfile.DatabaseLimitBytes)
		}
		fmt.Fprintf(os.Stdout, "Physical storage: main=%d wal=%d shm=%d total=%d bytes\n", report.Storage.DatabaseFileBytes, report.Storage.DatabaseWALBytes, report.Storage.DatabaseSHMBytes, report.Storage.DatabasePhysicalBytes)
		for _, finding := range report.Findings {
			fmt.Fprintf(os.Stdout, "%s [%s] %s\n  %s\n", strings.ToUpper(string(finding.Severity)), finding.Code, finding.Summary, finding.Remediation)
		}
		if len(report.Findings) == 0 {
			fmt.Fprintln(os.Stdout, "No deployment findings.")
		}
	}
	if report.HasErrors() {
		return findingsError(errors.New("doctor found blocking deployment issues"))
	}
	return nil
}

// openExisting opens the configured database for a narrow administrative
// write without creating, migrating, or otherwise rewriting it.
func openExisting(command string) (*store.Store, error) {
	config, err := boot.Load(version)
	if err != nil {
		return nil, fmt.Errorf("%s configuration: %w", command, err)
	}
	key, err := config.MasterKey()
	if err != nil {
		return nil, fmt.Errorf("%s master key: %w", command, err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return nil, fmt.Errorf("%s master key: %w", command, err)
	}
	st, err := store.OpenExisting(config.DatabasePath(), box)
	if err != nil {
		return nil, fmt.Errorf("%s database: %w", command, err)
	}
	return st, nil
}

func adminReset() error {
	// Reset must work while serve is running and must never create or
	// migrate a database (a mistyped data directory or a newer image would
	// otherwise do so silently); it writes only the reset token row.
	st, err := openExisting("admin reset")
	if err != nil {
		return err
	}
	defer st.Close()
	token, err := st.NewResetToken(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("Password reset token: %s\nOpen /reset to choose a new administrator password.\n", token)
	return nil
}

func adminRekey(args []string) error {
	flags := newFlagSet("admin rekey")
	newKeyFile := flags.String("new-key-file", "", "path to the replacement raw or base64 master-key file")
	if done, err := parseFlags("admin rekey", flags, args); done {
		return err
	}
	if strings.TrimSpace(*newKeyFile) == "" {
		return usageError("admin rekey", errors.New("-new-key-file is required"))
	}
	_, st, err := load()
	if err != nil {
		return err
	}
	defer st.Close()
	key, err := boot.ReadMasterKeyFile(*newKeyFile)
	if err != nil {
		return err
	}
	newBox, err := secret.NewBox(key)
	if err != nil {
		return err
	}
	if err := st.Rekey(context.Background(), newBox); err != nil {
		return err
	}
	fmt.Printf("TailState master key rotated successfully. Replace the configured key file with %s before restarting the service.\n", *newKeyFile)
	return nil
}

func adminBackup(args []string) error {
	flags := newFlagSet("admin backup")
	out := flags.String("out", "", "snapshot file to create (must not exist); FILE.sha256 is written beside it")
	if done, err := parseFlags("admin backup", flags, args); done {
		return err
	}
	if strings.TrimSpace(*out) == "" {
		return usageError("admin backup", errors.New("-out is required"))
	}
	config, err := boot.Load(version)
	if err != nil {
		return fmt.Errorf("admin backup configuration: %w", err)
	}
	key, err := config.MasterKey()
	if err != nil {
		return fmt.Errorf("admin backup master key: %w", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return fmt.Errorf("admin backup master key: %w", err)
	}
	result, err := store.Backup(context.Background(), config.DatabasePath(), box, *out)
	if err != nil {
		return fmt.Errorf("admin backup: %w", err)
	}
	fmt.Fprintf(os.Stdout, "TailState backup written: %s (%d bytes, schema %d)\nSHA-256: %s (%s)\nKeep the matching master key; the snapshot is unusable without it.\n", result.Path, result.Bytes, result.SchemaVersion, result.SHA256, result.ChecksumPath)
	return nil
}

func adminCompact(args []string) error {
	flags := newFlagSet("admin compact")
	incremental := flags.Bool("incremental-vacuum", false, "also switch the database to auto_vacuum=INCREMENTAL so later cleanup passes release free pages")
	if done, err := parseFlags("admin compact", flags, args); done {
		return err
	}
	config, err := boot.Load(version)
	if err != nil {
		return fmt.Errorf("admin compact configuration: %w", err)
	}
	key, err := config.MasterKey()
	if err != nil {
		return fmt.Errorf("admin compact master key: %w", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return fmt.Errorf("admin compact master key: %w", err)
	}
	result, err := store.Compact(context.Background(), config.DatabasePath(), box, store.CompactOptions{IncrementalVacuum: *incremental})
	if err != nil {
		return fmt.Errorf("admin compact: %w", err)
	}
	fmt.Fprintf(os.Stdout, "TailState database compacted: %d -> %d bytes (%d -> %d pages, %d free pages released); incremental auto-vacuum %t\n",
		result.PagesBefore*result.PageSize, result.PagesAfter*result.PageSize, result.PagesBefore, result.PagesAfter, result.FreePagesBefore-result.FreePagesAfter, result.AutoVacuumEnabled)
	return nil
}

func evidenceVerify(args []string) error {
	flags := newFlagSet("evidence verify")
	file := flags.String("file", "-", "evidence pack path, or - to read standard input")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key path (base64, hexadecimal, or raw)")
	if done, err := parseFlags("evidence verify", flags, args); done {
		return err
	}
	var data []byte
	var err error
	if *file == "-" {
		data, err = readEvidenceInput(os.Stdin, store.EvidencePackLimitBytes, store.ErrEvidencePackTooLarge)
	} else {
		data, err = readEvidenceFile(*file, store.EvidencePackLimitBytes, store.ErrEvidencePackTooLarge)
	}
	if err != nil {
		return fmt.Errorf("read evidence pack: %w", err)
	}
	if *publicKeyPath != "" {
		keyData, err := readEvidenceFile(*publicKeyPath, store.EvidencePublicKeyLimitBytes, fmt.Errorf("evidence public key exceeds %d bytes", store.EvidencePublicKeyLimitBytes))
		if err != nil {
			return fmt.Errorf("read evidence public key: %w", err)
		}
		publicKey, err := store.ParseEvidencePublicKey(keyData)
		if err != nil {
			return fmt.Errorf("parse evidence public key: %w", err)
		}
		if err := store.VerifyEvidencePackWithKey(data, publicKey); err != nil {
			return findingsError(err)
		}
	} else if err := store.VerifyEvidencePack(data); err != nil {
		return findingsError(err)
	}
	// Verification only accepts the signed v3 and v4 formats. Keep the success output
	// explicit so operators and scripts cannot confuse it with an unsigned
	// legacy export (which this command deliberately rejects).
	fmt.Println("signed evidence pack verified")
	return nil
}

func evidenceAudit(args []string) error {
	flags := newFlagSet("evidence audit")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key path (base64, hexadecimal, or raw)")
	batchSize := flags.Int("batch-size", 128, "maximum ledger entries read per page")
	if done, err := parseFlags("evidence audit", flags, args); done {
		return err
	}
	config, err := boot.Load(version)
	if err != nil {
		return fmt.Errorf("evidence audit configuration: %w", err)
	}
	key, err := config.MasterKey()
	if err != nil {
		return fmt.Errorf("evidence audit master key: %w", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return fmt.Errorf("evidence audit master key: %w", err)
	}
	st, err := store.OpenEvidenceReadOnly(config.DatabasePath(), box)
	if err != nil {
		return fmt.Errorf("evidence audit database: %w", err)
	}
	defer st.Close()
	var trustedKey []byte
	if strings.TrimSpace(*publicKeyPath) != "" {
		keyData, err := readEvidenceFile(*publicKeyPath, store.EvidencePublicKeyLimitBytes, fmt.Errorf("evidence public key exceeds %d bytes", store.EvidencePublicKeyLimitBytes))
		if err != nil {
			return fmt.Errorf("read evidence audit public key: %w", err)
		}
		trustedKey, err = store.ParseEvidencePublicKey(keyData)
		if err != nil {
			return fmt.Errorf("parse evidence audit public key: %w", err)
		}
	}
	var cursor, entries, verified, unverifiable int64
	var keyID string
	trusted := len(trustedKey) > 0
	for {
		result, err := st.AuditEvidenceLedger(context.Background(), store.EvidenceAuditOptions{Cursor: cursor, Limit: *batchSize, TrustedPublicKey: trustedKey})
		if err != nil {
			var auditErr *store.EvidenceAuditError
			if errors.As(err, &auditErr) {
				return findingsError(fmt.Errorf("evidence ledger audit: %w", err))
			}
			return fmt.Errorf("evidence ledger audit: %w", err)
		}
		entries += result.Entries
		verified += result.VerifiedEntries
		unverifiable += result.UnverifiableEntries
		if keyID == "" {
			keyID = result.SigningKeyID
		}
		if result.Complete {
			fmt.Printf("evidence ledger audit verified: entries=%d verified=%d unverifiable_payloads=%d key=%s trusted_key=%t\n", entries, verified, unverifiable, keyID, trusted)
			return nil
		}
		if result.NextCursor <= cursor {
			return errors.New("evidence ledger audit did not advance its cursor")
		}
		cursor = result.NextCursor
	}
}

func readEvidenceFile(path string, limit int64, tooLarge error) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readEvidenceInput(file, limit, tooLarge)
}

func readEvidenceInput(input io.Reader, limit int64, tooLarge error) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, tooLarge
	}
	return data, nil
}

func evidencePublicKey() error {
	// Read-only: a missing database, an older schema, or a missing signing
	// key is an error. This command must never create a database or a fresh
	// key that an operator could mistake for the instance's trusted key.
	config, err := boot.Load(version)
	if err != nil {
		return fmt.Errorf("evidence public-key configuration: %w", err)
	}
	key, err := config.MasterKey()
	if err != nil {
		return fmt.Errorf("evidence public-key master key: %w", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return fmt.Errorf("evidence public-key master key: %w", err)
	}
	st, err := store.OpenEvidenceReadOnly(config.DatabasePath(), box)
	if err != nil {
		return fmt.Errorf("evidence public-key database: %w", err)
	}
	defer st.Close()
	public, err := st.EvidenceSigningPublicKey(context.Background())
	if err != nil {
		return err
	}
	fmt.Println(base64.RawStdEncoding.EncodeToString(public))
	return nil
}

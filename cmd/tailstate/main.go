package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
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
	if err := run(); err != nil {
		slog.Error("TailState stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "serve":
		return serve()
	case "healthcheck":
		return healthcheck(os.Args[2:])
	case "doctor":
		return doctor(os.Args[2:])
	case "admin":
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "reset":
				return adminReset()
			case "rekey":
				return adminRekey(os.Args[3:])
			}
		}
		return errors.New("usage: tailstate admin reset or tailstate admin rekey -new-key-file PATH")
	case "evidence":
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "verify":
				return evidenceVerify(os.Args[3:])
			case "audit":
				return evidenceAudit(os.Args[3:])
			case "public-key":
				return evidencePublicKey()
			}
		}
		return errors.New("usage: tailstate evidence audit [-public-key public.key] [-batch-size N], evidence verify [-file evidence.json] [-public-key public.key], or tailstate evidence public-key")
	case "version", "--version", "-version":
		fmt.Printf("tailstate %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (use serve, healthcheck, doctor, admin reset, admin rekey, evidence audit, evidence verify, evidence public-key, or version)", command)
	}
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

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serveContext(ctx)
}

func serveContext(ctx context.Context) error {
	config, st, err := load()
	if err != nil {
		return err
	}
	defer st.Close()
	level := slog.LevelInfo
	if config.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	if config.InsecureHTTPListener() {
		slog.Warn("authenticated UI is exposed on a non-loopback plaintext listener; configure TAILSTATE_COOKIE_SECURE=true behind a trusted HTTPS proxy or bind TAILSTATE_LISTEN_ADDR to loopback")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
	notified, err := st.TrackAppVersion(ctx, version, notify.Update)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("track TailState version: %w", err)
	}
	if notified {
		slog.Info("TailState update notification queued", "version", version)
	}
	engine := monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, version)
	engine.Run(ctx)
	defer func() {
		cancel()
		engine.Wait()
	}()
	server, err := webui.New(config, st, engine)
	if err != nil {
		return err
	}
	if err := server.Serve(ctx); errors.Is(err, context.Canceled) {
		return nil
	} else {
		return err
	}
}

func healthcheck(args []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := flags.String("url", "http://127.0.0.1:8080/healthz", "health endpoint URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(*url)
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
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write the report as JSON")
	if err := flags.Parse(args); err != nil {
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
		fmt.Fprintf(os.Stdout, "Storage: %d/%d bytes (snapshot limit %d, event limit %d, history page limit %d)\n", report.Storage.DatabaseBytes, report.Storage.DatabaseLimitBytes, report.Storage.SnapshotLimitBytes, report.Storage.EventValueLimitBytes, report.Storage.HistoryPageLimitBytes)
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
		return errors.New("doctor found blocking deployment issues")
	}
	return nil
}

func adminReset() error {
	_, st, err := load()
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
	flags := flag.NewFlagSet("admin rekey", flag.ContinueOnError)
	newKeyFile := flags.String("new-key-file", "", "path to the replacement raw or base64 master-key file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*newKeyFile) == "" {
		return errors.New("-new-key-file is required")
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

func evidenceVerify(args []string) error {
	flags := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
	file := flags.String("file", "-", "evidence pack path, or - to read standard input")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key path (base64, hexadecimal, or raw)")
	if err := flags.Parse(args); err != nil {
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
			return err
		}
	} else if err := store.VerifyEvidencePack(data); err != nil {
		return err
	}
	// Verification only accepts the signed v3 format. Keep the success output
	// explicit so operators and scripts cannot confuse it with an unsigned
	// legacy export (which this command deliberately rejects).
	fmt.Println("signed evidence pack verified")
	return nil
}

func evidenceAudit(args []string) error {
	flags := flag.NewFlagSet("evidence audit", flag.ContinueOnError)
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key path (base64, hexadecimal, or raw)")
	batchSize := flags.Int("batch-size", 128, "maximum ledger entries read per page")
	if err := flags.Parse(args); err != nil {
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
	_, st, err := load()
	if err != nil {
		return err
	}
	defer st.Close()
	public, err := st.EvidenceSigningPublicKey(context.Background())
	if err != nil {
		return err
	}
	fmt.Println(base64.RawStdEncoding.EncodeToString(public))
	return nil
}

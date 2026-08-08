package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
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
	case "admin":
		if len(os.Args) > 2 && os.Args[2] == "reset" {
			return adminReset()
		}
		return errors.New("usage: tailstate admin reset")
	case "evidence":
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "verify":
				return evidenceVerify(os.Args[3:])
			case "public-key":
				return evidencePublicKey()
			}
		}
		return errors.New("usage: tailstate evidence verify [-file evidence.json] [-public-key public.key] or tailstate evidence public-key")
	case "version", "--version", "-version":
		fmt.Printf("tailstate %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (use serve, healthcheck, admin reset, evidence verify, evidence public-key, or version)", command)
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
	st, err := store.Open(config.DatabasePath(), box)
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	exists, err := st.AdminExists(ctx)
	if err != nil {
		return err
	}
	if !exists {
		token, err := st.NewSetupToken(ctx)
		if err != nil {
			return err
		}
		slog.Warn("installation is unclaimed; open /setup and use the one-time setup token", "setup_token", token)
	}
	notified, err := st.TrackAppVersion(ctx, version, notify.Update)
	if err != nil {
		return fmt.Errorf("track TailState version: %w", err)
	}
	if notified {
		slog.Info("TailState update notification queued", "version", version)
	}
	engine := monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, version)
	engine.Run(ctx)
	server, err := webui.New(config, st, engine)
	if err != nil {
		return err
	}
	return server.Serve(ctx)
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
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(*file)
	}
	if err != nil {
		return fmt.Errorf("read evidence pack: %w", err)
	}
	if *publicKeyPath != "" {
		keyData, err := os.ReadFile(*publicKeyPath)
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
	fmt.Println("evidence pack verified")
	return nil
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

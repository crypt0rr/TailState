package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Process exit codes. They are part of the operator interface (documented in
// README.md) so scripts can tell "the check ran and found a problem" apart
// from "the command could not run".
const (
	exitOK       = 0
	exitRuntime  = 1 // runtime failure: configuration, I/O, database, network
	exitUsage    = 2 // invalid command line: unknown command, bad or missing flag
	exitFindings = 3 // check completed and failed: doctor errors, evidence verification or ledger audit failure
)

// exitError attaches an exit code, and for usage errors the relevant usage
// text, to a command error.
type exitError struct {
	code  int
	err   error
	usage string
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// usageError reports an invalid command line; main prints the message and the
// command's usage to standard error and exits with exitUsage.
func usageError(command string, err error) error {
	return &exitError{code: exitUsage, err: err, usage: commandUsage(command, nil)}
}

// findingsError marks a completed check whose result is a failure.
func findingsError(err error) error {
	return &exitError{code: exitFindings, err: err}
}

func exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var exit *exitError
	if errors.As(err, &exit) {
		return exit.code
	}
	return exitRuntime
}

// reportError writes the final error and returns the process exit code. Usage
// errors are written as plain text with the usage summary; every other error
// is a structured log record so it matches the rest of the process output.
func reportError(w io.Writer, err error) int {
	code := exitCode(err)
	var exit *exitError
	if errors.As(err, &exit) && exit.code == exitUsage {
		fmt.Fprintf(w, "tailstate: %v\n", err)
		if exit.usage != "" {
			fmt.Fprintf(w, "\n%s", exit.usage)
		}
		return code
	}
	slog.Error("TailState stopped", "error", err, "exit_code", code)
	return code
}

// configureLogging installs the JSON handler and the TAILSTATE_LOG_LEVEL
// level before any command loads configuration or opens the store, so
// configuration errors, migration progress, and evidence backfill logs share
// one structured format. boot.Load still validates the variable; an invalid
// value is reported there after logging falls back to info.
func configureLogging(w io.Writer) {
	level := slog.LevelInfo
	if strings.TrimSpace(os.Getenv("TAILSTATE_LOG_LEVEL")) == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}

var usageText = map[string]string{
	"": `Usage: tailstate <command> [options]

Commands:
  serve                  Run the web UI, collectors, and notification delivery (default)
  healthcheck            Probe the local /healthz endpoint
  doctor                 Report deployment findings without changing the database
  admin reset            Issue a one-time administrator password reset token
  admin rekey            Re-encrypt protected values with a new master key
  admin backup           Write a consistent online database snapshot and checksum
  evidence verify        Verify a signed evidence pack offline
  evidence audit         Audit the persisted evidence ledger
  evidence public-key    Print the evidence signing public key
  version                Print the version
  help [command]         Show help for a command

Every command accepts -h or --help.

Exit codes:
  0  success
  1  runtime error (configuration, I/O, database, or network failure)
  2  usage error (unknown command, invalid or missing option)
  3  check failed (doctor blocking findings, evidence verification or audit failure)
`,
	"serve": `Usage: tailstate serve

Open (and if needed create or migrate) the database, bind TAILSTATE_LISTEN_ADDR,
then start collectors and notification delivery. Configuration is read from
the TAILSTATE_* environment variables described in README.md.
`,
	"healthcheck": `Usage: tailstate healthcheck [-url URL]

Request the health endpoint and exit 0 when it answers 200. Without -url the
address is derived from TAILSTATE_LISTEN_ADDR (default 127.0.0.1:8080); a
wildcard host such as 0.0.0.0 or [::] is probed on loopback.
`,
	"doctor": `Usage: tailstate doctor [-json]

Report deployment findings without creating, migrating, or writing the
database. Exits 3 when a blocking finding is reported.
`,
	"admin": `Usage: tailstate admin <reset|rekey|backup> [options]

  reset      Issue a one-time administrator password reset token
  rekey      Re-encrypt protected values with a new master key (service stopped)
  backup     Write a consistent online database snapshot and checksum
`,
	"admin reset": `Usage: tailstate admin reset

Issue a one-time password reset token. Safe while the service runs; never
creates or migrates a database.
`,
	"admin rekey": `Usage: tailstate admin rekey -new-key-file PATH

Re-encrypt every protected value with the replacement master key. Stop the
service first.
`,
	"admin backup": `Usage: tailstate admin backup -out FILE

Write a transactionally consistent snapshot of the database to FILE with
SQLite VACUUM INTO, plus FILE.sha256. Safe while the service runs; the live
database is opened read-only and is never created or migrated. Existing
files are never overwritten.
`,
	"evidence": `Usage: tailstate evidence <verify|audit|public-key> [options]

  verify       Verify a signed evidence pack offline
  audit        Audit the persisted evidence ledger
  public-key   Print the evidence signing public key
`,
	"evidence verify": `Usage: tailstate evidence verify [-file PATH] [-public-key PATH]

Verify a signed evidence pack. Exits 3 when verification fails.
`,
	"evidence audit": `Usage: tailstate evidence audit [-public-key PATH] [-batch-size N]

Audit the persisted evidence ledger read-only. Exits 3 when the ledger fails
an integrity check.
`,
	"evidence public-key": `Usage: tailstate evidence public-key

Print the evidence signing public key (base64). Read-only.
`,
	"version": `Usage: tailstate version

Print the version.
`,
	"help": `Usage: tailstate help [command]

Show help for a command, for example "tailstate help admin backup".
`,
}

// commandUsage returns the usage text for command, followed by its option
// defaults when a flag set is supplied.
func commandUsage(command string, flags *flag.FlagSet) string {
	text, ok := usageText[command]
	if !ok {
		text = usageText[""]
	}
	if flags == nil {
		return text
	}
	var options bytes.Buffer
	flags.SetOutput(&options)
	flags.PrintDefaults()
	flags.SetOutput(io.Discard)
	if options.Len() == 0 {
		return text
	}
	return text + "\nOptions:\n" + options.String()
}

func newFlagSet(command string) *flag.FlagSet {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	return flags
}

// parseFlags parses args for command. It prints the usage to standard output
// and reports done for -h/--help, and returns a usage error for an invalid
// flag or an unexpected positional argument.
func parseFlags(command string, flags *flag.FlagSet, args []string) (done bool, err error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stdout, commandUsage(command, flags))
			return true, nil
		}
		return true, &exitError{code: exitUsage, err: fmt.Errorf("%s: %w", command, err), usage: commandUsage(command, flags)}
	}
	if flags.NArg() > 0 {
		return true, &exitError{code: exitUsage, err: fmt.Errorf("%s: unexpected argument %q", command, flags.Arg(0)), usage: commandUsage(command, flags)}
	}
	return false, nil
}

func isHelpArgument(arg string) bool {
	switch arg {
	case "help", "-h", "-help", "--help":
		return true
	}
	return false
}

// dispatch runs one command line (without the program name).
func dispatch(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}
	switch command {
	case "help", "-h", "-help", "--help":
		return help(args)
	case "serve":
		if done, err := parseFlags("serve", newFlagSet("serve"), args); done {
			return err
		}
		return serve()
	case "healthcheck":
		return healthcheck(args)
	case "doctor":
		return doctor(args)
	case "admin":
		return dispatchGroup("admin", args, map[string]func([]string) error{
			"reset": func(args []string) error {
				if done, err := parseFlags("admin reset", newFlagSet("admin reset"), args); done {
					return err
				}
				return adminReset()
			},
			"rekey":  adminRekey,
			"backup": adminBackup,
		}, "missing admin subcommand (use admin reset, admin rekey, or admin backup)")
	case "evidence":
		return dispatchGroup("evidence", args, map[string]func([]string) error{
			"verify": evidenceVerify,
			"audit":  evidenceAudit,
			"public-key": func(args []string) error {
				if done, err := parseFlags("evidence public-key", newFlagSet("evidence public-key"), args); done {
					return err
				}
				return evidencePublicKey()
			},
		}, "missing evidence subcommand (use evidence audit [-public-key public.key] [-batch-size N], evidence verify [-file evidence.json] [-public-key public.key], or evidence public-key)")
	case "version", "--version", "-version":
		if done, err := parseFlags("version", newFlagSet("version"), args); done {
			return err
		}
		fmt.Fprintf(os.Stdout, "tailstate %s\n", version)
		return nil
	default:
		return usageError("", fmt.Errorf("unknown command %q (use serve, healthcheck, doctor, admin reset, admin rekey, admin backup, evidence audit, evidence verify, evidence public-key, version, or help)", command))
	}
}

func dispatchGroup(group string, args []string, commands map[string]func([]string) error, missing string) error {
	if len(args) == 0 {
		return usageError(group, errors.New(missing))
	}
	if isHelpArgument(args[0]) {
		fmt.Fprint(os.Stdout, commandUsage(group, nil))
		return nil
	}
	command, ok := commands[args[0]]
	if !ok {
		return usageError(group, fmt.Errorf("unknown %s subcommand %q", group, args[0]))
	}
	return command(args[1:])
}

// help prints the top-level usage, or the usage of the named command by
// dispatching it with -h so the option list always matches the parser.
func help(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, commandUsage("", nil))
		return nil
	}
	name := strings.Join(args, " ")
	switch name {
	case "help", "admin", "evidence":
		fmt.Fprint(os.Stdout, commandUsage(name, nil))
		return nil
	}
	if _, ok := usageText[name]; !ok {
		return usageError("help", fmt.Errorf("no help for unknown command %q", name))
	}
	return dispatch(append(append([]string(nil), args...), "-h"))
}

// healthcheckURL derives the local health endpoint from a listen address. A
// wildcard or empty host accepts loopback connections, so it is probed on the
// loopback address of the same family.
func healthcheckURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return "", fmt.Errorf("TAILSTATE_LISTEN_ADDR must be host:port: %w", err)
	}
	if port == "" {
		return "", errors.New("TAILSTATE_LISTEN_ADDR must include a port")
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		host = "127.0.0.1"
	} else if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.Unmap().IsUnspecified() {
		host = "127.0.0.1"
		if address.Unmap().Is6() {
			host = "::1"
		}
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

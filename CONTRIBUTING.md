# Contributing to TailState

TailState is a read-only Tailscale inventory monitor. Contributions should
preserve that boundary, the encrypted-at-rest credential model, and the
explainable history guarantees described in [README.md](README.md).

## Before opening a change

Use Go 1.26.6 (the version in `go.mod`) and keep changes focused. Do not add
credentials, database files, backup archives, generated coverage output, or
local Compose state to a commit.

Run the same fast checks used by CI:

```console
gofmt -w cmd internal
go mod tidy -diff
go vet ./...
go test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
bash scripts/invariant-suite.sh
go tool staticcheck ./...
go tool govulncheck ./...
git diff --check
```

When changing dependency declarations or the Renovate configuration, also
validate the updater metadata and its local dependency lookup:

```console
npx --yes -p renovate renovate-config-validator renovate.json
RENOVATE_LOG_LEVEL=warn npx --yes -p renovate renovate --platform=local --dry-run=lookup
```

The module tidy check is intentional: Go analysis tools are declared in
`go.mod`, so their content checksums must be present in `go.sum` for a clean
runner to execute `go tool staticcheck` and `go tool govulncheck`.

For container or Compose changes, also run:

```console
docker build --build-arg VERSION=dev -t tailstate:dev .
bash scripts/container-smoke.sh tailstate:dev
bash scripts/compose-smoke.sh tailstate:dev
bash scripts/proxy-smoke.sh tailstate:dev
bash scripts/container-backup-restore-smoke.sh tailstate:dev
```

The invariant tests listed in `.github/invariant-tests.txt` are intentionally
named and should be extended when a change affects security, drift detection,
delivery, persistence, or evidence verification. Keep one exact top-level Go
test name per line; CI rejects malformed or duplicate entries and reports a
stale or failing entry with its manifest line. Add a regression test that
expresses the operator guarantee, not only a branch-coverage test.

The persistence package is split by responsibility: `auth.go` owns setup,
password, session, and token state; `settings.go` owns encrypted application
settings; `snapshots.go` owns collector application and baseline transitions;
`outbox.go` owns notification delivery bookkeeping; `status.go` owns health,
scheduling, and retention queries; and `history.go`, `destinations.go`,
`webhooks.go`, and `migrations.go` contain the corresponding audit, endpoint,
trigger, and schema seams. Keep changes in the narrowest seam and add a store
regression test beside the behavior it protects.

## Data and security rules

- Never log, render, or persist OAuth credentials, webhook secrets, Shoutrrr
  URL credentials, or raw provider error text.
- Keep notification delivery at-least-once and destination-specific; a failed
  destination must not suppress another destination.
- Preserve baselines across transient, unsupported, and partial collector
  responses. A change to normalization or diffing needs a named invariant test.
- Do not rewrite historical evidence or regenerate the Ed25519 signing key
  during a master-key rekey.
- Treat database migrations and restore scripts as recovery-sensitive code;
  test wrong-key startup, rollback/error paths, and unsafe archive entries.

## Pull requests

Describe the user-visible behavior, migration/rollback implications, and the
validation commands you ran. Keep dependency and GitHub Actions updates
pin-aware and explain any change to the release or coverage gates.

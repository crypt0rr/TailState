# TailState

TailState polls the read-only Tailscale API, establishes a silent inventory baseline, and posts later changes to one or more Shoutrrr destinations. It runs as one static Go binary with an embedded setup/status interface and durable SQLite storage.

TailState never modifies a tailnet. Optional signed Tailscale webhooks can
accelerate reconciliation; the read-only polling schedule remains the source
of truth and the safety net for missed events.

## What it monitors

- Devices, stable tailnet IPv4/IPv6 addresses, details, authorization, tags, key expiry, client version, routes, posture attributes, and invites.
- Users and user invites.
- DNS nameservers, preferences, search paths, and split DNS.
- Policy section fingerprints without storing policy contents.
- Credential metadata, webhook configuration inventory, log-streaming configuration/status, contacts, posture integrations, and tailnet settings.

The REST API does not expose authoritative online state. TailState therefore does **not** generate online/offline notifications and ignores `lastSeen`, `connectedToControl`, live user/device connectivity, public endpoints, connectivity metadata, profile-picture URLs, internal rotating node keys, operational status counters, response timestamps, array ordering, and unknown fields outside its monitored schema. Tailscale client-version and `updateAvailable` changes remain alertable.

## Quick start

Requirements: Docker with Compose and a Tailscale OAuth client permitted to request `all:read`.

First, create the local environment file and encryption key:

```console
cp .env.example .env
mkdir -p secrets
openssl rand -base64 32 > secrets/tailstate_master_key
chmod 600 .env secrets/tailstate_master_key
```

### Pull the public image

The default image is `ghcr.io/crypt0rr/tailstate:latest`:

```console
docker compose pull
docker compose up -d
```

To pin a specific release instead of `latest`, set `TAILSTATE_IMAGE` in `.env`, for example:

```dotenv
TAILSTATE_IMAGE=ghcr.io/crypt0rr/tailstate:1.0.0
```

### Build locally

To build TailState from the source in this repository:

```console
docker compose up --build -d
```

After either installation method, inspect the startup log:

```console
docker compose logs tailstate
```

The logs contain a one-time setup token. Open [http://127.0.0.1:8080/setup](http://127.0.0.1:8080/setup), enter that token, and create the administrator password.

The setup interface then asks for:

1. Tailnet (`-` uses the OAuth credential's tailnet).
2. OAuth client ID and secret with `all:read`.
3. At least one notification destination using a Shoutrrr URL.
4. Device and secondary inventory polling intervals.

Add destinations on the authenticated Settings page, then save monitoring settings. Each destination is validated and can be tested independently. TailState then performs a Tailscale API check and builds a silent baseline. The status page shows baseline counts, collector capabilities, source health, and delivery state.

The authenticated **History** page keeps a 30-day, searchable ledger of semantic inventory changes. Each poll is grouped into a batch with the affected collector, resource, previous/current normalized snapshots, field-level differences, and the delivery state for every destination. Use it to investigate a notification without exposing credentials or volatile API fields. The page shows the fingerprint of the Ed25519 key used to sign evidence exports.

### Faster reconciliation with Tailscale webhooks

Polling remains enabled even when webhooks are configured. To reduce the time
between a tailnet change and its explanation in TailState, create a webhook in
the Tailscale admin console and enter its signing secret in **Settings**. Point
the webhook at:

```text
https://tailstate.example/webhooks/tailscale
```

The endpoint accepts the signed event arrays described in the [Tailscale
webhook documentation](https://tailscale.com/docs/features/webhooks). TailState
verifies the HMAC signature and timestamp, rejects oversized or replayed
requests, and stores only a body hash and event metadata before acknowledging
the delivery. A durable worker leases queued triggers, polls the affected
collectors, and retries failures for up to 24 hours across restarts. Unknown
event types trigger a complete reconciliation. The normal TailState poll
interval remains the fallback if the endpoint is unavailable; accepted webhook
triggers are never lost between the HTTP response and reconciliation.

Shoutrrr supports Mattermost natively, for example:

```text
mattermost://TailState@mattermost.example/hooks-token?icon=satellite
```

Any service registered by the pinned Shoutrrr release is accepted. See the [Shoutrrr service overview](https://containrrr.dev/shoutrrr/dev/services/overview/) for supported endpoint schemes and provider-specific URL formats. Generic webhooks can be configured with `generic://` URLs and Shoutrrr query options such as `template=json&messagekey=text`.

```console
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

`/metrics` exposes readiness, pending/dead delivery counts, pending/processing/dead webhook trigger counts, resource counts, and low-cardinality collector health gauges (`supported`, `baseline`, failures, last success, and next poll timestamps) for Prometheus-compatible monitoring.

## Security and persistence

Compose creates the Docker-managed `tailstate-data` volume and stores `/data/tailstate.db` there. Snapshots, events, baseline state, sessions, and the delivery outbox survive container replacement.

OAuth secrets, the Tailscale webhook secret, every Shoutrrr destination URL, and the evidence-ledger private key are encrypted with AES-256-GCM using `secrets/tailstate_master_key`. Destination credentials and webhook secrets are never echoed into HTML, logs, persisted delivery errors, or the history ledger. Normalized history snapshots are retained for 30 days and exclude volatile and secret fields. OAuth access tokens exist only in memory. Back up the master key separately: TailState intentionally refuses to start if the key is missing or incorrect, and encrypted settings and signed history cannot be recovered without it.

The image is scratch-based, runs as UID/GID `10001`, uses a read-only root filesystem, drops every Linux capability, and publishes the UI only on `127.0.0.1` by default. For remote access, place TailState behind an HTTPS reverse proxy and set:

```dotenv
TAILSTATE_BIND_ADDRESS=0.0.0.0
TAILSTATE_COOKIE_SECURE=true
```

Do not expose the setup interface directly to the internet.

### Password reset

Generate a one-time reset token:

```console
docker compose exec tailstate /tailstate admin reset
```

Then open `/reset`. Resetting the password invalidates existing sessions.

### Backup

Use the repository helper to stop TailState, archive the exact data volume, and
write a SHA-256 checksum. The helper discovers the Compose-managed volume from
the service container, so it does not depend on a project name or a hardcoded
volume name:

```console
./scripts/backup.sh ./backups
```

Back up `secrets/tailstate_master_key` separately and securely. A backup is
only useful with the matching master key: TailState intentionally refuses to
open encrypted state with a different key.

Restore into the same Compose project only after confirming the archive and
key are from the same point in time. The command requires an explicit
`--yes`, verifies the checksum when present, rejects unsafe archive paths, and
creates a pre-restore archive beside the source archive before replacing the
data volume:

```console
./scripts/restore.sh ./backups/tailstate-data-20260813T120000Z.tar.gz --yes
docker compose ps
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

After a restore, sign in and verify that the expected History, evidence,
notification destinations, and monitoring settings are present. Keep the
pre-restore archive until that verification is complete. Run a restore drill
in a disposable project before relying on the procedure for an outage.

## Change and delivery behavior

- The first complete supported inventory is a silent baseline.
- Stable additions and modifications alert on the next successful poll.
- Removals require absence from two complete successful polls.
- Failed or partial polls never delete snapshots.
- Multiple changes in one poll become one digest, fanned out into one durable outbox item per enabled destination.
- Every change batch is also recorded in the authenticated History page with field-level diffs and redacted normalized before/after snapshots. Filters support collector, change type, and resource name or ID; history is retained for 30 days.
- The History page can download a filtered, redacted JSON evidence pack for incident reports and offline review. Packs include normalized snapshots, field diffs, destination delivery outcomes, a SHA-256 content hash, and an Ed25519 signature over a hash-linked event ledger; exports are limited to 100 batches, 2,000 events, and 5 MiB. A changed export fails verification.
- Verify an export offline with `tailstate evidence verify --file tailstate-drift-evidence.json`. Verification checks the content hash, embedded public key fingerprint, signature, and included ledger links. For independent trust, print the instance public key with `tailstate evidence public-key`, save it as a base64 file, and pass it with `--public-key public.key`.
- Shoutrrr deliveries retry independently for up to 24 hours across restarts, then remain visible as dead letters. Disabling or removing a destination dead-letters its pending items; newly added destinations receive only future notifications.
- If every destination is disabled, monitoring continues and notifications are reported as paused.
- API collector failures alert after three consecutive failures and once on recovery.
- Plan-specific unavailable endpoints appear as unsupported and retry every six hours.
- Starting a different TailState release queues one durable notification containing the previous and current versions.

Version tracking is introduced in v0.3.0. Its first startup records the release silently because earlier releases did not persist their version; subsequent upgrades include both exact versions in the notification.

### Migration from older releases

On the first startup after this upgrade, an existing encrypted Mattermost webhook is converted automatically to a native `mattermost://` destination when it uses the standard `/hooks/<token>` path. Other paths are preserved as a `generic://` JSON webhook with the existing TailState username and satellite icon. Existing pending outbox items are assigned to the migrated destination. The legacy encrypted column is retained but no longer used for new configuration.

The schema v4 migration also adds encrypted storage for the optional Tailscale
webhook secret, a deduplicated webhook trigger ledger, and trigger IDs on
history batches. Schema v5 adds trigger leases, retry state, and many-to-many
links between coalesced triggers and history batches. Existing installations
start with webhook acceleration disabled until a secret is entered in Settings.
Schema v6 adds the encrypted Ed25519 evidence key and the hash-linked evidence
ledger. Existing event batches are signed automatically on
the first startup after the upgrade; the public-key fingerprint is shown on the
History page and new exports use signed evidence format version 2.

## Runtime configuration

Only bootstrap settings use environment variables; application credentials and
the optional webhook secret are entered in the authenticated UI.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TAILSTATE_LISTEN_ADDR` | `0.0.0.0:8080` | Listener inside the container |
| `TAILSTATE_DATA_DIR` | `/data` | SQLite directory |
| `TAILSTATE_MASTER_KEY_FILE` | `/run/secrets/tailstate_master_key` | 32-byte or base64 master key |
| `TAILSTATE_COOKIE_SECURE` | `false` | Require HTTPS for session cookies |
| `TAILSTATE_LOG_LEVEL` | `info` | `info` or `debug` structured logging |

The test-only `TAILSTATE_TS_API_URL` and `TAILSTATE_TS_OAUTH_URL` variables allow local mock servers; production deployments should leave them unset.

## Local development

TailState uses Go 1.26.5.

```console
gofmt -w cmd internal
go vet ./...
go test -race ./...
docker build -t tailstate:dev .
```

For a local binary, generate a master key and point TailState at a writable data directory:

```console
mkdir -p .local-data secrets
openssl rand -base64 32 > secrets/tailstate_master_key
TAILSTATE_DATA_DIR="$PWD/.local-data" \
TAILSTATE_MASTER_KEY_FILE="$PWD/secrets/tailstate_master_key" \
go run ./cmd/tailstate serve
```

## Releases

Pushing a semantic tag such as `v1.0.0` starts the verified release promotion workflow. The exact tagged commit must pass the reusable CI gate, including tests, coverage, Staticcheck, Govulncheck, an Anchore high-severity scan, runtime healthchecks, backup/restore validation, and a multi-architecture build. Release promotion first pushes one immutable candidate manifest, scans and smoke-tests both platform images by digest, and only then assigns the version, minor, and `latest` tags to that same verified digest. The workflow publishes signed-build metadata, an SBOM, and `linux/amd64` plus `linux/arm64` images to:

```text
ghcr.io/crypt0rr/tailstate
```

The workflow also creates the matching GitHub Release with generated notes. Use the immutable version tag or image digest in deployments; reserve `latest` for development convenience. For a rollback, set `TAILSTATE_IMAGE` to a previously verified digest and keep the matching `secrets/tailstate_master_key` backup available:

```dotenv
TAILSTATE_IMAGE=ghcr.io/crypt0rr/tailstate@sha256:<known-good-digest>
```

The builder and runtime base images are pinned by digest and updated by Renovate, so a release is reproducible until an explicit dependency update changes those pins.

## License

MIT

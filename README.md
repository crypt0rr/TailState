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

The REST API does not expose authoritative online state. TailState therefore does **not** generate online/offline notifications and ignores `lastSeen`, `connectedToControl`, live user/device connectivity, public endpoints, connectivity metadata, profile-picture URLs, internal rotating node keys, operational status counters, response timestamps, ordering in set-like arrays, and unknown fields outside its monitored schema. DNS nameserver and search-path ordering is preserved because position determines resolver behavior. Tailscale client-version and `updateAvailable` changes remain alertable.

## Quick start

Requirements: Docker with Compose and a Tailscale OAuth client permitted to request `all:read`.

First, create the local environment file and encryption key:

```console
cp .env.example .env
mkdir -p secrets
openssl rand -base64 32 > secrets/tailstate_master_key
chmod 600 .env
# The image runs as UID/GID 10001 and must be able to read the mounted secret.
sudo chown 10001:10001 secrets/tailstate_master_key
sudo chmod 400 secrets/tailstate_master_key
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

The logs contain a one-time setup token. Open [http://127.0.0.1:8080/setup](http://127.0.0.1:8080/setup), enter that token, and create the administrator password. Setup tokens expire after 30 minutes; restart the service to issue a fresh token if needed.

After claiming the installation, the authenticated Settings page asks for:

1. Tailnet (`-` uses the OAuth credential's tailnet).
2. OAuth client ID and secret with `all:read`.
3. At least one notification destination using a Shoutrrr URL.
4. Device and secondary inventory polling intervals.

Add destinations on the authenticated Settings page, then save monitoring settings. Each destination is validated and can be tested independently. TailState then performs a Tailscale API check and builds a silent baseline. The status page shows baseline counts, collector capabilities, source health, and delivery state. Rotating the OAuth secret or changing poll intervals refreshes the monitor without discarding the existing baseline; changing the tailnet or OAuth client identity starts a new generation and dead-letters pending event notifications from the previous identity while preserving their history for audit. System and release notifications remain eligible for delivery.

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

`/metrics` exposes readiness, pending/dead delivery counts, notification destination totals and enabled counts (plus a paused gauge when every destination is disabled), pending/processing/dead webhook trigger counts, resource counts, low-cardinality collector health gauges (`supported`, `baseline`, partial-result state, partial error count, failures, poll duration, last success, and next poll timestamps), the scheduler's total database-error counter (`tailstate_collector_due_errors_total`), delivery telemetry (`tailstate_outbox_delivery_attempts_total`, success/failure counters, lease renewal/loss counters, and the `tailstate_outbox_delivery_duration_seconds` histogram), and bounded storage telemetry. Storage metrics include the database size and pressure ratio, configured snapshot/event/history/rejection limits, and counters for snapshot truncation, event-value truncation, history-page truncation, and oversized raw writes represented by a metadata marker. These signals make storage pressure visible without exposing destination URLs, provider bodies, or message contents. The `device_details` collector uses a bounded eight-worker fan-out and a two-minute per-collector deadline; usable partial results are retained and marked in the status page and metrics with the number of failed detail requests. When `TAILSTATE_METRICS_TOKEN` is empty, only a direct loopback connection is accepted; requests from a reverse proxy (including a loopback or trusted proxy), requests with forwarded headers, and non-loopback peers receive `401`. Set that variable for Prometheus or any reverse proxy to require `Authorization: Bearer <token>` from any network location. Do not publish the endpoint without a token through a public reverse proxy.

Retention cleanup is resumable and writer-friendly. Each table is processed in keyset batches of at most 128 rows, each autocommit transaction has a 250 ms deadline, and one pass stops after two seconds; when work remains, the monitor schedules a continuation within one second instead of waiting for the hourly sweep. Cleanup logs include per-table row counts, transaction count, duration, failures, and the remaining-work flag. The same information is available through `tailstate_cleanup_*` metrics. Active notification and webhook leases are never dead-lettered until their lease has expired, and evidence-ledger rows are never removed by retention.

`/readyz` reports each collector's baseline state. It returns `503` while setup
is incomplete or before the first baseline; after the 15-minute first-baseline
grace period, a persistently failing collector is reported as `degraded` and
readiness remains available for orchestration while the collector continues to
retry. The response includes sanitized collector names, baseline flags, and
failure counts plus bounded per-collector reasons (`baseline pending`,
`partial`, `unsupported`, `retrying`, or `healthy`) without upstream error
text. Once a historical baseline exists, readiness remains available while
supported collectors that fail, return partial data, or are still awaiting a
new baseline keep the overall state visibly `degraded`; confirmed
plan-unsupported collectors remain informational.

## Security and persistence

Compose creates the Docker-managed `tailstate-data` volume and stores `/data/tailstate.db` there. Snapshots, events, baseline state, sessions, and the delivery outbox survive container replacement.

OAuth secrets, the Tailscale webhook secret, every Shoutrrr destination URL, and the evidence-ledger private key are encrypted with AES-256-GCM using `secrets/tailstate_master_key`. Destination credentials and upstream provider response bodies are never echoed into HTML, logs, persisted delivery errors, or the history ledger; delivery history keeps only bounded, provider-independent status reasons. Normalized history snapshots are retained for 30 days, exclude volatile fields, and replace known secret values with one-way fingerprints so presence and rotation remain auditable without exposing the value. OAuth access tokens exist only in memory. Back up the master key separately: TailState intentionally refuses to start if the key is missing or incorrect, and encrypted settings and signed history cannot be recovered without it.

The image is scratch-based, runs as UID/GID `10001`, uses a read-only root filesystem, drops every Linux capability, and publishes the UI only on `127.0.0.1` by default. Keep that publish address when using a reverse proxy; let the proxy terminate TLS and expose the public listener:

```dotenv
TAILSTATE_COOKIE_SECURE=true
```

For example, a minimal Caddy site is:

```text
tailstate.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

If the reverse proxy should run in Compose instead of on the host, copy the
worked example and replace its hostname:

```console
cp Caddyfile.example Caddyfile
```

The override uses Compose's `!reset` merge tag (Docker Compose v2.24 or newer)
to remove the base file's loopback port publish; do not replace it with an
empty `ports: []` list.

Then use the tracked [`compose.remote.yaml`](compose.remote.yaml) override. It
removes TailState's host port and exposes only Caddy while keeping the proxy
and application wiring reproducible.

With the copied `Caddyfile`, start the private listener and HTTPS proxy
together. The proxy has a public network for ACME certificate renewal and a
separate fixed-address private network for TailState. The fixed proxy address and
`TAILSTATE_TRUSTED_PROXIES` setting are paired intentionally; if you choose a
different subnet or proxy address, change both values together:

```console
docker compose -f compose.yaml -f compose.remote.yaml up -d
```

For a host-installed Caddy or nginx, point the proxy at `http://127.0.0.1:8080`
and expose only the proxy's HTTPS listener. `TAILSTATE_BIND_ADDRESS` controls only the host-side Compose
port publish; it does not change the in-container `TAILSTATE_LISTEN_ADDR`.
If the proxy terminates TLS, set `TAILSTATE_COOKIE_SECURE=true` and configure
the proxy's actual source address in `TAILSTATE_TRUSTED_PROXIES`. Preserving the
public `Host` and setting `X-Forwarded-Proto: https` keeps deployment
diagnostics accurate. Do not set `TAILSTATE_BIND_ADDRESS=0.0.0.0` unless a
firewall and TLS-terminating proxy already restrict access to the host port.

Setup, login, and password-reset forms do not reject requests based on
`Origin`, `Referer`, or Fetch Metadata headers because reverse proxies can
rewrite those values. Each credential form also carries an action-bound,
single-use challenge in a `SameSite=Strict` cookie and a signed hidden field.
Challenges expire after five minutes and are invalidated when TailState
restarts; reload the page if a challenge expires or a bookmarked form was
opened before a restart. Setup and reset still require one-time tokens, login
is rate limited, and authenticated state-changing forms require CSRF tokens.
Challenge and credential failures are exposed only through low-cardinality
route/outcome metrics; secrets, tokens, cookies, and request headers are never
logged.

If the proxy forwards the original client address or terminates TLS, configure
only its actual source address as trusted, for example
`TAILSTATE_TRUSTED_PROXIES=127.0.0.1/32`. TailState ignores
`X-Forwarded-For` and `X-Forwarded-Proto` from every other peer.
Enabling `TAILSTATE_COOKIE_SECURE=true` without a trusted proxy is rejected at
startup because this binary serves plain HTTP and must receive the proxy's
authenticated HTTPS indication.

Do not expose the setup interface directly to the internet.

### Deployment diagnostics

When a deployment reports a proxy or readiness issue, run the doctor command in
the same container or environment as TailState:

```console
docker compose exec tailstate /tailstate doctor
docker compose exec tailstate /tailstate doctor -json
```

The report checks the effective listener, secure-cookie and trusted-proxy
pairing, setup/baseline state, and whether notifications are paused. The
authenticated Settings page shows the same checks plus the sanitized origin
seen for the current request. Raw headers, credentials, and destination URLs
are never included in reports. `doctor` is strictly read-only: it does not
create a missing database, run schema migrations, backfill the evidence ledger,
create signing metadata, or persist storage limits. If a supported older schema
is found, the report marks migration as pending and asks you to stop the service
and make a verified backup before restarting the current release. The report
shows configured and persisted storage profiles separately so a changed
environment cannot be mistaken for the currently persisted profile.

### Password reset

Generate a one-time reset token:

```console
docker compose exec tailstate /tailstate admin reset
```

Then open `/reset`. Resetting the password invalidates existing sessions and any
outstanding reset token. Reset tokens expire after 30 minutes; generate another
token if one expires.

### Master-key rotation

The master key protects OAuth credentials, notification URLs, webhook secrets,
and the evidence signing key. Rotate it while the service is stopped so no
writer can race the transaction:

```console
openssl rand -base64 32 > secrets/tailstate_master_key.new
docker compose stop tailstate
docker compose run --rm \
  -v "$PWD/secrets:/keys:ro" \
  tailstate admin rekey -new-key-file /keys/tailstate_master_key.new
mv secrets/tailstate_master_key secrets/tailstate_master_key.old
mv secrets/tailstate_master_key.new secrets/tailstate_master_key
sudo chown 10001:10001 secrets/tailstate_master_key
sudo chmod 400 secrets/tailstate_master_key
docker compose up -d tailstate
```

The command re-encrypts all protected values in one transaction and preserves
the evidence signing identity. If it fails, the old key remains valid; do not
replace the configured key file until the command reports success. Keep the old
key and a verified database backup until the new deployment has been checked.

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

The backup and restore helpers use the single Renovate-managed pinned BusyBox
sidecar in `scripts/backup-image.sh`; CI and release jobs scan that sidecar
separately. Set `TAILSTATE_BACKUP_IMAGE` only for an explicitly reviewed
override.

Restore into the same Compose project only after confirming the archive and
key are from the same point in time. The command requires an explicit
`--yes`, verifies the checksum when present, checks that the archive directory
is writable and has room for a conservative pre-restore copy, rejects unsafe
paths and symlink/device/FIFO entries before touching the data volume, and
creates a pre-restore archive beside the source archive before replacing the
data volume:

```console
./scripts/restore.sh ./backups/tailstate-data-20260813T120000Z.tar.gz --yes
docker compose ps
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

The service is restarted only after a successful restore. The replacement is
staged inside the data volume and applied with same-filesystem renames; if a
rename fails, the script rolls the previous entries back without copying the
live database. If extraction or replacement still fails, the service remains
stopped; inspect the pre-restore archive before starting it.

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
- Every change batch is also recorded in the authenticated History page with field-level diffs and redacted normalized before/after snapshots. Filters support collector, change type, and resource name or ID; history is retained for 30 days. Normalized snapshots are capped at 1 MiB and each event before/after value at 512 KiB. Larger values retain their SHA-256, original byte count, configured limit, and a bounded truncation marker instead of the provider body; the authenticated UI calls this out explicitly. A normal history page reads at most 2 MiB of stored event data and displays a truncation notice with a cursor when that budget is reached. The hard 4 MiB raw-write ceiling prevents an unusually large normalized value from entering SQLite unbounded; the small marker remains queryable for audit.
- The History page can download a filtered, redacted JSON evidence pack for incident reports and offline review. Packs include normalized snapshots, field diffs, destination delivery outcomes, a SHA-256 content hash, and an Ed25519 signature over a hash-linked event ledger; exports are limited to 100 batches, 2,000 events, and 5 MiB. A changed export fails verification.
- Verify an export offline with `tailstate evidence verify --file tailstate-drift-evidence.json`. Verification checks the content hash, embedded public key fingerprint, signature, and included ledger links; packs and public-key files are bounded before decoding (5 MiB and 4 KiB respectively). For independent trust, print the instance public key with `tailstate evidence public-key`, save it as a base64 file, and pass it with `--public-key public.key`.
- Audit the persisted evidence ledger explicitly with `tailstate evidence audit`. The command opens the existing database read-only, verifies sequence continuity, predecessor hashes, signatures, key IDs, stored head, and canonical payload digests, then resumes through bounded pages until the chain is complete. Pass `--public-key public.key` to anchor verification to an independently trusted Ed25519 key; entries whose event snapshots have aged out are reported as cryptographically verified but payload-unverifiable. The audit never creates a database, runs migrations, generates keys, or changes metadata, and can run while TailState is serving from SQLite WAL mode.
- Shoutrrr deliveries retry independently for up to 24 hours across restarts, then remain visible as dead letters until the 30-day operational retention window expires. Delivery is at-least-once: each outbox row is leased while a sender is in flight, and if the process stops after a provider accepts a message but before the durable bookkeeping update commits, that message may be sent again after the lease expires. Per-lease fencing prevents a stale worker from changing a newer retry attempt. Disabling or removing a destination dead-letters its pending or in-flight items; newly added destinations receive only future notifications.
- Tailscale API retries honor `Retry-After` while capping a provider delay at five minutes and the complete retry window for one request at 30 seconds. Collectors also have a two-minute poll deadline, so a throttled endpoint cannot stall the scheduler indefinitely.
- Each paginated collection is bounded to 10,000 items and 64 MiB of response data across all pages, in addition to the 16 MiB per-response cap. If an aggregate limit is exceeded, the collector fails without applying partial inventory or deleting the last known snapshots. Device-detail requests share a bounded eight-worker queue so a large device list cannot create one job and result buffer per device.
- If every destination is disabled, monitoring continues and notifications are reported as paused.
- API collector failures alert after three consecutive failures and once on recovery.
- A 403/404 from an optional plan-specific endpoint is treated as an
  unsupported response. Collectors that have never produced a baseline are
  retried every six hours. For an established baseline, the first response is
  recorded as pending confirmation and retried after five minutes; only a
  second consecutive response opens the six-hour unsupported window. Baselines
  and snapshots remain intact across that interval, so recovery reports drift
  instead of silently rebasing. A later non-403/404 failure is recorded as a
  transient supported collector failure rather than retaining the unsupported
  label.
- Collection endpoints must return the documented array field. TailState treats
  an omitted, `null`, or wrong-typed `userInvites` or `webhooks` field as an
  invalid upstream response and preserves the last known snapshots; an
  explicitly returned `[]` is the healthy empty result. This prevents a
  malformed or permission-filtered response from looking like mass removal.
- Starting a different TailState release queues one durable notification containing the previous and current versions.

Version tracking is introduced in v0.3.0. Its first startup records the release silently because earlier releases did not persist their version; subsequent upgrades include both exact versions in the notification.

### Migration from older releases

Before upgrading an existing data volume, stop TailState and create a verified
backup with the matching master key. Startup verifies that key before applying
schema changes; a wrong key therefore exits without mutating the database. If a
migration fails, leave the service stopped, keep the original database and key,
and restore the pre-upgrade archive before retrying or rolling back the image.
TailState also refuses to bootstrap a non-empty database that has no valid
`schema_version` marker (including an empty, duplicated, or unsupported
marker); restore a verified backup or use a release that ships the required
migration instead of allowing a malformed file to be treated as new.

On the first startup after this upgrade, an existing encrypted Mattermost webhook is converted automatically to a native `mattermost://` destination when it uses the standard `/hooks/<token>` path. Other paths are preserved as a `generic://` JSON webhook with the existing TailState username and satellite icon. Existing outbox items are assigned to the migrated destination; if no legacy destination is configured, orphaned pending or in-flight rows are retained as dead letters with a safe explanation instead of remaining undeliverable forever. The legacy encrypted column is retained but no longer used for new configuration.

The schema v4 migration also adds encrypted storage for the optional Tailscale
webhook secret, a deduplicated webhook trigger ledger, and trigger IDs on
history batches. Schema v5 adds trigger leases, retry state, and many-to-many
links between coalesced triggers and history batches. Existing installations
start with webhook acceleration disabled until a secret is entered in Settings.
Schema v6 adds the encrypted Ed25519 evidence key and the hash-linked evidence
ledger. Existing complete event batches are signed automatically once on the
first startup after the upgrade; the migration records a durable batch cutoff,
so rows written after the upgrade can never be promoted into that historical
backfill. TailState never infers a missing cutoff from live rows, so a database
row written directly outside the versioned migration is not silently treated as
historical evidence. Empty or incomplete database rows are not promoted into the
historical chain. The public-key fingerprint is shown on the
History page and new exports use signed evidence format version 3. Version 3
packs embed the signed ledger payloads, intervening chain links, and the
preceding checkpoint for filtered or paginated ranges so an offline verifier
can recompute selected entries, bind the visible event projection to each
signed ledger payload, and detect gaps between them. Ledger rows are retained
after event snapshots age out, preserving the checkpoint needed to distinguish
normal retention from a broken chain.
Schema v7 adds expiring, revocable setup and password-reset token records. Schema
v8 records the latest collector poll duration and whether its result was partial,
so the status page and metrics can distinguish usable-but-degraded data from a
fully successful poll. Schema v9 records the number of failed related requests in
the latest partial collector result, and schema v10 adds per-lease fencing tokens
to durable webhook triggers so an expired worker cannot finalize a newer attempt.
Schema v11 adds the same lease and fencing state to notification outbox rows,
preventing duplicate claims during overlapping workers and stale delivery
bookkeeping after a restart. Schema v12 adds byte and truncation metadata to
snapshots and event values, backfills hashes and observed sizes for existing
history in resumable 64-row transactions, and enables bounded history reads.
The startup evidence-ledger backfill uses the same bounded transactions and a
durable cursor, so an interrupted upgrade resumes without duplicate entries or
a broken hash chain. Existing normalized values are
retained unchanged; only values written after the upgrade are replaced by a
marker when they exceed the configured budget. The authenticated Settings
diagnostics and `doctor -json` report the active limits and database pressure.
The schema v7 migration also bounds notification retries
to 24 hours and removes dead-letter rows after
the normal 30-day retention period. Legacy token hashes remain only as a
rollback aid and are removed by cleanup once their active token record expires.

## Runtime configuration

Only bootstrap settings use environment variables; application credentials and
the optional webhook secret are entered in the authenticated UI.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TAILSTATE_LISTEN_ADDR` | `127.0.0.1:8080` | Listener for a standalone binary; the image sets `0.0.0.0:8080` inside the container |
| `TAILSTATE_DATA_DIR` | `/data` | SQLite directory |
| `TAILSTATE_MASTER_KEY_FILE` | `/run/secrets/tailstate_master_key` | 32-byte or base64 master key |
| `TAILSTATE_MEMORY_LIMIT` | `512m` | Compose-only container memory ceiling; increase only after sizing for the deployment |
| `TAILSTATE_COOKIE_SECURE` | `false` | Require HTTPS for session cookies |
| `TAILSTATE_METRICS_TOKEN` | empty | Loopback-only `/metrics` when empty; bearer token for remote scrapes |
| `TAILSTATE_TRUSTED_PROXIES` | empty | Comma-separated proxy IPs/CIDRs allowed to supply `X-Forwarded-For` and `X-Forwarded-Proto` |
| `TAILSTATE_LOG_LEVEL` | `info` | `info` or `debug` structured logging |
| `TAILSTATE_SNAPSHOT_LIMIT_BYTES` | `1048576` | Maximum normalized snapshot value retained per resource; `0` uses the default |
| `TAILSTATE_EVENT_VALUE_LIMIT_BYTES` | `524288` | Maximum before/after value retained per history event; `0` uses the default |
| `TAILSTATE_HISTORY_PAGE_LIMIT_BYTES` | `2097152` | Maximum stored event data read for one History page; `0` uses the default |
| `TAILSTATE_REJECT_LIMIT_BYTES` | `4194304` | Hard raw-value write ceiling; `0` uses the default |
| `TAILSTATE_DATABASE_LIMIT_BYTES` | `536870912` | SQLite logical database byte ceiling enforced with SQLite's page limit; `0` uses the default |

The test-only `TAILSTATE_TS_API_URL` and `TAILSTATE_TS_OAUTH_URL` variables allow local mock servers; production deployments should leave them unset.

Standalone binaries bind the authenticated UI to loopback by default. If you
explicitly bind a plaintext listener beyond loopback, TailState logs a warning;
use `TAILSTATE_COOKIE_SECURE=true` and a configured trusted HTTPS proxy for
remote access. Compose keeps the application listener on the private container
network and publishes it on loopback by default.

`TAILSTATE_CONTAINER_NAME`, `TAILSTATE_IMAGE`, `TAILSTATE_BIND_ADDRESS`,
`TAILSTATE_PORT`, `TAILSTATE_MASTER_KEY_FILE`, and `TAILSTATE_MEMORY_LIMIT` are Compose-file variables;
they select the container name/image, host publishing address/port, and secret
file mount. They are not read as application settings by a standalone binary.

Storage limits are read by both the standalone binary and Compose. The database
limit is a real SQLite page ceiling: writes that reach it fail atomically, and
TailState reports the condition through diagnostics and metrics. Set the limit
above the current database size before lowering it; a restart refuses to open a
database that already exceeds the configured ceiling. The limit covers the
logical SQLite database, while the signed evidence ledger remains retained for
audit and is never silently deleted to make room.

## Local development

TailState uses Go 1.26.6. CI reads this version from `go.mod`, and the
release container is built with the same digest-pinned Go builder. Run
`bash scripts/check-go-toolchain.sh` to verify that the tested and published
toolchains remain aligned before changing either declaration.

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

Before changing the container or persistence path, run the isolated Compose
smoke test used by CI:

```console
bash scripts/compose-smoke.sh tailstate:dev
bash scripts/proxy-smoke.sh tailstate:dev
```

Contributor workflow, security boundaries, and the complete validation matrix
are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Pushing a semantic tag such as `v1.0.0` starts the verified release promotion workflow. The exact tagged commit must pass the reusable CI gate, including tests, coverage, Staticcheck, Govulncheck, an Anchore high-severity scan, runtime healthchecks, backup/restore validation, and a multi-architecture build. Release promotion first pushes one immutable candidate manifest, scans and smoke-tests both platform images by digest, and only then creates an annotated stable manifest copy whose platform digests match the candidate. The version, minor, and stable-only `latest` tags point to that verified copy; the temporary candidate package version is removed after the aliases are verified. The workflow publishes signed-build metadata, an SBOM, and `linux/amd64` plus `linux/arm64` images to:

```text
ghcr.io/crypt0rr/tailstate
```

The workflow also creates the matching GitHub Release with generated notes. Use the immutable version tag or image digest in deployments; reserve `latest` for development convenience. For a rollback, set `TAILSTATE_IMAGE` to a previously verified digest and keep the matching `secrets/tailstate_master_key` backup available:

```dotenv
TAILSTATE_IMAGE=ghcr.io/crypt0rr/tailstate@sha256:<known-good-digest>
```

The builder and runtime base images are pinned by digest and updated by Renovate, so a release is reproducible until an explicit dependency update changes those pins. Release images carry OCI labels for the compiler version, base-image digest, target platform, source commit, and release version; BuildKit's max-level provenance and the SBOM provide the corresponding attestation metadata.

## License

MIT

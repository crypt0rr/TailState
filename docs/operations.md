# Operating TailState

This page covers running TailState in production: persistence, remote
access, the web interface, health checks, the command line, diagnostics,
backup and restore, and storage. The [README](../README.md#quick-start)
has the quick start and the configuration summary;
[UPGRADING.md](../UPGRADING.md) has the upgrade and rollback procedure.

## Container and persistence

Compose creates the Docker-managed `tailstate-data` volume and stores `/data/tailstate.db` there. Snapshots, events, baseline state, sessions, and the delivery outbox survive container replacement. The image creates `/data` as `0700`, the process runs with a `077` umask, and the database and its `-wal`/`-shm` sidecars are kept at `0600` (including sidecars left by an unclean shutdown). An existing host directory is not re-permissioned; restrict a bind-mounted data directory to the service user yourself.

The image is scratch-based, runs as UID/GID `10001`, uses a read-only root filesystem, drops every Linux capability, and publishes the UI only on `127.0.0.1` by default. Compose also caps the process count, rotates container logs (3 × 10 MiB), and allows a 30-second stop grace period so an in-flight notification can finish its durable bookkeeping instead of being resent after a restart.

## HTTPS and reverse proxies

The optional Caddy proxy in `compose.remote.yaml` runs with only `NET_BIND_SERVICE`, `no-new-privileges`, a memory limit, a healthcheck against its loopback admin API, and HTTP/3 (`443/udp`). Keep TailState's loopback publish address when using a reverse proxy; let the proxy terminate TLS and expose the public listener:

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

Then use the tracked [`compose.remote.yaml`](../compose.remote.yaml) override. It
removes TailState's host port and exposes only Caddy while keeping the proxy
and application wiring reproducible.

With the copied `Caddyfile`, start the private listener and HTTPS proxy
together. The proxy has a public network for ACME certificate renewal and a
separate fixed-address internal network for reaching TailState. TailState also
joins an outbound-only `tailstate-egress` network so it can reach the Tailscale
API and notification providers; no service publishes ports on that network. The fixed proxy address and
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

Do not expose the setup interface directly to the internet.

## Listener exposure

Standalone binaries bind the authenticated UI to loopback by default. If you
explicitly bind a plaintext listener beyond loopback, TailState logs a warning
(inside the official image, the default wildcard listener is logged at info
level because the published port controls exposure);
use `TAILSTATE_COOKIE_SECURE=true` and a configured trusted HTTPS proxy for
remote access. Compose keeps the application listener on the private container
network and publishes it on loopback by default.

## Web interface

Add destinations on the authenticated Settings page, then save monitoring settings. Each destination is validated and can be tested independently. The form is validated locally first (interval range, required OAuth credentials, webhook secret of at most 1024 bytes, and a tailnet name without spaces, slashes, or URL syntax), so a mistake is reported immediately with a specific message and nothing is sent to Tailscale. TailState then performs a Tailscale API check, bounded to 20 seconds so a slow or rate-limited API still produces a "Tailscale test failed" page, and builds a silent baseline. The status page shows baseline counts, collector capabilities, source health, and delivery state. Each collector row lists its state, last success, next scheduled poll, last poll duration, consecutive failures, and details; every time is shown in UTC with a relative hint ("3 min ago"). **Reconcile now** requests an immediate poll of every collector (a CSRF-protected form, limited to one request every 30 seconds). The **Delivery by destination** table shows pending, processing, and dead notifications per destination, and **Retry dead letters** requeues an enabled destination's dead letters with a fresh 24-hour delivery window. Dead letters from a previous tailnet/OAuth identity are never requeued, a disabled destination must be enabled first, and delivery remains at-least-once, so a message the provider had already accepted can arrive again. Rotating the OAuth secret or changing poll intervals refreshes the monitor without discarding the existing baseline; changing the tailnet or OAuth client identity starts a new generation and dead-letters pending and in-flight event notifications from the previous identity (an in-flight sender can no longer complete or requeue them) while preserving their history for audit. System and release notifications remain eligible for delivery.

The interface follows the browser's light or dark preference and works down to 320-pixel-wide screens: the header wraps instead of overlapping, and on narrow screens table rows stack with every value labelled by its column name. Field differences carry "Old" and "New" text markers, so they do not depend on red/green colour. Errors are announced to screen readers, the current page is marked in the navigation, and repeated destination buttons are labelled with the destination name. The pages load no scripts and no inline styles, so the strict Content-Security-Policy stays unchanged.

Destination actions (add, edit including routing and message format, enable, disable, send test, remove), mute rule changes, password changes, **Sign out all other sessions**, and the status page actions use Post/Redirect/Get: the result is shown once as a message on the page you return to, so reloading never sends another test notification or repeats an action. **Remove** opens a confirmation step that states how many pending notifications will be dead-lettered; the server refuses a removal that was not confirmed. If your session expired (including the idle timeout described in [Administrator accounts and sessions](security.md#administrator-accounts-and-sessions)) or was reset while a page was open, submitting a form clears the stale cookies and opens the login page, which then returns you to the page you were on; opening a bookmarked page while signed out returns you to it the same way. The return target must be one of TailState's own Status, History, or Settings pages: absolute, scheme-relative (`//host`), backslash, and percent-encoded variants are ignored and you land on the default page. A form submitted with a valid session but a missing or wrong CSRF token is refused with `403` and keeps the session.

## Health and readiness

```console
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

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

Only the documented routes exist (including the bearer-token [read-only API](security.md#read-only-api) under `/api/v1/`): `/` redirects to the right page, unknown paths return `404`, `/static/` serves the embedded stylesheet without directory listings, and the browser's automatic `/favicon.ico` probe gets an empty, cacheable `204` without touching the database.

## Command line

```console
tailstate help                 # all commands and exit codes
tailstate help admin backup    # one command; every command also accepts -h/--help
```

| Command | Purpose |
| --- | --- |
| `serve` (default) | Bind `TAILSTATE_LISTEN_ADDR`, then start collectors and delivery |
| `healthcheck [-url URL]` | Probe `/healthz`; the URL defaults to `TAILSTATE_LISTEN_ADDR` (a wildcard host such as `0.0.0.0` or `[::]` is probed on loopback) |
| `doctor [-json]` | Read-only deployment report |
| `admin reset` | One-time password reset token (safe while serving) |
| `admin rekey -new-key-file PATH` | Master-key rotation (service stopped) |
| `admin backup -out FILE` | Consistent online database snapshot plus `FILE.sha256` (safe while serving) |
| `admin compact [-incremental-vacuum]` | Release free pages (service stopped; see [Compaction](#compaction)) |
| `evidence verify`, `evidence audit`, `evidence public-key` | Evidence verification and ledger audit |
| `version` | Print the version |

Help output goes to standard output and exits `0`. Exit codes are stable for
scripts:

| Code | Meaning |
| --- | --- |
| `0` | Success (including `help`, `-h`, and `--help`) |
| `1` | Runtime error: configuration, master key, I/O, database, or network failure |
| `2` | Usage error: unknown command or subcommand, invalid or missing option, unexpected argument |
| `3` | The check ran and failed: `doctor` reported a blocking (error) finding, `evidence verify` rejected a pack, or `evidence audit` found a ledger integrity failure |

Logging is configured before configuration is validated or the database is
opened, so startup errors, schema migration progress, and evidence-ledger
backfill logs are JSON at the `TAILSTATE_LOG_LEVEL` level. `serve` logs to
standard output; other commands log to standard error so their standard output
stays machine-readable. `serve` binds its listener before it writes the setup
token, queues the version notification, or starts collectors and delivery, so
an address already in use exits (code `1`) before any poll or notification.

The image `HEALTHCHECK` and the Compose healthcheck run `tailstate healthcheck`
without arguments, so they follow a custom `TAILSTATE_LISTEN_ADDR` port.

## Deployment diagnostics

When a deployment reports a proxy or readiness issue, run the doctor command in
the same container or environment as TailState:

```console
docker compose exec tailstate /tailstate doctor
docker compose exec tailstate /tailstate doctor -json
```

The report checks the effective listener, secure-cookie and trusted-proxy
pairing, setup/baseline state, and whether notifications are paused
(`notifications_paused` when every destination is disabled,
`notifications_no_destinations` when monitoring is configured but no
destination exists). The Settings banner, these findings, and `/metrics` use
one shared rule, so they always agree. In the official image
(`TAILSTATE_CONTAINER=1`, set by the Dockerfile and `compose.yaml`) the
wildcard container listener is reported as the informational
`container_listener` finding instead of a warning, because Docker port
publishing (loopback by default) decides who can reach it; a default Compose
deployment therefore reports `ok`. The
authenticated Settings page shows the same checks plus the sanitized origin
seen for the current request. Raw headers, credentials, and destination URLs
are never included in reports. `doctor` is strictly read-only: it does not
create a missing database, run schema migrations, backfill the evidence ledger,
create signing metadata, or persist storage limits. If a supported older schema
is found, the report marks migration as pending and asks you to stop the service
and make a verified backup before restarting the current release. The report
shows configured and persisted storage profiles separately so a changed
environment cannot be mistaken for the currently persisted profile.

## Backup and restore

Use the repository helper to stop TailState, archive the exact data volume, and
write a SHA-256 checksum. The helper discovers the Compose-managed volume from
the service container, so it does not depend on a project name or a hardcoded
volume name:

```console
./scripts/backup.sh ./backups
```

To take a snapshot without stopping the service, use `admin backup`. It opens
the live database read-only (it never creates, migrates, or writes it), copies
a transactionally consistent snapshot with SQLite `VACUUM INTO`, checks the
copy's integrity and master key, and writes `FILE.sha256` in `sha256sum`
format. Existing files are never overwritten. In the default Compose
deployment, write the snapshot into the data volume and copy it out:

```console
docker compose exec tailstate /tailstate admin backup -out /data/tailstate-backup.db
docker compose cp tailstate:/data/tailstate-backup.db ./backups/
docker compose cp tailstate:/data/tailstate-backup.db.sha256 ./backups/
docker compose exec tailstate /tailstate admin backup -h   # options
```

The snapshot is a plain SQLite database protected by the same master key. To
restore it, stop TailState, verify it with `sha256sum -c`, replace
`tailstate.db` in the data directory with the snapshot (remove any
`tailstate.db-wal` and `tailstate.db-shm` left beside the old file), keep the
file owned by the service user with mode `0600`, and start the service. Remove
the snapshot from the data volume after copying it out; it counts against the
volume, not against the database budget.

Back up `secrets/tailstate_master_key` separately and securely. A backup is
only useful with the matching master key: TailState intentionally refuses to
open encrypted state with a different key.

The backup and restore helpers mount only the TailState data volume (read-only
for backups) into a network-less container, so the helper never sees the
master-key secret. A failed backup removes its partial archive. They use the
single Renovate-managed pinned BusyBox sidecar in `scripts/backup-image.sh`; CI and release jobs scan that sidecar
separately. Set `TAILSTATE_BACKUP_IMAGE` only for an explicitly reviewed
override.

Restore into the same Compose project only after confirming the archive and
key are from the same point in time. The command requires an explicit
`--yes`, requires and verifies the `.sha256` checksum written by the backup
helper (pass `--no-checksum` to restore an archive that has none), refuses an
archive that does not contain an SQLite `tailstate.db`, checks that the archive directory
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

## Storage, retention, and compaction

### Storage limits

Storage limits are read by both the standalone binary and Compose. The database
limit is a real SQLite page ceiling: writes that reach it fail atomically, and
TailState reports the condition through diagnostics and metrics. The budget is
compared with *used* bytes, `(page_count - freelist_count) * page_size`:
retention frees pages that SQLite reuses before it grows the file, so
`tailstate_storage_used_bytes` and `tailstate_storage_pressure_ratio` fall as
soon as old history is removed, while `tailstate_storage_bytes` (allocated,
including free pages), `tailstate_storage_freelist_pages`, and
`tailstate_storage_free_bytes` show what compaction would return. A restart
refuses a limit below the used bytes. A limit below the file size but above
the used bytes is accepted; because SQLite cannot lower its page ceiling below
the current file size, it is enforced at that size (and `doctor` reports
`storage_compaction_needed`) until you compact the database. The limit covers
the logical SQLite database, while the signed evidence ledger remains retained
for audit and is never silently deleted to make room.

### Retention cleanup

Retention cleanup is resumable and writer-friendly. Each table is processed in keyset batches of at most 128 rows, each autocommit transaction has a 250 ms deadline, and one pass stops after two seconds; when work remains, the monitor schedules a continuation within one second instead of waiting for the hourly sweep. A failed pass is retried after one second, and consecutive failures double that delay up to the hourly sweep interval, so a persistent error (for example a full disk) does not retry every second; the next successful pass resets the backoff. Cleanup logs include per-table row counts, transaction count, duration, failures, and the remaining-work flag. The same information is available through `tailstate_cleanup_*` metrics. Active notification and webhook leases are never dead-lettered until their lease has expired, and evidence-ledger rows are never removed by retention. Administrative audit records use their own 365-day retention period.

### Compaction

`admin compact` rewrites the database without free pages. It is an offline
command: `serve` holds an advisory lock on `tailstate.db.lock` for its whole
lifetime, and `compact` refuses to run (exit code `1`) while that lock is held.
It opens the database like `admin reset` (never creates or migrates it),
writes a compacted copy beside it with `VACUUM INTO`, verifies the copy, and
only then replaces the original, so an interrupted run leaves the original in
place. It also refuses if another process still has the database open. Take a
backup first:

```console
docker compose exec tailstate /tailstate admin backup -out /data/pre-compact.db
docker compose stop tailstate
docker compose run --rm tailstate admin compact
docker compose up -d tailstate
```

`-incremental-vacuum` additionally switches the database to SQLite
`auto_vacuum=INCREMENTAL`; afterwards every retention pass that removes rows
also returns up to 2,048 free pages to the filesystem, so the file shrinks
without further manual compaction. The setting is per database and changing
it requires this rewrite, so it is never applied by a migration. The lock is
advisory and only covers processes on the same host and kernel; on a
platform without `flock(2)`, stop the service manually first.

### WAL and read concurrency

The writer connection sets `journal_size_limit` to 64 MiB, so after a burst
the `-wal` file is truncated back to that cap the next time SQLite restarts
the log, and every retention pass that changed rows ends with a
`wal_checkpoint(TRUNCATE)`. `/healthz`, `/readyz`, `/metrics`, session checks,
History reads, the Status page (collector state, the **Expiring soon** card,
and per-destination delivery counts), and the Settings page's webhook state
and mute rules use a separate pool of four read-only (`mode=ro`,
`query_only`) connections. In WAL mode these readers never wait for the
single writer, so health checks and scrapes keep answering during a long write
transaction, and every read observes the latest committed data.

The Settings diagnostics show the used database bytes (excluding free pages)
in MiB with their percentage of the configured limit, and the allocated size
when free pages are waiting for reuse or compaction. Settings diagnostics, `doctor`, and `/metrics` also expose the
observed physical sizes of the main
`tailstate.db` file, its `-wal` and `-shm` sidecars, and their total. These
physical gauges are volume-safety observations, not additional enforcement
limits; a missing transient sidecar is reported as zero.

The evidence ledger is intentionally never pruned and so grows with the
number of change batches. Ledger archival (exporting a signed checkpoint plus
the archived segment, then pruning locally while keeping the chain verifiable
from that checkpoint) is planned future work; until then, size the database
budget for the ledger's growth and monitor `tailstate_storage_used_bytes`.

## Standalone binary (systemd)

Each GitHub Release also ships reproducible `tailstate_<version>_<os>_<arch>.tar.gz`
archives for Linux (amd64, arm64), macOS (amd64, arm64), and FreeBSD (amd64),
plus `SHA256SUMS`, an SPDX SBOM, and a signed build-provenance attestation:

```console
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify tailstate_<version>_linux_amd64.tar.gz --owner crypt0rr
```

The archive contains a hardened systemd unit in
`contrib/systemd/tailstate.service` (dynamic user, private state directory,
master key passed as a systemd credential, `systemd-analyze security` score
1.1). Its header lists the install steps; the standalone binary listens on
`127.0.0.1:8080` and prints the one-time setup token to the journal
(`journalctl -u tailstate`).

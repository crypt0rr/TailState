# TailState

TailState polls the read-only Tailscale API, establishes a silent inventory baseline, and posts later changes to one or more Shoutrrr destinations. It runs as one static Go binary with an embedded setup/status interface and durable SQLite storage.

TailState never modifies a tailnet. Optional signed Tailscale webhooks can
accelerate reconciliation; the read-only polling schedule remains the source
of truth and the safety net for missed events.

## Documentation

| Page | Contents |
| --- | --- |
| [What TailState monitors](docs/monitoring.md) | Collectors and ignored fields, change detection, OAuth scopes, expiry warnings, change attribution, Tailscale webhooks |
| [Notifications](docs/notifications.md) | Shoutrrr destinations, message rendering, severity and routing, mute rules, delivery semantics |
| [History and evidence](docs/evidence.md) | The History page, signed evidence packs, offline verification, ledger audit |
| [Operations](docs/operations.md) | Persistence, HTTPS and reverse proxies, health checks, command line, `doctor`, backup and restore, storage and compaction, systemd |
| [Security](docs/security.md) | Encryption and master-key rotation, administrator accounts and sessions, throttling, trusted proxies, audit trail, read-only API |
| [Metrics and alerting](docs/metrics.md) | `/metrics` access, metric reference, [Prometheus alert rules](docs/prometheus/alerts.yml) |
| [UPGRADING.md](UPGRADING.md) | Upgrade and rollback procedure, schema history, migration details |
| [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) | Release notes, vulnerability reporting, contributor workflow |

## Quick start

Requirements: Docker with Compose and a Tailscale OAuth client permitted to request `all:read` (or the narrower read scopes listed in [OAuth scopes](docs/monitoring.md#oauth-scopes)).

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

`.env.example` pins a released image in `TAILSTATE_IMAGE`. Before the first
start, set it in `.env` to the newest version listed in the
[CHANGELOG](CHANGELOG.md) (or to a verified digest, see [Releases](#releases)),
for example:

```dotenv
TAILSTATE_IMAGE=ghcr.io/crypt0rr/tailstate:1.0.0
```

Then pull and start it:

```console
docker compose pull
docker compose up -d
```

Without `TAILSTATE_IMAGE`, Compose falls back to
`ghcr.io/crypt0rr/tailstate:latest`.

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
2. OAuth client ID and secret, and the OAuth scopes to request (default
   `all:read`; see [OAuth scopes](docs/monitoring.md#oauth-scopes)).
3. At least one notification destination using a Shoutrrr URL; see
   [Notifications](docs/notifications.md#destinations).
4. Device and secondary inventory polling intervals, in whole seconds. Device
   polling accepts 15 seconds to 24 hours (86400 seconds); inventory polling
   accepts 30 seconds to 24 hours.
5. Optional expiry warning windows (default `14, 3` days) and an expiry tag
   filter; see [Expiry warnings](docs/monitoring.md#expiry-warnings).

Next steps:

- For access from other machines, put TailState behind an HTTPS reverse proxy;
  see [HTTPS and reverse proxies](docs/operations.md#https-and-reverse-proxies).
- Scrape `/metrics` with a bearer token and load the
  [alert rules](docs/metrics.md#alerting), so a broken notification path is
  still noticed.
- Take a first [backup](docs/operations.md#backup-and-restore) and store the
  master key separately.
- Before every upgrade, follow [UPGRADING.md](UPGRADING.md).


## Runtime configuration

Only bootstrap settings use environment variables; application credentials and
the optional webhook secret are entered in the authenticated UI.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TAILSTATE_LISTEN_ADDR` | `127.0.0.1:8080` | Listener for a standalone binary; the image sets `0.0.0.0:8080` inside the container |
| `TAILSTATE_DATA_DIR` | `/data` | SQLite directory |
| `TAILSTATE_MASTER_KEY_FILE` | `/run/secrets/tailstate_master_key` | 32-byte or base64 master key |
| `TAILSTATE_MEMORY_LIMIT` | `512m` | Compose-only container memory ceiling; increase only after sizing for the deployment |
| `TAILSTATE_COOKIE_SECURE` | `false` | Require HTTPS for session cookies and name them with the `__Host-` prefix |
| `TAILSTATE_METRICS_TOKEN` | empty | Bearer token for `/metrics`; required to scrape from outside the container or host loopback (Compose, `docker run -p`, proxies). Empty allows only local loopback scrapes of a standalone binary |
| `TAILSTATE_TRUSTED_PROXIES` | empty | Comma-separated proxy IPs/CIDRs allowed to supply `X-Forwarded-For` and `X-Forwarded-Proto` |
| `TAILSTATE_LOG_LEVEL` | `info` | `info` or `debug` structured logging |
| `TAILSTATE_PUBLIC_URL` | empty | External `https://` base URL of this instance (no credentials, query, or fragment). Digests then link to `/history?batch=<id>` and health alerts and expiry warnings to `/status`; empty emits no links |
| `TAILSTATE_INSTANCE_LABEL` | empty | Optional instance name (at most 64 printable bytes) shown in every notification title next to the tailnet |
| `TAILSTATE_CONTAINER` | `false` (`1` in the image) | Marks the official container image; its wildcard listener is then an informational diagnostic |
| `TAILSTATE_SNAPSHOT_LIMIT_BYTES` | `1048576` | Maximum normalized snapshot value retained per resource; `0` uses the default |
| `TAILSTATE_EVENT_VALUE_LIMIT_BYTES` | `524288` | Maximum before/after value retained per history event; `0` uses the default |
| `TAILSTATE_HISTORY_PAGE_LIMIT_BYTES` | `2097152` | Maximum stored event data read for one History page; `0` uses the default |
| `TAILSTATE_REJECT_LIMIT_BYTES` | `4194304` | Hard raw-value write ceiling; `0` uses the default |
| `TAILSTATE_DATABASE_LIMIT_BYTES` | `536870912` | SQLite logical database byte ceiling enforced with SQLite's page limit; `0` uses the default |

The test-only `TAILSTATE_TS_API_URL` and `TAILSTATE_TS_OAUTH_URL` variables allow local mock servers; production deployments should leave them unset.

`TAILSTATE_CONTAINER_NAME`, `TAILSTATE_IMAGE`, `TAILSTATE_BIND_ADDRESS`,
`TAILSTATE_PORT`, `TAILSTATE_MASTER_KEY_FILE`, and `TAILSTATE_MEMORY_LIMIT` are Compose-file variables;
they select the container name/image, host publishing address/port, and secret
file mount. They are not read as application settings by a standalone binary.

Storage limits and their enforcement are described in
[Storage limits](docs/operations.md#storage-limits), and listener exposure in
[Listener exposure](docs/operations.md#listener-exposure).

## Local development

TailState uses Go 1.27.2. CI reads this version from `go.mod`, and the
release container is built with the same digest-pinned Go builder. Run
`bash scripts/check-go-toolchain.sh` to verify that the tested and published
toolchains remain aligned before changing either declaration.

```console
gofmt -w cmd internal
go vet ./...
go test -race ./...
docker build -t tailstate:dev .
```

For a local development binary, generate a master key and point TailState at a writable data directory:

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

Pushing a semantic tag such as `v1.0.0` starts the verified release promotion workflow. The exact tagged commit must pass the reusable CI gate, including tests, coverage, Staticcheck, Govulncheck, an Anchore high-severity scan, runtime healthchecks, backup/restore validation, and a multi-architecture build. Release promotion first pushes one immutable candidate manifest, scans and smoke-tests both platform images by digest, and only then creates an annotated stable manifest copy whose platform digests match the candidate. The version, minor, and stable-only `latest` tags point to that verified copy; the temporary candidate package version is removed after the aliases are verified. The workflow publishes a Sigstore-signed build-provenance attestation, an SBOM, and `linux/amd64` plus `linux/arm64` images to:

```text
ghcr.io/crypt0rr/tailstate
```

Verify that an image was built by this repository's release workflow before
deploying it:

```console
gh attestation verify oci://ghcr.io/crypt0rr/tailstate:<version> \
  --owner crypt0rr \
  --signer-workflow crypt0rr/TailState/.github/workflows/release.yml
```

The attestation covers the promoted multi-architecture index digest that the
version, minor, and `latest` tags resolve to, so the same check works for a
pinned digest (`oci://ghcr.io/crypt0rr/tailstate@sha256:...`).

The workflow also creates the matching GitHub Release. Every release has a [CHANGELOG](CHANGELOG.md) entry stating its database schema version and whether an image-only rollback is possible; the release workflow refuses a tag without one. Use the immutable version tag or image digest in deployments; reserve `latest` for development convenience. See [UPGRADING.md](UPGRADING.md) for the upgrade and rollback procedure. When the schema did not change, roll back by setting `TAILSTATE_IMAGE` to a previously verified digest; when it did, restore the pre-upgrade backup first, because older releases refuse a migrated database. Keep the matching `secrets/tailstate_master_key` backup available:

```dotenv
TAILSTATE_IMAGE=ghcr.io/crypt0rr/tailstate@sha256:<known-good-digest>
```

The builder and runtime base images are pinned by digest and updated by Renovate, so a release is reproducible until an explicit dependency update changes those pins. Release images carry OCI labels for the compiler version, target platform, source commit, and release version. The image is built `FROM scratch`, so it has no base-image labels; the exact digest-pinned builder image is recorded in BuildKit's max-level provenance attestation alongside the SBOM. The builder stage runs on the build host's native platform and cross-compiles the static binary for each target architecture.

Standalone binary archives and the hardened systemd unit are described in
[Operations](docs/operations.md#standalone-binary-systemd).

## License

MIT

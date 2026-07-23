# TailState

TailState polls the read-only Tailscale API, establishes a silent inventory baseline, and posts later changes to Mattermost. It runs as one static Go binary with an embedded setup/status interface and durable SQLite storage.

TailState never modifies a tailnet and does not use native Tailscale webhooks.

## What it monitors

- Devices, stable tailnet IPv4/IPv6 addresses, details, authorization, tags, key expiry, client version, routes, posture attributes, and invites.
- Users and user invites.
- DNS nameservers, preferences, search paths, and split DNS.
- Policy section fingerprints without storing policy contents.
- Credential metadata, webhook configuration inventory, log-streaming configuration/status, contacts, posture integrations, and tailnet settings.

The REST API does not expose authoritative online state. TailState therefore does **not** generate online/offline notifications and ignores `lastSeen`, `connectedToControl`, public endpoints, connectivity metadata, response timestamps, and array ordering.

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
3. Mattermost incoming webhook URL.
4. Device and secondary inventory polling intervals.

Saving performs a Tailscale API check and posts an explicit Mattermost test. TailState then builds a silent baseline. The status page shows baseline counts, collector capabilities, source health, and delivery state.

```console
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

## Security and persistence

Compose creates the Docker-managed `tailstate-data` volume and stores `/data/tailstate.db` there. Snapshots, events, baseline state, sessions, and the delivery outbox survive container replacement.

OAuth secrets and the Mattermost webhook URL are encrypted with AES-256-GCM using `secrets/tailstate_master_key`. OAuth access tokens exist only in memory. Back up the master key separately: TailState intentionally refuses to start if the key is missing or incorrect, and encrypted settings cannot be recovered without it.

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

Stop the service before a simple volume backup so the SQLite files are consistent:

```console
docker compose stop tailstate
docker run --rm -v tailstate_tailstate-data:/data -v "$PWD:/backup" alpine:3.24 \
  tar czf /backup/tailstate-data.tar.gz -C /data .
docker compose start tailstate
```

Back up `secrets/tailstate_master_key` separately and securely.

## Change and delivery behavior

- The first complete supported inventory is a silent baseline.
- Stable additions and modifications alert on the next successful poll.
- Removals require absence from two complete successful polls.
- Failed or partial polls never delete snapshots.
- Multiple changes in one poll become one Mattermost digest.
- Failed Mattermost deliveries retry independently for up to 24 hours across restarts, then remain visible as dead letters.
- API collector failures alert after three consecutive failures and once on recovery.
- Plan-specific unavailable endpoints appear as unsupported and retry every six hours.

## Runtime configuration

Only bootstrap settings use environment variables; application credentials are entered in the authenticated UI.

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

Pushing a semantic tag such as `v1.0.0` publishes signed-build metadata, an SBOM, and `linux/amd64` plus `linux/arm64` images to:

```text
ghcr.io/crypt0rr/tailstate
```

## License

MIT

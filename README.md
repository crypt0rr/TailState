# TailState

TailState watches one [Tailscale](https://tailscale.com) tailnet and sends durable notifications to the places where you work. It accepts Tailscale's signed webhooks for real-time administration events and polls the read-only API for inventory and configuration changes.

## Features

- Signed Tailscale webhook verification with replay protection and retry deduplication.
- Silent initial API baseline followed by durable, semantic change notifications.
- Devices (including routes, posture attributes, and invites), users, DNS, policy fingerprints, key metadata, webhooks, log-streaming status, contacts, posture integrations, and settings.
- Telegram, Mattermost, Slack, Discord, Microsoft Teams, Google Chat, and versioned generic webhook delivery.
- Per-destination case-sensitive glob filters and minimum severity.
- SQLite transactional outbox, exponential retry, dead letters, retention, and restart recovery.
- Health, readiness, and Prometheus endpoints.
- OAuth client credentials with token renewal or API-token fallback.

TailState is read-only. It never approves or deletes devices, changes policy, or performs remediation.

## Quick start

1. Create a Tailscale OAuth client with the `all:read` scope. Narrower read scopes work when the corresponding collectors are disabled.
2. Copy [`config.example.yaml`](config.example.yaml) to `config.yaml` and [`.env.example`](.env.example) to `.env`.
3. Create the referenced files under `./secrets`, create `./tailstate-data`, then adjust the destinations:

```console
mkdir -p secrets tailstate-data
chmod 700 tailstate-data
sudo chown 10001:10001 tailstate-data
chmod 600 .env secrets/*
```

SQLite is stored directly under `./tailstate-data` alongside the Compose file. The directory is ignored by Git and must be writable by the container's non-root UID `10001`.

4. Start the service:

```console
docker compose up -d
```

Validate a configuration without starting the server:

```console
tailstate check --config /config/tailstate.yaml
```

The first successful polling run stores a silent baseline. TailState sends one `tailstate.baseline_ready` summary; later differences become events.

## Configuration

Configuration is YAML. `${ENV_VAR}` expressions are expanded before parsing. Every sensitive field also has a mutually exclusive `_file` variant, suitable for Docker and Kubernetes secrets:

```yaml
tailscale:
  tailnet: example.com
  auth:
    type: oauth
    client_id: k1234567890
    client_secret_file: /run/secrets/tailscale_oauth_secret
    scope: all:read
  webhook_secret_file: /run/secrets/tailscale_webhook_secret
```

Use `type: api_token` with `token` or `token_file` instead of OAuth when required. Tailscale API tokens expire after at most 90 days; OAuth is the recommended unattended mode.

Docker Compose automatically reads `.env` for Compose interpolation, and this project's `env_file` entry also passes those values to TailState so `${TAILSCALE_TAILNET}`, `${TELEGRAM_CHAT_ID}`, and destination URL expressions in `config.yaml` can be expanded. Keep `.env` out of version control.

For secrets, prefer the files mounted at `/run/secrets`:

- `tailscale_oauth_secret`: the long-lived OAuth client secret.
- `tailscale_webhook_secret`: the inbound webhook HMAC signing secret.
- `telegram_bot_token`: the Telegram bot credential.

The file locations are configurable from `.env`, but the secret contents remain outside the container environment. Webhook URLs for Mattermost, Slack, Discord, Teams, and Google Chat commonly contain an embedded credential; if supplied through `.env`, protect that file like any other secret (for example, `chmod 600 .env`).

Collectors are named `devices`, `users`, `dns`, `policy`, `keys`, `webhooks`, `log_streaming`, `contacts`, `posture`, and `settings`. Remove collectors for which the credential lacks access. `tailstate check` fails when any enabled collector is inaccessible.

Devices and users use `core_interval_seconds` (60 seconds by default); other collectors use `secondary_interval_seconds` (five minutes). `collector_intervals_seconds` can override any enabled collector, for example `keys: 3600`.

Native webhook ingestion and API polling are independently switchable with `webhook_enabled` and `polling_enabled`.

### Routing

Each enabled destination receives an event when:

1. Its `min_severity` is met.
2. At least one `include` glob matches (an empty include list matches everything).
3. No `exclude` glob matches. Exclusions always win.

Globs are case-sensitive and match stable event types. Examples:

- Native: `tailscale.webhook.nodeCreated`, `tailscale.webhook.policyUpdate`
- API: `tailscale.device.created`, `tailscale.user.changed`, `tailscale.dns.changed`
- Service: `tailstate.baseline_ready`, `tailstate.source_unhealthy`

The generic webhook body is the normalized event and always contains `schema_version: 1`. Generic endpoints can add headers, bearer or basic authentication, and `X-TailState-Signature: t=<unix>,v1=<hmac-sha256>` signing over `<timestamp>.<raw-body>`.

### Inferred stale devices

The Tailscale REST Devices API does not expose authoritative online state. Optional stale-device events are therefore labelled internally as inferred and are disabled by default. Enabling `stale_device.enabled` compares `lastSeen` with `threshold_seconds`; ordinary `lastSeen` updates never generate changes.

## HTTP endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /webhooks/tailscale` | Signed Tailscale webhook receiver |
| `GET /healthz` | Process liveness |
| `GET /readyz` | Baseline/source health and outbox counts |
| `GET /metrics` | Prometheus text exposition |

Tailscale requires its webhook receiver to be reachable over HTTPS on port 80 or 443. TailState listens on plain HTTP by default and should sit behind a TLS reverse proxy. Alternatively, run it on a Tailscale node and publish port 8080 with [Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel):

```console
tailscale funnel --bg 8080
```

Configure the resulting HTTPS URL as `https://<device>.<tailnet>.ts.net/webhooks/tailscale`, choose the general Tailscale payload format, subscribe to events, and store the displayed signing secret in TailState.

## Local development

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo run -- check --config config.example.yaml
```

Set `RUST_LOG=tailstate=debug,tower_http=debug` for additional diagnostics. Secrets and API response bodies are never logged.

## Security and persistence

- Run one TailState instance and SQLite volume per tailnet.
- Protect `./tailstate-data`: it contains normalized current inventory and retained events, but never configured secrets or OAuth access tokens.
- Policy contents are represented only by per-section fingerprints. Secret/token fields returned by APIs are removed recursively.
- The container runs as an unprivileged user and supports a read-only root filesystem.

## License

MIT

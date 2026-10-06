# Security

This page describes how TailState protects its credentials, administrator
access, and machine access. To report a vulnerability, follow
[SECURITY.md](../SECURITY.md). Deployment hardening (container, Compose, and
HTTPS proxy) is described in [Operations](operations.md#https-and-reverse-proxies).

## Encryption and secrets

OAuth secrets, the Tailscale webhook secret, every Shoutrrr destination URL, and the evidence-ledger private key are encrypted with AES-256-GCM using `secrets/tailstate_master_key`, each bound to its storage location. Destination credentials and upstream provider response bodies are never echoed into HTML, logs, persisted delivery errors, or the history ledger; delivery history keeps only bounded, provider-independent status reasons. Normalized history snapshots are retained for 30 days, exclude volatile fields, and replace known secret values with one-way fingerprints so presence and rotation remain auditable without exposing the value. OAuth access tokens exist only in memory. Back up the master key separately: TailState intentionally refuses to start if the key is missing or incorrect, and encrypted settings and signed history cannot be recovered without it.

## Master-key rotation

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

Each encrypted value is bound to the row and column that stores it (AES-GCM
additional data), so a ciphertext copied to another row or column fails to
decrypt instead of, for example, redirecting one destination to another's URL.
Values written by releases before this binding use the older unbound format;
they stay readable, and are rewritten in the bound format when changed or when
`admin rekey` runs. Rekey also accepts the current key file
(`-new-key-file` pointing at the configured key) to upgrade every value without
rotating the key.

## Administrator accounts and sessions

New administrator passwords (setup, reset, and the Settings change form) must
be at least 15 characters, counted as characters rather than bytes, at most
256 characters, free of control characters, not a single repeated character
or short pattern, and not on a small embedded list of common passwords
(compared case-insensitively, ignoring spaces, hyphens, underscores, and
dots). The policy is checked first and a failure names the rule that was
broken, so a short password is never reported as a setup or reset token
problem. Existing passwords are not re-evaluated: an administrator whose
password predates the 15-character minimum can still sign in, and the policy
applies the next time the password is changed.

The **Account security** section of Settings changes the password (the
current password is required, wrong current passwords are throttled like
logins, and every other session is signed out in the same transaction),
lists active sessions with their sign-in, last-activity, and expiry times,
and offers **Sign out all other sessions**. A session lasts at most 12 hours
and ends after 60 minutes without activity. The status page's 30-second
automatic refresh requests `/status?refresh=1`; those requests are
authenticated but do not count as activity, so an unattended status tab
cannot keep a session alive. Sessions are identified in the list (and in the
administrative audit log) by a short prefix of their stored token hash, which
cannot be used to authenticate.

`Strict-Transport-Security: max-age=31536000` is sent only on requests that
reached TailState over HTTPS: directly over TLS, or through a peer listed in
`TAILSTATE_TRUSTED_PROXIES` whose `X-Forwarded-Proto` says `https`. A
forwarded-proto header from any other peer is ignored. With
`TAILSTATE_COOKIE_SECURE=true` the session and CSRF cookies are named
`__Host-tailstate_session` and `__Host-tailstate_csrf` (Secure, `Path=/`, no
`Domain`), so another host in the same site cannot set or shadow them.
Sessions issued under the unprefixed names before the upgrade (or before
secure cookies were enabled) keep working until they expire; the next
sign-in replaces them, and the two namings are never combined. The
short-lived credential-form challenge cookies keep their page-scoped paths
and therefore their existing names.

## Password reset

Generate a one-time reset token:

```console
docker compose exec tailstate /tailstate admin reset
```

Then open `/reset`. Resetting the password invalidates existing sessions and any
outstanding reset token. A signed-in administrator who knows the current
password can instead use **Change password** under **Account security** in
Settings, which needs no shell access. Reset tokens expire after 30 minutes; generate another
token if one expires.

`admin reset` is safe to run while the service is serving: it opens the
existing database without bootstrap DDL, migrations, backfills, or storage
limit writes, writes only the reset token, and waits for the service's write
lock instead of failing with `database is locked`. It never creates a database
(a mistyped `TAILSTATE_DATA_DIR` fails with "database not found") and refuses a
database whose schema is not the current version; start the current release
once, after a verified backup, to migrate it first.

## Credential forms and throttling

Setup, login, and password-reset forms do not reject requests based on
`Origin`, `Referer`, or Fetch Metadata headers because reverse proxies can
rewrite those values. Each credential form also carries an action-bound,
single-use challenge: a signed hidden field bound to a signed per-browser
`SameSite=Strict` cookie. Issuing a form keeps no server-side state, so
unauthenticated page loads cannot evict a pending form, and several tabs in the
same browser can each submit their own form. Only submitted challenges are
remembered (until they expire) so they cannot be replayed. Challenges expire
after five minutes and are invalidated when TailState restarts; reload the page
if a challenge expires or a bookmarked form was opened before a restart. Setup
and reset still require one-time tokens, and authenticated state-changing forms
require CSRF tokens.

Setup, login, and reset submissions are throttled. Each client may fail five
times per action in 15 minutes; IPv6 clients are grouped by their /64 network
because one host can usually use any address in it, while IPv4 clients are
tracked per address. Independently, each action has a global budget of 30
failures per 15 minutes from any mix of sources; beyond it every further
failure doubles the wait (1 s, 2 s, 4 s, ... up to five minutes). A throttled
submission receives `429 Too Many Requests` with a `Retry-After` header (in
seconds) and the form explains the delay. Behind a reverse proxy, list the
proxy in `TAILSTATE_TRUSTED_PROXIES` so clients are throttled individually;
otherwise every user shares the proxy's bucket, and the Settings diagnostics
report `untrusted_forwarded_headers`.
Challenge and credential failures are exposed only through low-cardinality
route/outcome metrics; secrets, tokens, cookies, and request headers are never
logged.

## Trusted proxies

If the proxy forwards the original client address or terminates TLS, configure
only its actual source address as trusted, for example
`TAILSTATE_TRUSTED_PROXIES=127.0.0.1/32`. TailState ignores
`X-Forwarded-For` and `X-Forwarded-Proto` from every other peer.
Enabling `TAILSTATE_COOKIE_SECURE=true` without a trusted proxy is rejected at
startup because this binary serves plain HTTP and must receive the proxy's
authenticated HTTPS indication.

## Administrative audit trail

TailState records its own security-relevant configuration changes in a
durable `admin_audit` table, so a change made with a stolen session or by an
insider is not silent. One record is written for each sign-in, failed
sign-in, sign-out, setup claim, token password reset, password change, and
"sign out all other sessions"; for each monitoring settings save that changes
something (tailnet, OAuth client ID, OAuth secret rotation, OAuth scopes,
either polling interval, expiry warning windows or tag filter, webhook secret
set or cleared); for each notification destination added, edited (name, URL,
enabled state, routing, message format), enabled, disabled, or removed (after
the confirmation step); for each mute rule added or removed; for each
read-only API token created or revoked; and for the status page's operator
actions, **Reconcile now** (when the request is accepted, not when the
cooldown refuses it) and **Retry dead letters** (when it requeued at least
one notification). A record holds
the event, time, outcome, the client address (taken from
`X-Forwarded-For` only when the peer is a trusted proxy), a short reference
to the acting session, the affected object as `kind:id`, and the **names** of
the changed fields. Values are never recorded: the store accepts only the
fixed event vocabulary and identifier-shaped field names, so a URL, secret,
password, or display name cannot be written by mistake. Every record is also
logged as a structured `administrative action` line (`event`, `outcome`,
`client_ip`, `session`, `target`, `fields`) for SIEM collection, and the 25
newest records are listed under **Recent administrative activity** in
Settings. Records are kept for 365 days and removed afterwards by the same
bounded, resumable retention cleanup as other tables
(`tailstate_cleanup_rows_total{table="admin_audit"}`).

Command-line administration (`tailstate admin reset`, `admin rekey`,
`admin backup`, `admin compact`) is not recorded in the audit table: those
commands run with direct access to the database and master key, outside any
web session, and `admin rekey`/`admin compact` require the service to be
stopped. A password reset token issued by `admin reset` is audited when it is
used on the reset page; the commands report their own result on standard
output or standard error for the operator who ran them.

High-risk changes also send a "TailState configuration changed" system
notification (action, changed field names, object, client address, time) to
every destination that was enabled **before** the change: monitoring
settings changes (including an OAuth identity change, which notifies every
enabled destination and is not dead-lettered by the identity switch),
password resets and changes, mute rules added, API tokens created, and
destination URL, routing, disable, and removal changes. The notice is queued in the same transaction as
the audit record. A destination that the change itself disables, removes, or
points at a new URL is notified directly at its current URL before the
change is applied (bounded to 10 seconds and best effort, so an unreachable
destination can still be removed; the outcome is logged), which means
disabling or deleting the last enabled destination still tells that
destination first.

## Read-only API

Machine clients (SIEM, SOAR, compliance pipelines) read TailState through a
small read-only API instead of scraping HTML or sharing the administrator
password. Create a token under **API tokens** in Settings: give it a name,
one or more scopes, and an expiry of 30, 90, 180, or 365 days. The token
(`tsapi_...`) is shown once, on the Settings page the form returns to, and
cannot be displayed again: the form uses Post/Redirect/Get, the secret is held
only in server memory until that page is shown to the session that created
it (at most 60 seconds), and it is never placed in a URL, a cookie, or the
database. Reloading the page does not show it again. Only its SHA-256 hash is
stored. At most 25 tokens can be active at once.
Revoking a token takes effect on the very next request. Expired and revoked
tokens stay listed for 30 days after their expiry and are then removed by
retention cleanup. Creating a token is recorded in the administrative audit
trail and notified to every enabled destination; revoking one is recorded.

| Endpoint | Scope | Response |
| --- | --- | --- |
| `GET /api/v1/status` | `status:read` | JSON status: setup and baseline state, notification state, destination counts, outbox and webhook queue counts, resource counts, and collectors with the bounded readiness reasons |
| `GET /api/v1/history` | `history:read` | NDJSON History page (`application/x-ndjson`) |
| `GET /api/v1/evidence` | `evidence:read` | Signed evidence pack, identical to the History download (format version 5) |

```console
curl -fsS -H "Authorization: Bearer $TAILSTATE_API_TOKEN" https://tailstate.example/api/v1/status
curl -fsS -H "Authorization: Bearer $TAILSTATE_API_TOKEN" \
  "https://tailstate.example/api/v1/history?severity=high&limit=50"
```

`/api/v1/history` and `/api/v1/evidence` accept the History page's filters
with the same meaning (`collector`, `event_type`, `resource`, `severity`,
`batch`, and the whole-UTC-day date range `from` and `to` as `YYYY-MM-DD`,
`to` inclusive) and its paging (`cursor` for older batches; history also
accepts `after` for newer batches). A malformed date is refused with `400`
(`invalid_request`) instead of being ignored. History also accepts `limit`
(1 to 100 batches, default 20). Each history
line is either one `{"type":"batch",...}` object (batch metadata, the ledger
sequence and hash, events with field diffs and redacted normalized
snapshots, and per-destination delivery status by destination ID and name)
or the final `{"type":"page",...}` trailer with `has_next`, `next_cursor`, and
a ready-made `next` path towards older batches; `has_prev`, `prev_cursor`, and
a `prev` path towards newer batches (both paths keep the filters and limit);
and the `bytes_read` and
`byte_limit` of the History page budget (`TAILSTATE_HISTORY_PAGE_LIMIT_BYTES`).
A page stops at that budget, so follow `next` until `has_next` is false to
read everything without duplicates. Each response is built completely before
it is sent. Token checks, status, history, and evidence are pure reads served
from the read-only database pool, so the API keeps answering while a
collector or cleanup holds the writer; the once-a-minute "last used" update
is best effort and bounded.

Only `Authorization: Bearer <token>` authenticates the API; browser session
cookies do not. A missing, unknown, revoked, or expired token receives `401`
with a `WWW-Authenticate: Bearer` challenge, a token without the endpoint's
scope receives `403` (`insufficient_scope`), and errors are JSON
(`{"error":...,"error_description":...}`). Each token may make 60 requests per
minute; beyond that, and after five failed authentications per client in 15
minutes, requests receive `429` with `Retry-After`. Failed guesses never
block a valid token. Responses never include destination URLs, OAuth or
webhook secrets, collector error text, or token values: destinations appear
only as counts or by ID and display name.

Multiple user accounts with roles (for example administrator and viewer) and
OIDC sign-in are out of scope for this release and remain future work; the
API tokens are the supported way to give read-only access without sharing
the administrator password.

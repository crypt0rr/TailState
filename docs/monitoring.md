# What TailState monitors

TailState polls the read-only Tailscale API on two schedules (devices and
secondary inventory), compares each normalized response with the stored
baseline, and records semantic changes. This page describes what each
collector watches, how changes are detected, and the optional sources that
enrich them. How changes are delivered is described in
[Notifications](notifications.md); how they are recorded and exported in
[History and evidence](evidence.md).

## Collectors and monitored fields

- Devices, stable tailnet IPv4/IPv6 addresses, details, authorization, tags, key expiry, client version, routes, posture attributes, and invites.
- Users (members and shared/external users, collected with `type=all`) and user invites. Shared users that already existed when upgrading from a version that collected members only are absorbed silently into the existing baseline on the first poll after the upgrade; a user shared after that is reported as created.
- DNS configuration from `dns/configuration`: nameservers, split DNS, search paths, MagicDNS and override-local-DNS preferences, and each resolver's `useWithExitNode` flag. If that endpoint returns `404`, TailState falls back to the four legacy DNS endpoints.
- Tailscale Services (`services`): each service's name, display name, addresses, ports, tags, and comment.
- OAuth apps (`oauth_apps`): name, description, redirect URIs, granted scopes, and allowed node attributes (never the client secret or timestamps).
- Policy section fingerprints without storing policy contents.
- Credential metadata, webhook configuration inventory, log-streaming configuration/status, contacts, posture integrations, and tailnet settings.
- Upcoming expiry of device node keys and auth keys: a daily check warns before they expire (see [Expiry warnings](#expiry-warnings)).
- Who made each change: the configuration audit log names the actor in History, notifications, the API, and signed evidence (see [Change attribution](#change-attribution)).

The REST API does not expose authoritative online state. TailState therefore does **not** generate online/offline notifications. What is ignored depends on the collector:

| Collector | Monitored fields | Always ignored |
| --- | --- | --- |
| Every collector | (see below) | `lastSeen`, `connectedToControl`, `clientConnectivity`, `endpoints`, `lastUpdated`, `createdAt`, `updatedAt`, `timestamp`, `requestedAt`, `profilePicUrl`, and the order of set-like arrays. Secret values (for example `secret`, `token`, `password`, `clientSecret`, `s3SecretAccessKey`, `gcsCredentials`) and URL fields are replaced by SHA-256 fingerprints |
| `devices` | Allowlist: `addresses`, `id`, `nodeId`, `user`, `name`, `hostname`, `clientVersion`, `updateAvailable`, `os`, `created`, `keyExpiryDisabled`, `expires`, `authorized`, `isExternal`, `blocksIncomingConnections`, `enabledRoutes`, `advertisedRoutes`, `tags`, `tailnetLockError`, `tailnetLockKey`, `sshEnabled`, `postureIdentity`, `isEphemeral`, `distro` | Any other top-level field, including `multipleConnections`, `machineKey`, and `nodeKey` (rotating keys) |
| `users` | Allowlist: `id`, `displayName`, `loginName`, `tailnetId`, `created`, `type`, `role`, `status` (`active` and `idle` are both recorded as `enabled`) | Any other top-level field, including `currentlyConnected` and `deviceCount` |
| `device_details` | Allowlist: `postureAttributes` and `deviceInvites` | Posture attribute `expiries` timestamps, and the `node:os`, `node:osVersion`, and `node:tsVersion` attributes (reported by `devices`) |
| `posture` | Allowlist: `provider`, `cloudId`, `clientId`, `tenantId`, `id`, `configUpdated`, `status` (reduced to `healthy` or `error`) | Any other top-level field, such as synchronization counters |
| `log_streaming` | Allowlist: `configuration`, `network`; stream status is reduced to `healthy`, `error`, or `unavailable` | Any other top-level field |
| `keys`, `webhooks`, `user_invites`, `settings`, `contacts`, `dns`, `policy` | Open schema: every field except the global ignore list (policy is stored as section fingerprints) | Only the global ignore list |

Because the last group has an open schema, a field that Tailscale adds to its API response appears on every resource of that collector at once. TailState reports that as one "upstream schema change" line in the digest (see [Noise controls](notifications.md#noise-controls)); History still lists every resource. DNS nameserver and search-path ordering is preserved because position determines resolver behavior. Tailscale client-version and `updateAvailable` changes remain alertable.

## Change detection

- The first complete supported inventory is a silent baseline.
- Stable additions and modifications alert on the next successful poll.
- Removals require absence from two complete successful polls.
- One device change is reported once. A device's appearance and removal are `devices` events only (its `device_details` snapshot is created and deleted silently); routes and client/OS versions are reported by `devices`, so `device_details` does not fetch the routes endpoint and ignores the `node:os`, `node:osVersion`, and `node:tsVersion` posture attributes. Snapshots stored by older releases are re-normalized before diffing, so upgrading does not report drift. A DNS snapshot stored from the legacy endpoints is compared with the `dns/configuration` response only on the fields both express (nameservers, MagicDNS, search paths, split DNS), so the upgrade, and any later fallback between the two endpoints, is silent unless one of those fields actually changed. New collectors (`services`, `oauth_apps`) take a silent baseline on their first successful poll.
- Failed or partial polls never delete snapshots.
- Single-object endpoints (tailnet settings, contacts, policy, the DNS configuration and each legacy DNS sub-endpoint, and log-streaming configuration and status) must return a JSON object. A `null`, empty, array, or scalar body is treated as an invalid upstream response: the collector fails, no events are recorded, and the last snapshot is kept.
- Tailscale API requests retry network errors, `429`, and the transient gateway statuses `502`, `503`, and `504` with exponential backoff; a transient OAuth token-endpoint failure (network error, `429`, or `5xx`) is retried the same way instead of failing every request that needs a token. Retries honor `Retry-After` while capping a provider delay at five minutes and the complete retry window for one request at 30 seconds; a gateway retry that would not fit in that window reports the upstream status immediately. Cursor pagination keeps the original query parameters (for example `fields=all`) on every page. Collectors also have a two-minute poll deadline, so a throttled endpoint cannot stall the scheduler indefinitely.
- Each paginated collection is bounded to 10,000 items and 64 MiB of response data across all pages, in addition to the 16 MiB per-response cap. If an aggregate limit is exceeded, the collector fails without applying partial inventory or deleting the last known snapshots. Device-detail requests share a bounded eight-worker queue so a large device list cannot create one job and result buffer per device. If the two-minute device-detail deadline expires, the poll is reported as partial with the number of devices left unrefreshed, their previous snapshots are kept, and the next poll starts with the stalest devices so every device is eventually refreshed.
- A failed or partial collector is retried after 30 seconds, and each further consecutive failure doubles the delay up to that collector's configured polling interval; a successful poll resets the backoff. A permanently broken endpoint or device therefore settles back to the normal cadence instead of repeating its requests every 30 seconds. Webhook triggers that are processed together poll the union of their collectors once, while each trigger still succeeds or retries only on the collectors it requested.
- Per-collector retry deadlines (failure retries, unsupported confirmation) are persisted and honored after a restart or a settings save, so a short retry is never replaced by the full polling interval.
- A 403/404 from an optional plan-specific endpoint is treated as an
  unsupported response. Collectors that have never produced a baseline are
  retried every six hours. For an established baseline, the first response is
  recorded as pending confirmation and retried after five minutes; only a
  second consecutive response opens the six-hour unsupported window. Baselines
  and snapshots remain intact across that interval, so recovery reports drift
  instead of silently rebasing. A later non-403/404 failure is recorded as a
  transient supported collector failure rather than retaining the unsupported
  label.
- Log streaming is the exception to the 404 rule: Tailscale returns `404` from
  `/logging/{kind}/stream` when no stream is configured, so TailState records
  that kind as `{"configured": false}` and diffs it like any other state.
  Deleting a configuration or network log stream, or configuring the first one,
  is reported as a change. A `403` for one kind is recorded the same way while
  the other kind stays readable; only a `403` for both kinds marks the collector
  unsupported. When a stream's status endpoint returns `404`, `403`, or `502`,
  the stream configuration is kept and its status is recorded as
  `unavailable`.
- Collection endpoints must return the documented array field. TailState treats
  an omitted, `null`, or wrong-typed `userInvites` or `webhooks` field as an
  invalid upstream response and preserves the last known snapshots; an
  explicitly returned `[]` is the healthy empty result. This prevents a
  malformed or permission-filtered response from looking like mass removal.

The `device_details` collector uses a bounded eight-worker fan-out and a two-minute per-collector deadline; usable partial results are retained and marked in the status page and metrics with the number of devices whose details are missing.

## OAuth scopes

TailState requests `all:read` by default. To run with a least-privilege OAuth
client, grant it only the read scopes for the collectors you want and list the
same scopes (space- or comma-separated) in **OAuth scopes** on the Settings
page. Only read scopes (ending in `:read`) are accepted; TailState never
requests a write scope.

| Collector | Read scope |
| --- | --- |
| `devices` (required; also used by the settings test) | `devices:core:read` |
| `device_details` | `devices:posture_attributes:read`, `device_invites:read` |
| `users` | `users:read` |
| `user_invites` | `user_invites:read` |
| `dns` | `dns:read` |
| `policy` | `policy_file:read` |
| `keys` | `auth_keys:read`; add `api_access_tokens:read`, `oauth_keys:read`, and `federated_keys:read` to see those credential types |
| `webhooks` | `webhooks:read` |
| `log_streaming` | `log_streaming:read` |
| `contacts` | `account_settings:read` |
| `posture` | `feature_settings:read` |
| `settings` | `feature_settings:read`; some fields also need `logs:network:read`, `networking_settings:read`, or `policy_file:read` |
| `services` | `services:read` |
| `oauth_apps` | `oauth_apps:read` |
| Change attribution (configuration audit logs, not a collector) | `logs:configuration:read` |

A collector whose endpoint answers `403` is shown on the status page as
**Unsupported** with the label "insufficient OAuth scope or plan (HTTP 403)"
(Tailscale uses the same status for a missing scope and a plan without the
feature); a `404` is labelled "not available for this tailnet". Without
`devices:posture_attributes:read` or `device_invites:read`, the per-device
detail is recorded as an explicit unsupported value. Unsupported collectors are
informational and do not degrade readiness. Changing the scopes makes every
unsupported collector due for an immediate re-check; a collector that becomes
readable baselines silently. Narrowing scopes can hide resources or fields
(for example other credential types under `keys`), which are then reported as
removed or changed, so settle on the scopes before the first baseline.

Without `logs:configuration:read` changes are still detected and notified;
they are only not attributed, and the status page shows **Change
attribution: Unsupported** with the HTTP 403 label.

Per-service hosts and approvals (`/services/{name}/devices` and
`/services/{name}/device/{id}/approved`) are not collected: Tailscale requires
the write-capable `services` scope for them.

## Expiry warnings

TailState already stores each device's key expiry and each auth key's expiry,
but those fields only produce events when they change. A separate daily check
reads the current snapshots and warns *before* a device node key or auth key
expires, so a server does not silently drop off the tailnet and automated
enrolment does not break on an expired auth key.

- **Windows.** Each window is a number of days before expiry (default `14` and
  `3`; at most four windows between 1 and 365 days). Leave the field blank on
  the Settings page to disable warnings.
- **One grouped notification per window.** Every resource that newly entered a
  window is listed in one system notification for that window, with its name,
  tags, and expiry. A resource inside several windows at once is reported once,
  in the tightest window.
- **Each resource and window alerts once.** The warning state lives in the
  existing `meta` table (no schema change) and is committed in the same
  transaction as the notification. When the expiry changes (for example after a
  device is re-authenticated or an auth key is replaced) the state for that
  resource resets, so the new expiry is warned about again when it comes close.
- **Delivered like health alerts.** Expiry warnings are system notifications,
  not inventory changes: like collector health alerts they reach every enabled
  destination regardless of routing and mute rules, are rendered in each
  destination's message format, name the instance and tailnet in the title,
  carry an `Observed at` line, and link to `/status` when
  `TAILSTATE_PUBLIC_URL` is set. A long list is shortened at line boundaries
  with an explicit count of the omitted resources.
- **Exclusions.** Devices with key expiry disabled, ephemeral devices, revoked
  or invalid keys, OAuth clients, and short-lived API access tokens are never
  warned about. Only machine auth keys (`keyType: auth`) are considered.
- **Tag filter.** Optionally list tags such as `tag:server`; only devices and
  auth keys carrying one of them (for auth keys, the tags they create devices
  with) are warned about.

The status page shows an **Expiring soon** card listing everything that expires
within the widest window (14 days when warnings are disabled), using the same
exclusions and tag filter. The first check runs two minutes after start-up so
the first poll can refresh the snapshots; failed checks are retried after 15
minutes.

## Change attribution

TailState explains **what** changed; the Tailscale configuration audit log
(`GET /tailnet/{tailnet}/logging/configuration`, scope
`logs:configuration:read`, included in `all:read`) tells **who** changed it.
The audit log is an optional source, not a collector: it creates no
snapshots, never affects collector health or readiness, and is read only
when a poll can produce a change.

- **When.** Before a poll's changes are recorded, TailState reads the audit
  log for the window since the previous successful poll of the affected
  collectors, widened by two minutes on both sides for clock skew (and by the
  polling interval when a removal is confirmed, because removals are reported
  one poll after the resource disappeared). The window is at most 24 hours,
  at most 5,000 entries are read, and the lookup has a strict 10-second
  budget: a slow or failing audit log delays a batch by at most that budget
  and never fails it.
- **Matching.** Entries are correlated with each change by target: devices by
  their node ID, users, auth keys, invites, and webhooks by ID, and the
  policy file, DNS, contacts, log streaming, posture integrations, and tailnet
  settings by the tailnet property the entry changed (for example `ACL` or
  `DNS_CONFIG`). Only an action that fits the change counts: a created device
  needs a create/approve/login entry, a removed one a delete, and a device
  field change an entry for that property (a tag change matches `ACL_TAGS`;
  client version, OS, or address changes reported by the node itself never
  match an administrator's edit). The latest matching entry wins; failed
  attempts are ignored.
- **What is stored.** Only the actor's login and display name, the actor
  type, the origin (admin console, API, ...), the audit action (for example
  `NODE.UPDATE.ACL_TAGS`), the target, and the audit timestamp, each bounded
  in length and stripped of control characters. The audit log's old and new
  values (which may contain policy text), action details, and error text are
  never decoded into a stored value, persisted, logged, or exported.
- **Where it is shown.** History shows **Changed by** for every change of an
  attributed batch, for example "alice@example.com (Alice) via admin console"
  or "k123 [OAuth client] via API", followed by the audit action and time.
  Digests add a **Changed by** line under each listed change in every message
  format, `/api/v1/history` adds `changed_by`, the `attribution` record, and
  the batch `attribution_status`, and evidence packs (format version 5) sign
  the record (see [History and evidence](evidence.md#evidence-packs)).
- **Unknown actors.** A change without a matching entry, or every change of a
  batch whose lookup failed or timed out, shows "actor unknown"; the batch
  itself is recorded and notified as usual.
- **Unsupported.** A `403` (missing scope or plan) or `404` (logging not
  available) degrades silently: changes carry no attribution and no
  "Changed by" line, the status page's **Change attribution** card shows
  **Unsupported** with the bounded reason, and the audit log is not asked
  again for six hours or until the tailnet, OAuth client, or OAuth scopes
  change. The card also shows **Supported** or **Unavailable** (last lookup
  failed, with a bounded reason such as `timeout`), and `/api/v1/status`
  reports the same state.
- **Metrics.** `tailstate_attribution_lookups_total{outcome="complete|unsupported|failed"}`
  counts lookups and `tailstate_attribution_changes_total{result="matched|unknown"}`
  counts changes in attributed batches.

## Faster reconciliation with Tailscale webhooks

Polling remains enabled even when webhooks are configured. To reduce the time
between a tailnet change and its explanation in TailState, create a webhook in
the Tailscale admin console and enter its signing secret in **Settings**. The
Settings page shows "Webhook acceleration: enabled" with the time of the last
accepted delivery while a secret is stored, or "disabled" otherwise; the
"Remove the configured webhook secret" option appears only when there is a
secret to remove. Point the webhook at:

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

Once the signature is valid the delivery is authentic, so content outside
TailState's own bounds (more than 100 events, an empty batch, or an event type
that is missing, longer than 128 bytes, or contains control characters) is
still recorded with capped metadata, answered with `202`, and queued as a
complete reconciliation rather than dropped. Response codes are:

| Status | Meaning |
| --- | --- |
| `202` | Accepted (or a duplicate of an accepted body); the JSON body reports `"reconciliation": "targeted"` or `"full"` |
| `400` | Empty body, or a correctly signed body that is not a JSON event array |
| `401` | Missing or invalid signature, or a timestamp outside the accepted window |
| `404` | No webhook secret is configured |
| `413` | Body larger than 1 MiB |

`tailstate_webhook_requests_total{outcome=...}` counts `accepted`,
`content_fallback`, `duplicate`, `invalid_signature`, `malformed`, `too_large`,
`not_configured`, and `unavailable` separately, so a burst that fell back to a
full reconciliation is never mistaken for a signature problem.

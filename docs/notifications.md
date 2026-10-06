# Notifications

TailState delivers every change digest, collector health alert, expiry
warning, and release notice through [Shoutrrr](https://shoutrrr.nickfedor.com/latest/)
destinations configured on the authenticated Settings page. Notifications are
an alerting channel, not the record: every change is also kept in
[History](evidence.md), and delivery problems are visible in
[metrics](metrics.md).

## Destinations

Any service registered by the pinned release of the [nicholas-fedor/shoutrrr](https://github.com/nicholas-fedor/shoutrrr) fork (see `go.mod`) is accepted. See the [Shoutrrr service overview](https://shoutrrr.nickfedor.com/latest/services/overview/) for supported endpoint schemes and provider-specific URL formats. Generic webhooks can be configured with `generic://` URLs and Shoutrrr query options such as `template=json&messagekey=text`.

Shoutrrr supports Mattermost natively, for example:

```text
mattermost://TailState@mattermost.example/hooks-token?icon=satellite
```

For Matrix, prefer an access-token URL such as `matrix://:<access-token>@matrix.example/?rooms=!roomid:matrix.example`. A `matrix://user:password@host/...` URL makes Shoutrrr log in to the homeserver every time its sender is constructed: once when the destination is saved or tested and once per delivery attempt. Those logins use TailState's bounded, redirect-rejecting transport, and a rejected or rate-limited login is classified like any other provider response, but frequent logins can still hit homeserver login rate limits (for example Synapse's `rc_login`) and each one issues a new access token. Token URLs authenticate without a login request.

Destinations are added, edited, tested, and removed on the Settings page; see
[Web interface](operations.md#web-interface).

## Message content and rendering

- Every notification names the tailnet (prefixed by `TAILSTATE_INSTANCE_LABEL` when set) in its title and states when it was observed, in a compact UTC form such as `6 Oct 2026 09:14 UTC` (History and the API keep full RFC 3339 times): digests on their closing context line, other notifications on an `Observed at` line. With `TAILSTATE_PUBLIC_URL` set, digests link to their History batch (`/history?batch=<id>`) and health alerts and expiry warnings to `/status`. The Settings test message names the instance, tailnet, TailState version, and time.
- Multiple changes in one poll become one digest, fanned out into one durable outbox item per enabled destination (subject to its [routing rules](#severity-and-routing)). The outbox stores a format-neutral message that is rendered when it is sent, in the format the receiving service displays: Slack mrkdwn for `slack` and `googlechat` (single-asterisk bold, no `###` headings, `<url|label>` links, and `&`, `<`, `>` escaped so a resource name cannot mention a channel), plain text for `telegram`, `smtp`, `pushover`, `matrix`, `ntfy`, `gotify`, `signal`, `bark`, `join`, `lark`, `wecom`, `pushbullet`, `ifttt`, `opsgenie`, `pagerduty`, `mqtt`, `twilio`, `xmpp`, `signalgrid`, and `hass`, and Markdown for every other service (for example `mattermost`, `discord`, `rocketchat`, `zulip`, `teams`, and `generic`). Each destination can override the automatic choice under **Edit destination** in Settings; the Settings test message uses the same format. Each digest is fitted to the receiving service's message limit (for example 4,096 bytes for Telegram, Lark, WeCom, and ntfy, 1,024 for Pushover, and 10,000 for Zulip) by dropping whole lines from the end and adding an explicit "lines omitted, see History" note. A provider that still rejects a message as too large (or with HTTP 413) dead-letters it immediately instead of retrying for 24 hours.

## Example digest

A batch of 19 changes (with attribution, 3 muted changes, and a 12-device
client rollout) as an email, ntfy, Gotify, or Pushbullet destination receives
it in plain text. The first line is the title, which these services show in
their own title field (see [Titles](#titles)):

```text
🔴 19 Tailscale changes (5 high) · prod (example.com)
2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low

🔴 ✏️ web-02 (device) changed
  • Changed by: ci-bot [api key]
  • tags: +tag:db
🔴 ➕ kAbc123CNTRL (key) created
  • Changed by: alice@example.com
🔴 ✏️ Tailnet policy changed
  • Changed by: alice@example.com
  • section acls changed (3f9a1c0e → c41b7e2a)
  • section ssh added (9e8d7c6b)
🔴 ✏️ bob@example.com (user) changed
  • Changed by: alice@example.com
  • role: member → admin
🔴 ✏️ SIEM webhook (webhook) changed
  • Changed by: actor unknown
  • endpointUrl: secret changed (fingerprint aa11bb22 → 99887766)
🟠 ➕ laptop-new (device) created
  • Changed by: actor unknown
🟠 ✏️ DNS configuration changed
  • Changed by: actor unknown
  • searchPaths: now example.com, corp.example.com
⚪ 📦 12 devices: clientVersion 1.80.2 → 1.82.1

3 muted changes not shown · 5 Oct 2026 12:00 UTC · Batch 1842 in History: https://tailstate.example/history?batch=1842
```

The layout is compact:

- **Title:** the number of changes, led by the icon of the highest severity
  and with the count of that severity (high or medium), so push and e-mail
  previews show volume and urgency. Services with a title field receive it
  there.
- **Header:** the counts by kind and by severity; zero counts are left out.
- **Change lines:** the severity and kind icons, the name, the resource type
  ("device", "user", "key"; left out for the single policy, DNS, settings,
  contacts, and log streaming resources), and the kind as a word, so the line
  reads the same in plain text and to screen readers. Field changes follow as
  bullets. Device names lose the tailnet's MagicDNS suffix
  (`web-02.tail1234.ts.net` is shown as `web-02`); History, the API, and
  evidence packs keep the full name.
- **Fleet lines:** field transitions shared by the same resources are one line,
  for example "12 devices: clientVersion 1.80.2 → 1.82.0, updateAvailable
  true → false".
- **Context line:** the muted count, the observation time, and the History
  link close the digest. When a digest is shortened for a small destination,
  change lines are dropped before this line, so it is always delivered.

The same digest per service:

| Service | Title | Body |
| --- | --- | --- |
| Email (`smtp`) | Subject | Plain text as above, without the title line |
| Telegram | Bold first line (HTML mode) | Plain text as above |
| ntfy, Gotify, Pushbullet | Notification title | Plain text as above |
| Pushover | Notification title | Plain text, shortened to 1,024 bytes ("Shortened for this destination: 3 more lines omitted…" before the context line), so the high-severity changes stay |
| Discord | Embed title | Markdown in one embed (`**bob@example.com** (user) changed`, `` `role`: `member` → `admin` ``) |
| Microsoft Teams | Card heading | Markdown, one text block per line |
| Slack | Header block and preview text | Slack mrkdwn in one section (`*bob@example.com*`, links as `<url\|label>`) |
| Mattermost, Rocket.Chat, Zulip, generic webhooks | `### 🔴 19 Tailscale changes (5 high) · prod \(example.com\)` heading line | Markdown |
| Matrix, Signal, other plain-text services | First line | Plain text as above |

## How values are shown

Field changes are written for reading, not as raw JSON. History, the API, and
evidence packs keep the full normalized values; only notifications present
them this way, and every value stays escaped for the destination's format.

| Value | Shown as |
| --- | --- |
| Policy section (TailState stores only a SHA-256 fingerprint of each section, never policy text) | ``section `acls` changed (`3f9a1c0e` → `c41b7e2a`)``, ``section `ssh` added (`9e8d7c6b`)``, ``section `tests` removed`` |
| Redacted secret (`{"redacted_sha256": …}`) | ``secret changed (fingerprint `aa11bb22` → `99887766`)``, `secret set`, `secret removed` |
| Text, number, or boolean | Without JSON quotes: `` `member` → `admin` ``, `` `false` → `true` `` |
| Other 64-character fingerprints | The first 8 characters and `…` |
| List of values (tags, routes, addresses) | The elements added and removed: ``+`tag:db`, −`tag:old` `` (at most 10 per side, then "N more") |
| Ordered DNS lists (nameservers, search paths) | The new order, plus what was added or removed: ``now `8.8.8.8`, `1.1.1.1` (+`8.8.8.8`)`` |
| Absent or null value | `(not set)`; an empty string is `(empty)` |
| Object | Bounded compact JSON, with fingerprints shortened |

Fleet summaries use the same presentation, for example
"🔴 📦 6 devices: `tags` +`tag:db`".

## Titles

The title of every notification (its icon, title, instance label, and
tailnet, for example `🧪 TailState test · lab (example.com)`) is sent in the
service's own title field where Shoutrrr has one, and the body then starts
with the first content line instead of repeating the title:

| Service | Where the title appears |
| --- | --- |
| `smtp` (email) | Subject |
| `discord` | Embed title |
| `slack` | Header block, and the message text used for push previews |
| `teams` | Card heading |
| `telegram` | Bold first line |
| `gotify`, `ntfy`, `pushover`, `pushbullet` | Notification title |

Every other service receives the title as the first line of the message. This
includes Mattermost and Matrix, which would only prepend a separate title as
unformatted text, and Zulip, which would use it as the stream topic.

Shoutrrr fails a send that carries a parameter the service does not know, so
TailState passes only the parameters on a per-service allowlist taken from the
pinned Shoutrrr release; a test fails when a Shoutrrr update drops or renames
one of them. A parameter set in the destination URL always wins: with
`?title=` (for email `?subject=` or `?title=`) in the URL, TailState keeps the
operator's title and leaves its own as the first line of the body. Telegram
receives a separate title only when the URL sets no `parsemode` (Shoutrrr shows
a title only in its HTML mode, escaping the body), and a Discord URL with
`json=yes` receives the body unchanged.

## Discord

A Discord message arrives as one webhook request: the title is the embed
title, and the body follows as embeds of whole lines (at most 2,000
characters each, within Discord's 6,000-character message budget), so every
line arrives exactly once and in order. TailState also passes
`splitlines=no` unless the URL sets `splitlines`.

The pinned Shoutrrr release defaults to `splitlines=yes`, which sends one
embed per line in batches of ten, and its batching overwrites lines already
queued: a message longer than ten lines loses its first lines and repeats
later ones. A URL that sets `splitlines` keeps Shoutrrr's own behaviour; with
`splitlines=yes` the Settings test and `doctor` (`discord_splitlines_forced`)
warn about this. Remove the parameter, or set `splitlines=no`, to use
TailState's line-preserving delivery. A URL with `json=yes` sends the body as
a raw Discord payload, unchanged.

## Slack

`slack://` destinations, in both forms Shoutrrr supports (an incoming-webhook
token or a bot/user token with a channel), receive one native Slack message
instead of Shoutrrr's one attachment per line: a top-level `text` with the
title (shown in push previews), a header block with the title, and the body as
Block Kit `section` blocks of whole lines (at most 3,000 characters each and 50
blocks per message). TailState builds this payload itself, parses the URL with
Shoutrrr's Slack parser, and sends it through the same bounded,
redirect-rejecting HTTP client as every other delivery, so failures are
classified the same way (permanent 4xx, `Retry-After`). The URL options
`botname`/`username`, `icon`, `thread_ts`, `color` (the sections are then
wrapped in one attachment with that colour bar), and `title` keep their
meaning. A destination whose format is overridden to Markdown or plain text
receives `plain_text` sections, which Slack never parses for mentions or
links.

## Severity and routing

Every change is classified with a built-in severity. The digest prefixes each
line with 🔴 high, 🟠 medium, or ⚪ low, the header counts the changes per
severity, and History can be filtered by severity.

The digest lists its lines by severity: every high-severity line comes before
any medium one, and every medium line before any low one. Fleet and schema
summaries are ordered by their own severity like individual changes (a low
client rollout summary never precedes a high-severity change), and lead their
severity group; within a group, changes are ordered by collector and then
name. Because a digest that is too large for a destination is shortened from
the end, the least important changes are dropped first. When high-severity
changes still have to be dropped (a batch with more of them than the
destination's budget holds), the closing note says how many, for example
"Shortened for this destination: 31 more lines omitted, including 29
high-severity changes. See TailState History for the full batch."

| Severity | Changes |
| --- | --- |
| High | Any `policy`, `log_streaming`, `settings` (tailnet settings), `webhooks`, or `oauth_apps` change (OAuth applications grant API access, like keys); a `keys` resource created; a `users` change to `role`; a `devices` change to `tags`, `authorized` false→true, or `keyExpiryDisabled` false→true |
| Low | A `devices` change whose changed fields are all `clientVersion`, `updateAvailable`, `os`, or `distro` |
| Medium | Everything else, for example devices created or removed, route changes (`enabledRoutes`, `advertisedRoutes`), user invites, users created or removed, keys removed, DNS, contacts, posture, and `services` changes |

A changed resource takes the highest severity of its changed fields; a change
whose field list was truncated is at least medium, because the omitted fields
cannot be shown to be routine.

Each destination has routing rules, edited under **Edit destination** in
Settings: a minimum severity (all, medium and high, or high only), collectors
to include (empty means all), collectors to exclude, and change kinds
(created, changed, removed; none selected means all). Fan-out renders one
digest per distinct rule set, so each destination receives only its matching
changes, and a destination whose rules match nothing in a batch receives no
digest. For example, a paging channel with "high only" receives nothing for a
batch of client upgrades, while a default destination still receives it.
Destinations created before routing existed, and new destinations, receive all
changes. Collector health, expiry warnings, and release notifications are not
inventory changes and always reach every enabled destination.

## Noise controls

Predictable noise is reduced in the digest without losing the audit trail:

- **Mute rules** are managed under **Noise controls** in Settings (CSRF
  protected). A rule mutes a collector (`dns`), one field path of a collector
  (`devices.clientVersion`, which also covers nested paths below it), every
  device carrying a tag (`tag:ci`, matched in the before or after snapshot), or
  one resource by ID or exact name. Muted changes are still recorded in History
  and in the signed evidence ledger, flagged `muted` in the History page and in
  evidence exports, but are left out of digests; the digest states how many
  muted changes it omitted, and a batch of only muted changes sends nothing. A
  change whose fields are only partly muted is notified with its remaining
  fields. Rules apply to batches recorded after they are added; at most 200
  rules are kept.
- **Fleet summarisation:** when the same field transition (for example
  `updateAvailable` false→true) affects at least 5 resources of a collector in
  one batch, the digest shows one line such as "143 devices: `updateAvailable`
  `false` → `true`". Transitions that affect exactly the same resources share
  one line; the digest's context line links to the batch in History.
- **Schema-change detection:** when a field becomes newly present (or absent)
  on every resource a collector returned in one batch (at least 2 resources),
  the digest shows one "upstream schema change" line instead of one diff per
  resource.

## Delivery semantics

- Each destination receives its notifications in the order they were created, also after an outage: while a destination's oldest undelivered item is backing off after a failure (or still in flight), its younger items wait behind it instead of overtaking it when their own shorter retry delay expires, so a "collector recovered" message cannot arrive before the matching "unhealthy" one. Destinations are independent: one that fails or hangs holds back only its own queue. After a destination's first failed send in a delivery pass, its remaining items in that pass are returned unsent (without counting an attempt), so a blackholed destination delays the others by at most one send timeout (15 seconds) per pass.
- Shoutrrr deliveries retry for up to 24 hours from when each item was queued (including time spent waiting behind an older item), across restarts, then remain visible as dead letters until the 30-day operational retention window expires. Delivery is at-least-once: each outbox row is leased while a sender is in flight, and if the process stops after a provider accepts a message but before the durable bookkeeping update commits, that message may be sent again after the lease expires. Per-lease fencing prevents a stale worker from changing a newer retry attempt. Disabling or removing a destination dead-letters its pending or in-flight items; newly added destinations receive only future notifications. Removing a destination also erases its encrypted URL (and overwrites the freed database space), so a leaked webhook credential is not carried into later backups; History keeps the destination name for past deliveries.
- Delivery failures are classified from the HTTP response TailState's transport actually received, never from provider error text (so a port such as `:443` or an SMTP code is not mistaken for an HTTP status). Connection failures are recorded as "failed" or "timed out". HTTP 400, 401, 403, and 404 dead-letter on the first attempt as "notification rejected by provider (HTTP *n*)", because a malformed request, revoked token, or deleted webhook cannot succeed on retry. Other statuses (for example 429 and 5xx) are retried; a provider's `Retry-After` header (seconds or HTTP date) sets the next attempt, capped at one hour.
- If every destination is disabled, or the last destination is removed, monitoring continues and notifications are reported as paused.

## Collector health alerts

- API collector failures alert after three consecutive failures and once on recovery. Transitions observed in one poll are grouped into one message per destination (one "unhealthy" and later one "recovered"), each collector listed with a bounded reason: `auth rejected`, `rate limited`, `timeout`, `upstream 5xx`, `invalid response`, `unsupported`, or `network error`. Provider error text is never included. A revoked OAuth credential therefore produces one grouped alert per poll schedule (device and inventory collectors are polled on separate schedules) instead of one alert per collector.

## Release notifications

- Starting a different TailState release queues one durable notification containing the previous and current versions, provided monitoring is configured and at least one destination is enabled; otherwise the new version is recorded silently. Development builds (version `dev`) are not tracked.

Version tracking is introduced in v0.3.0. Its first startup records the release silently because earlier releases did not persist their version; subsequent upgrades include both exact versions in the notification.

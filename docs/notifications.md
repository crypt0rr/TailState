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
- Multiple changes in one poll become one digest, fanned out into one durable outbox item per enabled destination (subject to its [routing rules](#severity-and-routing)). The outbox stores a format-neutral message that is rendered when it is sent, in the format the receiving service displays: Slack mrkdwn for `slack` and `googlechat` (single-asterisk bold, no `###` headings, `<url|label>` links, and `&`, `<`, `>` escaped so a resource name cannot mention a channel), the Teams subset of Markdown for `teams` (see [Microsoft Teams](#microsoft-teams)), Telegram HTML for `telegram` (see [Telegram](#telegram)), plain text for `smtp`, `pushover`, `matrix`, `ntfy`, `gotify`, `signal`, `bark`, `join`, `lark`, `wecom`, `pushbullet`, `ifttt`, `opsgenie`, `pagerduty`, `mqtt`, `twilio`, `xmpp`, `signalgrid`, and `hass`, and Markdown for every other service (for example `mattermost`, `discord`, `rocketchat`, `zulip`, and `generic`). Each destination can override the automatic choice under **Edit destination** in Settings (Markdown, Slack mrkdwn, plain text, Microsoft Teams, or Telegram HTML); the Settings test message uses the same format. Each digest is fitted to the receiving service's message limit (for example 4,096 bytes for Telegram, Lark, WeCom, and ntfy, 1,024 for Pushover, and 10,000 for Zulip) by dropping whole lines from the end and adding an explicit "lines omitted, see History" note. A provider that still rejects a message as too large (or with HTTP 413) dead-letters it immediately instead of retrying for 24 hours.

## Example digest

A batch of 19 changes (with attribution, 3 muted changes, and a 12-device
client rollout) as an email, ntfy, Gotify, or Pushbullet destination receives
it in plain text. The first line is the title, which these services show in
their own title field (see [Titles](#titles)):

```text
🔴 19 Tailscale changes (5 high) · prod (example.com)
2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low

🔴 ✏️ web-02 (device) changed by ci-bot [api key]
  • tags: +tag:db
🔴 ➕ kAbc123CNTRL (key) created by alice@example.com
🔴 ✏️ Tailnet policy changed by alice@example.com
  • section acls changed (3f9a1c0e → c41b7e2a)
  • section ssh added (9e8d7c6b)
🔴 ✏️ bob@example.com (user) changed by alice@example.com
  • role: member → admin
🔴 ✏️ SIEM webhook (webhook) changed
  • endpointUrl: secret changed (fingerprint aa11bb22 → 99887766)
🟠 ➕ laptop-new (device) created
🟠 ✏️ DNS configuration changed
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
  The line is left out when the batch has a single kind and a single
  severity, since the title already says it ("⚪ 3 Tailscale changes" for
  three low-severity changes). When the configuration audit log lookup
  failed, the header states "Attribution unavailable" (see
  [Change attribution](monitoring.md#change-attribution)).
- **Actors:** a known actor is named on the change's own line ("changed by
  alice@example.com"), or on a "Changed by" line below it when the line would
  be long; fleet and schema summaries name the actors of the changes they
  stand for ("· by ci-bot [api key] (3 of 12)"). Changes without a known
  actor name none; History, the API, and evidence packs still record "actor
  unknown" for them.
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
| Telegram | Bold first line (HTML mode) | Telegram HTML: names in bold, values in `<code>`, the History link as a labelled anchor (see [Telegram](#telegram)) |
| ntfy, Gotify, Pushbullet | Notification title | Plain text as above |
| Pushover | Notification title | Plain text as above, which fits in 1,024 bytes; a longer digest is shortened ("Shortened for this destination: 7 more lines omitted…" before the context line), so the high-severity changes stay |
| Discord | Embed title | Markdown in one embed (`**bob@example.com** (user) changed by alice@example.com`, `` `role`: `member` → `admin` ``) |
| Microsoft Teams | Card title | The Teams subset of Markdown, one text block per line (`**bob@example.com** (user) changed by alice@example.com`, `- role: member → admin`) |
| Slack | Header block and preview text | Slack mrkdwn in one section (`*bob@example.com*`, links as `<url\|label>`) |
| Mattermost, Rocket.Chat, Zulip, generic webhooks | `### 🔴 19 Tailscale changes (5 high) · prod (example.com)` heading line | Markdown |
| Matrix, Signal, other plain-text services | First line | Plain text as above |

The start of the same digest in Markdown (Discord, Mattermost, Rocket.Chat,
Zulip, generic webhooks; the `###` heading line only where the title is not a
separate field):

```markdown
### 🔴 19 Tailscale changes (5 high) · prod (example.com)
2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low

🔴 ✏️ **web-02** (device) changed by ci-bot \[api key\]
  - `tags`: +`tag:db`
🔴 ✏️ **bob@example.com** (user) changed by alice@example.com
  - `role`: `member` → `admin`
…
3 muted changes not shown · 5 Oct 2026 12:00 UTC · [Batch 1842 in History](https://tailstate.example/history?batch=1842)
```

And in Slack mrkdwn (the title is the header block and preview text):

```text
2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low

🔴 ✏️ *web-02* (device) changed by ci-bot [api key]
    • `tags`: +`tag:db`
…
3 muted changes not shown · 5 Oct 2026 12:00 UTC · <https://tailstate.example/history?batch=1842|Batch 1842 in History>
```

The Microsoft Teams and Telegram renderings are shown in
[Microsoft Teams](#microsoft-teams) and [Telegram](#telegram).

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
| Element of a list of identified objects (see [Change detection](monitoring.md#change-detection)) | Added or removed as `` `splitDNS.corp`: +`10.0.0.53` `` or ``−`10.0.0.53` ``; a field inside an element under its element path, for example `` `splitDNS.corp[10.0.0.53].useWithExitNode`: `false` → `true` `` |
| Absent or null value | `(not set)`; an empty string is `(empty)` |
| Object | Bounded compact JSON, with fingerprints shortened |

Fleet summaries use the same presentation, for example
"🔴 📦 6 devices: `tags` +`tag:db`".

## Device shares

A device's share invites (`device_details.deviceInvites`) get their own
🔗 lines instead of field lines. Each invite is named by its recipient: the
login name of the user who accepted it, else the invited e-mail address, else
"invite link"; flags follow in parentheses. An invite that the snapshots do
not describe is named by its ID.

| Transition | Line | Severity |
| --- | --- | --- |
| Invite created | "🔴 🔗 **nas** shared via a new invite link (multi-use, exit node allowed)", "🟠 🔗 **printer** shared via a new invite to carol@example.com" | Medium; high when multi-use, the exit node is allowed, or it is already accepted |
| `accepted` false→true | "🔴 🔗 **build-01** share accepted by bob@example.com" | High |
| `acceptedBy` set to another user | "🔴 🔗 **build-01** share now accepted by erin@example.com" | High |
| Invite removed | "🟠 🔗 **camera** share with alice@example.com removed" | Medium |
| `allowExitNode` false→true | "🔴 🔗 **gateway** share with alice@example.com: exit node allowed" | High |
| `multiUse` false→true | "… : multi-use enabled" | Medium |
| `lastEmailSentAt` | "⚪ 🔗 **kiosk** share with carol@example.com: invite e-mail resent" | Low |
| Identifiers: `tailnetId`, `sharerId`, `deviceId`, `created`, `acceptedBy.id`, and the `inviteUrl` fingerprint of an accepted share | "… : `tailnetId` changed" | Low |
| Anything else (an invited e-mail address, a flag switched off, the invite URL of a pending share, an unknown field) | The field and its values, for example "exit node no longer allowed" | Medium |

A changed invite takes the highest severity of its fields, and a device
takes the highest severity of its invites and other detail fields (posture
attributes are medium). The same bookkeeping (an e-mail resend, an identifier
change) on two or more shares with the same recipient in one batch is one
line, naming at most three devices:

```text
⚪ 🔗 2 device shares with alice@example.com (ludus, spraakwater): `tailnetId` changed
```

Recipients and device names are tenant values and are escaped like any
other (see [Escaping](#escaping)). History, the API, and evidence packs keep
the recorded invite fields and values.

## Escaping

Resource names, field values, tags, actors, share recipients, the instance label, and the
tailnet are tenant- or operator-controlled, so every renderer escapes them
for its format, and control characters and Unicode line separators always
become spaces. Every line of a notification starts with text TailState
writes itself (an icon, a label, or a list marker), so a value can never
start a heading, quote, or list; a test checks this for generated values in
every message type and format.

- **Markdown:** values in names, prose, titles, and link labels escape only
  the characters that change inline meaning: `*` and `_` (emphasis), `[` and
  `]` (links and images), `` ` `` and `<` (code, HTML, and autolinks), `\`,
  and `~` and `|` (strike-through and tables). Hyphens, dots, parentheses,
  and `#` keep their form, so `prod-monitor (example.com)`, `ci-runner auth
  key`, and e-mail addresses read and copy without backslashes. Values in
  code spans are shown verbatim, with backticks replaced by apostrophes.
- **Slack:** `&`, `<`, and `>` become entities, so a value cannot mention a
  channel or create a link, and `*`, `~`, and `` ` `` in values are replaced
  by look-alike characters.
- **Microsoft Teams:** Teams shows backslash escapes literally, so values
  use look-alike characters instead, only where they could change the
  meaning: `*` becomes `∗`, an `_` that could start or end emphasis becomes
  `＿` (one inside a word, as in `tag:prod_db`, is kept), and a `]` followed
  by `(` becomes `］`, so a value cannot form a link.
- **Telegram HTML:** every value (and every other text) is HTML-escaped
  (`&`, `<`, `>`, `"`, `'`), so a value cannot add a tag, an attribute, or an
  entity; the only tags are TailState's own `<b>`, `<i>`, `<code>`, and
  `<a href>` to the configured public URL.
- **Plain text:** values are shown as they are.

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
| `teams` | Card title (a bolder, medium text block) |
| `telegram` | Bold first line (HTML mode) |
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
receives a separate title unless the URL sets a Markdown `parsemode` (Shoutrrr
shows a title only in its HTML mode; see [Telegram](#telegram)), and a Discord URL with
`json=yes` receives the body unchanged.

## Discord

A Discord message arrives as one webhook request: the title is the embed
title, and the body follows as embeds of whole lines (at most 2,000
characters each, within Discord's 6,000-character message budget), so every
line arrives exactly once and in order. TailState also passes
`splitlines=no` unless the URL sets `splitlines`.

Shoutrrr's `splitlines=yes` mode preserves long messages, including when the
URL explicitly sets that value. TailState continues to send whole-line embeds
by default unless the URL sets `splitlines`. A URL with `json=yes` sends the
body as a raw Discord payload, unchanged.

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
`botname`/`username`, `icon`, `thread_ts`, `color` (which replaces the
severity colour, see [Priority and colour](#priority-and-colour); the blocks
are wrapped in one attachment with the colour bar), and `title` keep their
meaning. A destination whose format is overridden to another format
receives `plain_text` sections, which Slack never parses for mentions or
links.

## Microsoft Teams

Shoutrrr delivers a `teams://` message to a Power Automate workflow as an
Adaptive Card: the title is the card title (a bolder, medium text block), and
every body line becomes its own `TextBlock`. TextBlocks render only a subset
of Markdown (bold, italic, bulleted lists, and links), so Teams destinations
receive their own rendering instead of CommonMark:

- no `###` heading (the title is the card title, or a `**bold**` first line
  when the URL sets its own `title`);
- names in `**bold**`, and values as plain text instead of code spans;
- detail lines as `- ` list items;
- links as `[label](url)`, only to the configured public URL;
- values escaped for the TextBlock subset without backslashes (see
  [Escaping](#escaping)).

```text
2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low
🔴 ✏️ **web-02** (device) changed by ci-bot [api key]
- tags: +tag:db
🔴 ✏️ **Tailnet policy** changed by alice@example.com
- section acls changed (3f9a1c0e → c41b7e2a)
…
3 muted changes not shown · 5 Oct 2026 12:00 UTC · [Batch 1842 in History](https://tailstate.example/history?batch=1842)
```

The Teams rendering can also be chosen as a destination's format override,
and a Teams destination can be overridden to Markdown or plain text.

## Telegram

Telegram destinations receive Telegram's HTML subset: names and labels in
`<b>`, remarks in `<i>`, values in `<code>`, and the History and Status links
as `<a href>` anchors (only to the configured public URL). TailState sends
the message with `parsemode=HTML` and the title, which Shoutrrr puts in bold
on the first line:

```text
<b>🔴 19 Tailscale changes (5 high) · prod (example.com)</b>
2 created, 17 changed · 🔴 5 high, 🟠 2 medium, ⚪ 12 low

🔴 ✏️ <b>web-02</b> (device) changed by ci-bot [api key]
  • <code>tags</code>: +<code>tag:db</code>
…
3 muted changes not shown · 5 Oct 2026 12:00 UTC · <a href="https://tailstate.example/history?batch=1842">Batch 1842 in History</a>
```

The 4,096-byte budget is counted on the rendered HTML, tags and entities
included, after reserving the title; a longer digest is shortened at line
boundaries, so every tag stays closed. A URL that sets `parsemode` keeps it:
with `parsemode=HTML` the destination still receives the HTML rendering,
and with `Markdown`, `MarkdownV2`, or `None` it receives plain text (with
`None`, Shoutrrr escapes it in its own HTML mode). Plain text also stays
available as the destination's format override; Telegram HTML can likewise
be chosen as an override. When a URL forces `parsemode=HTML` and the
destination's override is another format, that rendering is HTML-escaped, so
it is shown as written.

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
| High | Any `policy`, `log_streaming`, `settings` (tailnet settings), `webhooks`, or `oauth_apps` change (OAuth applications grant API access, like keys); a `keys` resource created; a `users` change to `role`; a `devices` change to `tags`, `authorized` false→true, or `keyExpiryDisabled` false→true; a device share created multi-use, with the exit node allowed, or already accepted, accepted (or accepted by another user), or newly allowed to use the exit node (see [Device shares](#device-shares)) |
| Low | A `devices` change whose changed fields are all `clientVersion`, `updateAvailable`, `os`, or `distro`; a `device_details` change whose changed fields are all share bookkeeping (an invite e-mail resent, identifier changes) |
| Medium | Everything else, for example devices created or removed, route changes (`enabledRoutes`, `advertisedRoutes`), user invites, users created or removed, keys removed, DNS, contacts, posture, posture attributes, new single-use device shares, device shares removed, and `services` changes |

A changed resource takes the highest severity of its changed fields; a change
whose field list was truncated is at least medium, because the omitted fields
cannot be shown to be routine.

### Priority and colour

Services that support it deliver a notification with a priority, tags, or
colour taken from its severity: the highest severity in a digest, or a fixed
level for other notifications (high for collector failures and TailState
configuration changes, medium for expiry warnings, low for recoveries,
release notices, and the Settings test).

| Service | High | Medium | Low |
| --- | --- | --- | --- |
| ntfy (`priority`, `tags`) | 4, `rotating_light` | 3, `warning` | 2, `information_source` |
| Pushover (`priority`) | 1 | 0 | -1 |
| Gotify (`priority`) | 8 | 5 | 2 |
| Opsgenie (`priority`) | P2 | P3 | P5 |
| Discord (embed `color`) | red `0xd60510` | orange `0xff8c00` | grey `0x95a5a6` |
| Slack (attachment colour bar) | red `#d60510` | orange `#ff8c00` | grey `#95a5a6` |
| Microsoft Teams (card title `color`) | `attention` | `warning` | `default` |

A value set in the destination URL always wins, per parameter: an ntfy URL
with `?priority=5` keeps priority 5 and still receives the severity's tags.
No mapping uses a priority that needs acknowledgement (Pushover's emergency
priority 2). Services without these keys receive none, and messages queued
before this release keep the provider's default. The parameters are on the
same per-service allowlist as titles (see [Titles](#titles)).

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
  (`devices.clientVersion`, which also covers nested paths below it, and
  `device_details.deviceInvites`, which covers every invite such as
  `deviceInvites[5861427050514914].tailnetId`), every
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
- Both summaries treat the same field of different list elements as one
  field, shown with `[]` in place of the element: `backends[].weight`. An
  element added or removed is listed with its resource.

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

# Changelog

All notable changes to TailState are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/): before 1.0, a **minor** release may
change the database schema, and a **patch** release never does.

Every release lists its database **Schema** version and whether a **Rollback**
to the previous release is possible by changing the image alone. When a
release migrates the schema, older releases refuse the migrated database, so a
rollback requires restoring the backup taken before the upgrade. See
[UPGRADING.md](UPGRADING.md) for the procedure and the full schema history.

## [Unreleased]

### Fixed
- `tailstate admin reset` and the other one-shot administration commands wait up to 30 seconds for the database write lock instead of 5, so a busy service no longer makes them fail with "database is locked (SQLITE_BUSY)" (#269).

### Changed
- Renovate proposes each Go release as one "Go toolchain" PR that updates the Dockerfile builder image, the `go` directive in `go.mod`, and the Dockerfile `GO_VERSION` argument together, so the toolchain alignment check passes and security releases of Go can land without manual work (#270).

## [0.18.1] - 2026-10-09

- **Schema:** 17 (unchanged)
- **Rollback:** image-only rollback to 0.18.0 is safe.

### Changed
- Digests no longer carry an "Attributed: X of Y changes" header line. Most changes (client versions, addresses, OS updates) are reported by the device itself and never have an administrator to attribute, so the line mostly read "Attributed: 0 of N". Known actors are still named on each change line, and "Attribution unavailable" still appears when the audit log lookup failed. The counts line ("3 changed · ⚪ 3 low") is left out when the batch has a single change kind and a single severity, since the title already says it (#256).

### Security
- Builds with Go 1.27.2 and `golang.org/x/net` v0.60.0, which fix vulnerabilities in `net/http` (HTTP/2), `crypto/tls`, `html/template`, and `mime/multipart` reported by govulncheck in TailState's call paths (#254, #255).

## [0.18.0] - 2026-10-08

- **Schema:** 17 (unchanged)
- **Rollback:** image-only rollback to 0.17.1 is safe; events recorded on 0.18.0 keep their element-level field paths in History.

### Added
- Device sharing changes are described by recipient and get their own severity: digests show "🔴 🔗 **build-01** share accepted by bob@example.com", "shared via a new invite link (multi-use, exit node allowed)", "share with alice@example.com removed", "exit node allowed", or "invite e-mail resent" instead of invite JSON. A share accepted (or accepted by another user), newly allowed to use the exit node, or created multi-use, with the exit node allowed, or already accepted is high; a new single-use share, a removed share, and other invite changes are medium; an e-mail resend and identifier changes (`tailnetId`, `sharerId`, `deviceId`, `created`, `acceptedBy.id`, the invite URL fingerprint of an accepted share) are low. The same bookkeeping on two or more shares with the same recipient is one line ("2 device shares with alice@example.com (ludus, spraakwater): `tailnetId` changed"). Routing by minimum severity follows the new levels; History, the API, and evidence packs keep the recorded fields and values (#251).

### Changed
- Changes inside lists of objects are reported per element instead of as two truncated JSON blobs: a list whose objects carry a unique `id` (or `nodeId`/`address`), such as a device's `deviceInvites`, is compared element by element, so one changed invite field is one change at `deviceInvites[5861427050514914].tailnetId`, and an added or removed invite is one change at `deviceInvites[<id>]`. Reordering such a list is no longer a change. Lists of plain values, lists without such an identity, and the ordered DNS lists are compared as before. History, the API, and evidence packs show the new paths verbatim (events recorded earlier keep theirs, and old and new evidence packs verify), a field mute rule for a list (`device_details.deviceInvites`) covers its elements, and fleet and schema summaries group the same field of different elements. No re-baseline or schema change is needed (#250).

## [0.17.1] - 2026-10-07

- **Schema:** 17 (unchanged)
- **Rollback:** image-only rollback to 0.17.0 is safe.

### Fixed
- Discord destinations that explicitly set Shoutrrr's `splitlines=yes` now preserve every line in messages longer than ten lines. The pinned Shoutrrr pseudo-version includes the upstream batching fix; TailState still uses its existing whole-line delivery by default (#242).

## [0.17.0] - 2026-10-06

- **Schema:** 17 (unchanged)
- **Rollback:** image-only rollback to 0.16.0 is safe; destinations that select the new Teams or Telegram HTML format fall back to the automatic format on 0.16.0.

### Added
- Notifications carry their severity to services that support it: the highest severity of a digest (or a fixed level for health alerts, expiry warnings, configuration changes, and the Settings test) sets the ntfy priority and tags (4/3/2, `rotating_light`/`warning`/`information_source`), the Pushover priority (1/0/-1, never the acknowledgement-only 2), the Gotify priority (8/5/2), the Opsgenie priority (P2/P3/P5), and a red, orange, or grey colour for Discord embeds, Slack attachments, and Teams card titles. A value set in the destination URL wins, services without these keys receive none, and messages queued before the upgrade keep the provider's default (#234).
- Telegram notifications use Telegram's HTML formatting: names in bold, values in `<code>`, remarks in italics, and the History and Status links as labelled anchors to the public URL, sent with `parsemode=HTML` and the title. Every value is HTML-escaped, the 4,096-byte budget is counted on the rendered HTML, and a `parsemode` set in the URL is respected (Markdown modes receive plain text). Plain text stays available as a format override, and "Telegram HTML" is a new override (#235).

### Changed
- Digests use a compact layout: the title states the number of changes, leads with the highest severity's icon, and counts that severity ("🔴 19 Tailscale changes (5 high) · prod (example.com)"), so push and e-mail previews show volume and urgency; change lines read "🔴 ✏️ **web-02** (device) changed" instead of repeating kind and severity; fleet transitions on the same resources share one line ("12 devices: clientVersion 1.80.2 → 1.82.0, updateAvailable true → false"); counts use collector nouns and proper plurals; device names lose the tailnet's MagicDNS suffix (History, the API, and evidence packs keep it); times are shown as "6 Oct 2026 09:14 UTC"; and one closing context line names the muted count, time, and History link and is kept when a digest is shortened. The assessment's sample digest is about 36% smaller than in v0.15.0 with every change, actor, and field still present (#236).
- Digests name an actor only when the configuration audit log knows it, on the change's own line ("🔴 ✏️ **Tailnet policy** changed by alice@example.com via admin console", or on a "Changed by" line when the line is long), and fleet and schema summaries name the actors of the changes they stand for. There are no more "Changed by: actor unknown" lines; instead the header states "Attributed: 4 of 19 changes", or "Attribution unavailable" when the lookup failed. History, the API, and evidence packs keep their explicit "actor unknown" (#233).

### Fixed
- Microsoft Teams notifications no longer show raw `###` headings, backticks, and backslashes: Teams destinations get their own rendering for the Adaptive Card TextBlock subset (the title as the card title, `**bold**` names, plain values, `- ` list items, `[label](url)` links), with values escaped by look-alike characters instead of backslashes so they cannot form links or emphasis. The rendering is also available as the "Microsoft Teams" format override in Settings (#231).
- Markdown notifications no longer add backslashes to ordinary names and labels: values escape only the characters that change inline meaning (`*`, `_`, `[`, `]`, `` ` ``, `<`, `\`, `~`, `|`), so `prod-monitor (example.com)`, `ci-runner auth key`, and e-mail addresses read and copy as they are. Images, links, emphasis, HTML, and autolinks inside values stay inert, and a generated-value test checks that no rendered line in any format starts with tenant-controlled text (#232).

## [0.16.0] - 2026-10-06

- **Schema:** 17 (unchanged)
- **Rollback:** image-only rollback to 0.15.0 is safe.

### Changed
- Notification field lines and fleet summaries show readable values instead of raw JSON and hashes: policy sections as "section `acls` changed/added/removed" with 8-character fingerprints, redacted secrets as "secret changed (fingerprint … → …)", set, or removed, text without JSON quotes, list changes as `+added`/`−removed` elements, ordered DNS lists in their new order, and absent values as "(not set)". History, the API, and evidence packs keep the full values (#230).

### Fixed
- Slack notifications arrive as one message with a title, a non-empty preview text, and the body in Block Kit sections, instead of one attachment bar per line. The payload is sent by TailState's own bounded, redirect-rejecting HTTP client for both webhook and token URLs, with the same error classification, mention and link escaping, and size fitting as before (#229).
- Digests list changes by severity (high, then medium, then low; fleet and schema summaries included, by collector and name within a severity), so destinations with small message budgets such as Telegram and Pushover drop the least important changes first; when high-severity changes must still be dropped, the shortening note says how many (#226).
- Discord notifications longer than 10 lines no longer lose their first lines and repeat later ones: the body is sent in one webhook request as embeds of whole lines, with `splitlines=no` unless the URL sets it. A URL that forces `splitlines=yes` keeps Shoutrrr's behaviour and is flagged by the Settings test and `doctor` (`discord_splitlines_forced`) (#227).
- Notifications carry their title in the service's title field: email has a subject instead of none, Gotify and Pushbullet no longer show "Shoutrrr notification", and Discord, Slack, Teams, Telegram, ntfy, and Pushover show the title once instead of as the first body line. Only Shoutrrr parameters on a per-service allowlist derived from the pinned Shoutrrr release are passed, and a title set in the destination URL wins (#228).

## [0.15.0] - 2026-10-06

- **Schema:** 17 (migrates from 16)
- **Rollback:** restore the pre-upgrade backup; older releases refuse a schema 17 database.

### Changed
- Leases, token and session expiries, retry times, and retention compare correctly within the same second: timestamps are stored in a fixed-width UTC form (`2006-01-02T15:04:05.000000000Z`) instead of RFC 3339 with trailing zeros dropped, which sorted `…:00Z` after `…:00.1Z`. Schema 17 rewrites stored operational timestamps in bounded, resumable transactions; signed observation times keep their bytes and are compared against whole-second bounds. The web server, collector batch application, schema migrations, monitor engine, and Tailscale client are split into smaller files and named phases without other behaviour changes (#197).

### Documentation
- The README is split into focused pages under `docs/` (monitoring, notifications, history and evidence, operations, security, metrics) with a concise quick start; per-schema migration details moved to `UPGRADING.md`. New example Prometheus alert rules in `docs/prometheus/alerts.yml` (dead letters, stuck or paused delivery, collector failures and degraded readiness, storage pressure and an unenforced database limit, dead webhook triggers, failing attribution lookups) are validated with `promtool` in CI. Shoutrrr links point to the `nicholas-fedor/shoutrrr` fork's documentation, and `.env.example` lists every Compose variable, including the commented storage limits, with a pinned image version (#194).

## [0.14.0] - 2026-10-06

- **Schema:** 16 (migrates from 14 through 15)
- **Rollback:** restore the pre-upgrade backup; older releases refuse a schema 16 database. New evidence exports use format v5, which older releases cannot verify (v3 and v4 packs still verify).

### Added
- Change attribution from the Tailscale configuration audit log (`logs:configuration:read`, included in `all:read`): History, digests in every message format, `/api/v1/history`, and evidence packs (format version 5, signed in the ledger payload) name who made each change, or "actor unknown" without failing the batch. Only the actor, action, target, and time are stored, never the audit log's old/new values. A `403`/`404` degrades silently and shows as unsupported on the status page; lookups have a 10-second budget and are counted in `tailstate_attribution_lookups_total`. Schema 16 adds `events.attribution` and `event_batches.attribution_status`; version 3 and 4 packs still verify (#173).

### Changed
- `oauth_apps` changes (created, removed, or changed) are classified as high severity, like keys, because OAuth applications grant API access. Events recorded earlier keep their stored severity (#174).

### Fixed
- Each destination receives notifications in creation order after an outage, and a failing or hanging destination delays the others by at most one send timeout per delivery pass (#159).
- Large histories export as a chain of signed evidence packs instead of failing: a pack that reaches the read, event, ledger-link, or size budget carries the batches that fit with `truncated` and `next_cursor`, and the History page offers **Download next part** (#155).

### Security
- Administrator passwords follow a length-first policy with a common-password blocklist; Settings can change the password, list sessions, and sign out other sessions; sessions end after 60 minutes idle (the status auto-refresh does not count); HSTS on HTTPS requests only; `__Host-` session cookies when cookies are secure. Schema 15 adds `sessions.last_seen_at` (#189).
- Administrative audit trail (`admin_audit`, schema 15, 365-day retention) for sign-ins, password and session changes, settings (including OAuth scopes and expiry warnings), destinations, mute rules, Reconcile now, and Retry dead letters, with a "TailState configuration changed" notice to previously enabled destinations for high-risk changes (#177).
- Scoped, read-only API tokens (`status:read`, `history:read`, `evidence:read`; hashed in schema 15, shown once after Post/Redirect/Get) and `GET /api/v1/status`, `/api/v1/history` (NDJSON, History filters including dates, bidirectional cursors), and `/api/v1/evidence` (#196).

### Documentation
- `/metrics` documentation matches the code: Compose and `docker run -p` deployments set the bearer token in `.env` and scrape with a header file, the HTTPS override scrapes through the proxy, and token-less scraping is limited to local loopback (#160).

## [0.13.0] - 2026-10-06

- **Schema:** 14 (migrates from 13)
- **Rollback:** restore the pre-upgrade backup; older releases refuse a schema 14 database. New evidence exports use format v4, which older releases cannot verify (v3 packs still verify).

### Added
- Notifications name the instance and tailnet, state when the batch was observed, link to History and Status when `TAILSTATE_PUBLIC_URL` is set, and group collector health changes per poll with bounded reasons (#176).
- Built-in change severity and per-destination routing by severity, collector, and change kind (#174).
- Mute rules, fleet-wide summaries, and upstream schema-change detection; posture expiry timestamps are ignored (#175).
- Per-service rendering: Markdown, Slack mrkdwn, or plain text, chosen per destination (#185).
- Proactive warnings for expiring device node keys and auth keys, and an "Expiring soon" status card (#183).
- `services` and `oauth_apps` collectors, DNS read from `/dns/configuration`, and configurable OAuth scopes (#184).
- Status/Settings/History usability: correct labels and time zones, Reconcile now, retry dead letters, webhook state, readable storage, date filters, and bidirectional paging (#186).
- `help` at every level, documented exit codes, `admin backup` (online) and `admin compact` (offline) commands (#190).
- Used-bytes storage accounting, a WAL size cap, and a read-only connection pool for health, metrics, status, and History (#191).

### Changed
- One shared, responsive, accessible layout with a light theme (#187).
- Destination actions use Post/Redirect/Get; expired sessions return to the original page after login; removing a destination requires confirmation; a CSRF failure now returns `403` without ending the session (#188).
- The healthcheck follows `TAILSTATE_LISTEN_ADDR`; the listener is bound before polling starts (#190).

## [0.12.0] - 2026-10-06

- **Schema:** 13 (migrates from 12)
- **Rollback:** restore the pre-upgrade backup; older releases refuse a schema 13 database, and new encrypted values use a bound envelope that older releases cannot read.

### Security
- Credential-form challenges are stateless until submitted; GET floods can no longer lock out login, setup, or reset (#144).
- Throttling keys IPv6 by /64, adds a global failure budget, and returns `429` with `Retry-After` (#145).
- Encrypted values are bound to their storage location; database and WAL files are created private; `/data` is `0700` in the image (#166).
- Deleted notification destinations no longer keep decryptable credentials (#153).
- `evidence public-key` and `admin reset` never create or migrate a database (#154).

### Fixed
- Persisted collector deadlines survive restarts and settings saves (#146).
- `device_details` reports every missing device and refreshes stalest-first (#147).
- Failed or partial collectors back off; overlapping webhook triggers poll once (#148).
- Transient 502/503/504 and token-endpoint failures are retried; cursor pagination keeps its query (#149).
- Shared/external users are monitored (#150); one device change is reported once (#151).
- Unchanged polls no longer rewrite snapshots (#152).
- Settings are validated locally and the Tailscale test stays within the write deadline (#156).
- Notification code spans render without backslashes (#157); delivery failures are classified from the real HTTP response (#158).
- Identity changes dead-letter in-flight notifications (#161); single-object endpoints must return JSON objects (#162).
- `/metrics` is atomic with HELP/TYPE everywhere; consistent notification state; container `doctor` reports `ok` (#163).
- Unknown paths return `404` (#164); retention-cleanup errors back off (#165).
- Authentic out-of-bounds webhooks trigger a full reconciliation (#167).
- Matrix password URLs log in once per delivery through TailState's transport (#170).
- The evidence audit reads its head from one snapshot (#171); retention cleanup uses index searches only (#172).

### Added
- Sigstore-signed build provenance for release images (#178).
- Standalone binaries with checksums, SBOM, provenance, and a systemd unit (#195).

## [0.11.16] - 2026-10-05

- **Schema:** 12 (unchanged)
- **Rollback:** image-only rollback to 0.11.15 is safe.

### Fixed
- The HTTPS Compose override gives TailState outbound network access (#140).
- The SQLite storage budget stays enforced after interrupted statements (#141).
- Removing or adding a log stream is reported as drift (#142).
- Digests are fitted to each notification service's message limit (#143).

### Security
- Backup/restore helpers mount only the data volume and require checksums (#169).
- Compose and Caddy runtime hardening (#192); repository security settings, `SECURITY.md`, and templates (#179).

### Changed
- Images are cross-compiled natively; drifting base-image labels removed (#168, #181).
- CI lint guards, weekly vulnerability scan, and release workflow hardening (#180, #193).

## Earlier releases

Releases before 0.11.16 are described in their
[GitHub release notes](https://github.com/crypt0rr/TailState/releases); their
schema versions are listed in [UPGRADING.md](UPGRADING.md#schema-history).

[Unreleased]: https://github.com/crypt0rr/TailState/compare/v0.18.1...HEAD
[0.18.1]: https://github.com/crypt0rr/TailState/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/crypt0rr/TailState/compare/v0.17.1...v0.18.0
[0.17.1]: https://github.com/crypt0rr/TailState/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/crypt0rr/TailState/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/crypt0rr/TailState/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/crypt0rr/TailState/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/crypt0rr/TailState/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/crypt0rr/TailState/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/crypt0rr/TailState/compare/v0.11.16...v0.12.0
[0.11.16]: https://github.com/crypt0rr/TailState/compare/v0.11.15...v0.11.16

# Upgrading TailState

TailState migrates its SQLite database automatically on the first start of a
release that raises the schema version. Migrations are one-way: an older
release refuses a database whose schema is newer than it supports. Plan every
upgrade so you can return to the exact previous state.

## Before upgrading

1. Read the [CHANGELOG](CHANGELOG.md) entries between your version and the
   target. Each entry states its **Schema** version and **Rollback** rule.
2. Create a verified backup with the matching master key:

   ```console
   ./scripts/backup.sh ./backups
   ```

   Keep `secrets/tailstate_master_key` with the backup; the archive is useless
   without it.
3. Pin the target version (`TAILSTATE_IMAGE=ghcr.io/crypt0rr/tailstate:<version>`
   in `.env`) instead of following `latest`, and optionally verify it:

   ```console
   gh attestation verify oci://ghcr.io/crypt0rr/tailstate:<version> --owner crypt0rr
   ```

## Upgrading

```console
docker compose pull
docker compose up -d
docker compose logs tailstate
curl -fsS http://127.0.0.1:8080/readyz
```

Startup verifies the master key before any schema change, so a wrong key
exits without touching the database. `tailstate doctor` reports a pending
migration without performing it.

## Rolling back

- **Same schema** (the CHANGELOG says "image-only rollback is safe"): set
  `TAILSTATE_IMAGE` to the previous version or digest and run
  `docker compose up -d`.
- **Schema changed**: stop TailState, restore the backup taken before the
  upgrade, then start the previous image:

  ```console
  docker compose stop tailstate
  ./scripts/restore.sh ./backups/tailstate-data-<timestamp>.tar.gz --yes
  ```

  Changes recorded by the newer release after the upgrade are lost; export
  evidence packs first if you need them.

## Schema history

| Schema | First release | Notes |
| --- | --- | --- |
| 1 | 0.4.0 | Initial versioned schema |
| 2 | 0.5.0 | |
| 3 | 0.6.0 | |
| 4 | 0.7.0 | Encrypted webhook secret, webhook trigger ledger |
| 5 | 0.8.0 | Webhook trigger leases and batch links |
| 6 | 0.9.0 | Encrypted Ed25519 evidence key and hash-linked ledger |
| 7 | 0.9.7 | Expiring, revocable setup and reset tokens |
| 9 | 0.9.8 | Poll duration, partial results, partial error counts (8–9) |
| 11 | 0.10.0 | Webhook (10) and outbox (11) lease fencing |
| 12 | 0.11.5 | Snapshot/event byte and truncation metadata, bounded history |
| 13 | 0.12.0 | Deleted-destination scrub, retention index changes |
| 14 | 0.13.0 | Destination routing, mute rules, rendering format, format-neutral outbox payloads, event severity |
| 15 | 0.14.0 | Session activity, administrative audit trail, API tokens |
| 16 | 0.14.0 | Change attribution from the configuration audit log |

[Migration details](#migration-details) describes each migration.

## Migration details

### Before migrating

Before upgrading an existing data volume, stop TailState and create a verified
backup with the matching master key. Startup verifies that key before applying
schema changes; a wrong key therefore exits without mutating the database. If a
migration fails, leave the service stopped, keep the original database and key,
and restore the pre-upgrade archive before retrying or rolling back the image.
TailState also refuses to bootstrap a non-empty database that has no valid
`schema_version` marker (including an empty, duplicated, or unsupported
marker); restore a verified backup or use a release that ships the required
migration instead of allowing a malformed file to be treated as new.

### Schema 2 (0.5.0): Shoutrrr destinations

On the first startup after the upgrade to 0.5.0, an existing encrypted Mattermost webhook is converted automatically to a native `mattermost://` destination when it uses the standard `/hooks/<token>` path. Other paths are preserved as a `generic://` JSON webhook with the existing TailState username and satellite icon. Existing outbox items are assigned to the migrated destination; if no legacy destination is configured, orphaned pending or in-flight rows are retained as dead letters with a safe explanation instead of remaining undeliverable forever. The legacy encrypted column is retained but no longer used for new configuration.

### Schemas 4 to 12 (0.7.0 to 0.11.5)

The schema v4 migration adds encrypted storage for the optional Tailscale
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

### Schema 13 (0.12.0)

Schema v13 erases the encrypted service URL of notification destinations that
were removed before this release; removed destinations keep their name for
History. It also drops two redundant indexes (`events_observed_at` and
`evidence_ledger_batch_id`, which duplicate `events_retention` and the ledger's
unique batch constraint) and adds `outbox_dead_retention` and
`auth_tokens_kind`, so every retention statement reaches its rows through an
index search and a pass with nothing to delete stays cheap on large databases.

### Schema 14 (0.13.0)

Schema v14 adds per-destination routing rules and message format overrides,
a built-in severity and a `muted` flag on every history event, the mute rule
table, and a payload format on outbox rows. Notifications queued before the
upgrade are marked as pre-rendered Markdown and are delivered exactly as they
were stored; only notifications queued after the upgrade are rendered per
service. Existing
destinations default to receiving all changes and no existing event is muted,
so the upgrade does not change delivery. Existing events are classified in
bounded, resumable 64-row transactions during the migration; severity is
derived data and is not part of the signed ledger payload, and the ledger
payload records `muted` only when it is set, so the existing chain and every
previously exported pack still verify. New exports use evidence format version
4, which adds per-event `severity` and `muted`; `tailstate evidence verify`
accepts both version 3 and version 4 packs.

### Schema 15

Schema v15 adds administrative security state. Sessions gain a last-activity
time for the 60-minute idle timeout; existing sessions are backfilled with
their sign-in time, so a session that has been idle for longer than the
timeout must sign in again after the upgrade, and every other session keeps
working. It also creates the `admin_audit` table and its
retention index, and the `api_tokens` table for hashed read-only API tokens;
the audit trail and token list start empty at the upgrade. The migration
runs in one transaction and changes no existing setting, destination,
history, or evidence row.

### Schema 16

Schema v16 adds [change attribution](docs/monitoring.md#change-attribution): an `attribution`
column on events (the bounded "changed by" record) and an
`attribution_status` column on change batches. Both default to empty, so the
migration rewrites no row, in one transaction: events recorded before the
upgrade show no "Changed by", and their signed ledger payloads keep their
exact bytes, so the existing chain still audits. A ledger payload records
`attribution` only for an attributed event. New exports use evidence format
version 5, which adds the batch `attribution_status` and the per-event
`attribution` (bound to the signed ledger payload); `tailstate evidence
verify` accepts versions 3, 4, and 5, and refuses a version 3 or 4 pack that
carries attribution, so a newer pack cannot be relabelled as an older one.
Older releases cannot verify version 5 packs. Rolling back requires restoring
the pre-upgrade backup, as for every schema change.

### Schema 17

Schema v17 stores every timestamp in a fixed-width UTC form with nine
fractional digits (`2006-01-02T15:04:05.000000000Z`). Earlier releases dropped
trailing fractional zeros, so a time on a whole second (`…:00Z`) sorted after
a later time in the same second (`…:00.1Z`) and a lease, token expiry, or
retry time could be compared the wrong way round for up to a second. The
migration rewrites the stored times of sessions, setup and reset tokens, API
tokens, the administrative audit trail, the notification outbox, webhook
triggers, and the collector schedule in bounded, resumable 64-row
transactions; each value keeps its instant, and empty or unparseable values
are left unchanged. An interrupted upgrade simply runs the rewrite again on the
next start. Observation times of events, change batches, and the evidence
ledger are part of signed ledger payloads and are deliberately not rewritten:
the existing chain still audits, and History filters and retention compare
them against whole-second bounds, which order both forms correctly (an event
observed within the retention cutoff's second is removed on the next pass).
Rolling back requires restoring the pre-upgrade backup, as for every schema
change.

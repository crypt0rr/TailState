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

The README section "Migration from older releases" describes each migration
in detail.

# History and evidence

TailState records every change batch in an authenticated History ledger and
can export it as signed, offline-verifiable evidence. What is detected is
described in [What TailState monitors](monitoring.md).

## History page

The authenticated **History** page keeps a 30-day, searchable ledger of semantic inventory changes. Each poll is grouped into a batch with the affected collector, resource, previous/current normalized snapshots, field-level differences, and the delivery state for every destination. Use it to investigate a notification without exposing credentials or volatile API fields. The page shows the fingerprint of the Ed25519 key used to sign evidence exports. History can be narrowed to a UTC date range (both dates inclusive) and paged in both directions with **Load newer changes** and **Load older changes**; the range carries over to the evidence-pack download, whose signed `filter` then records `from` and `until` (exclusive). Packs without a date range keep their previous shape; a pack that uses one needs a verifier from this release or later.

Every change batch is also recorded in the authenticated History page with field-level diffs and redacted normalized before/after snapshots. Field paths use dots for nested objects and `[<id>]` for identified list elements, for example `deviceInvites[5861427050514914].tailnetId` (see [Change detection](monitoring.md#change-detection)); History, the API, and evidence packs show them verbatim, and the signed ledger covers them like any other event field. Filters support collector, change type, severity, resource name or ID, and a single batch (`/history?batch=<id>`, the target of notification links); history is retained for 30 days. Normalized snapshots are capped at 1 MiB and each event before/after value at 512 KiB. Larger values retain their SHA-256, original byte count, configured limit, and a bounded truncation marker instead of the provider body; the authenticated UI calls this out explicitly. A normal history page reads at most 2 MiB of stored event data and displays a truncation notice with a cursor when that budget is reached. The hard 4 MiB raw-write ceiling prevents an unusually large normalized value from entering SQLite unbounded; the small marker remains queryable for audit.

## Evidence packs

The History page can download a filtered, redacted JSON evidence pack for incident reports and offline review. Packs (format version 5) include normalized snapshots, field diffs, each event's severity and `muted` flag, each batch's `attribution_status` and each attributed event's `attribution` record (see [Change attribution](monitoring.md#change-attribution)), destination delivery outcomes, a SHA-256 content hash, and an Ed25519 signature over a hash-linked event ledger; a pack holds at most 100 batches (fewer with the export's `limit` query parameter), 2,000 events, and 5 MiB. A changed export fails verification.

A history larger than one pack is exported as a chain of parts rather than refused. Each part holds the newest batches that fit, newest first; when a budget is reached the pack sets `"truncated": true` and `next_cursor` to its oldest batch ID, its file name ends in `-next-<cursor>`, and the response carries an `X-TailState-Evidence-Next-Cursor` header and a `Link: <...>; rel="next"` URL with the same filters. Enter that cursor in **Download next part** on the History page (the active collector, type, severity, resource, batch, and date filters carry over) to fetch the next part. Following the chain until a pack has `"truncated": false` covers every matching batch exactly once, and every part verifies on its own with `tailstate evidence verify`. Only a single batch that alone exceeds a budget is refused (`413`); narrow the filters to export it.

## Verifying an evidence pack

Verify an export offline with `tailstate evidence verify --file tailstate-drift-evidence.json`. Verification checks the content hash, embedded public key fingerprint, signature, and included ledger links; packs and public-key files are bounded before decoding (5 MiB and 4 KiB respectively). For independent trust, print the instance public key with `tailstate evidence public-key`, save it as a base64 file, and pass it with `--public-key public.key`. `evidence public-key` opens the database read-only and fails if the database, the current schema, or the stored signing key is missing; it never creates a database or a new key.

## Auditing the evidence ledger

Audit the persisted evidence ledger explicitly with `tailstate evidence audit`. The command opens the existing database read-only, verifies sequence continuity, predecessor hashes, signatures, key IDs, stored head, and canonical payload digests, then resumes through bounded pages until the chain is complete. Pass `--public-key public.key` to anchor verification to an independently trusted Ed25519 key; entries whose event snapshots have aged out are reported as cryptographically verified but payload-unverifiable. The audit never creates a database, runs migrations, generates keys, or changes metadata, and can run while TailState is serving from SQLite WAL mode.

## Ledger checkpoints

The ledger lives in the database it protects, so a database-only audit cannot tell a truncated tail, or a tail whose stored head was rewritten to match, from a complete one. A ledger checkpoint keeps evidence of the head outside the database. Choose one enabled notification destination, and TailState sends a signed statement of the newest ledger entry to it:

```console
tailstate evidence checkpoint                 # show the choice, the last checkpoint, and destination IDs
tailstate evidence checkpoint -destination-id 3
tailstate evidence checkpoint -clear          # turn checkpoints off
```

The command changes only the checkpoint settings, so it works while TailState runs. Like `admin reset`, a change takes the maintenance lock shared and refuses with an error while `admin compact` is replacing the database, so a change is never lost to the file replacement. Destinations are chosen by ID because their names need not be unique; the status output lists the IDs and never prints service URLs.

While the ledger advances, TailState checks every 15 minutes and sends at most one checkpoint every six hours. A checkpoint is sent only when the ledger has moved past the last one, so an idle ledger sends nothing and the same sequence is never sent twice. It is a system notification for the chosen destination only: routing and mute rules do not apply, and delivery is at-least-once like every other notification. The message shows the sequence, the ledger head (the lowercase hexadecimal SHA-256 entry hash), the recorded time in whole seconds (UTC), the signing key ID, and the Ed25519 signature. The signature covers this text, one value per line with no trailing newline:

```text
tailstate-ledger-checkpoint-v1
<sequence>
<head>
<recorded time, RFC 3339, UTC, whole seconds>
<signing key ID>
```

Verify the signature with the public key from `tailstate evidence public-key`, using any Ed25519 implementation. Before a checkpoint is sent, the ledger must still hold the entry that was last checkpointed at its sequence. A missing or changed entry is logged as an error and nothing is sent.

Audit the ledger against a checkpoint kept outside the database by passing the sequence and head from the notification:

```console
tailstate evidence audit -min-sequence 42 -expect-head <head-from-notification>
```

The audit verifies the whole chain first, then exits with code 3 if the ledger ends before sequence 42 or the entry at sequence 42 has a different hash. `-expect-head` requires `-min-sequence`; `-min-sequence` alone checks only the length. A passing audit reports `checkpoint_sequence=42 checkpoint_head=matched`.

A checkpoint proves the head as it was when the checkpoint was sent. It cannot prove entries that were never checkpointed, and an attacker who holds both the master key and the signing key can still issue new checkpoints. It does make a truncated or rewritten tail detectable for anyone who kept an earlier checkpoint. If the chosen destination is disabled or removed, nothing is sent and the service logs a warning until you choose another destination.

The setting and the last checkpoint are stored in the existing `meta` table, so the feature adds no schema change. Releases before this feature ignore the setting and reject the `-min-sequence` and `-expect-head` flags; checkpoints that were already delivered remain valid and can still be checked against the public key.

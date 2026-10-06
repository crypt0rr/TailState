# History and evidence

TailState records every change batch in an authenticated History ledger and
can export it as signed, offline-verifiable evidence. What is detected is
described in [What TailState monitors](monitoring.md).

## History page

The authenticated **History** page keeps a 30-day, searchable ledger of semantic inventory changes. Each poll is grouped into a batch with the affected collector, resource, previous/current normalized snapshots, field-level differences, and the delivery state for every destination. Use it to investigate a notification without exposing credentials or volatile API fields. The page shows the fingerprint of the Ed25519 key used to sign evidence exports. History can be narrowed to a UTC date range (both dates inclusive) and paged in both directions with **Load newer changes** and **Load older changes**; the range carries over to the evidence-pack download, whose signed `filter` then records `from` and `until` (exclusive). Packs without a date range keep their previous shape; a pack that uses one needs a verifier from this release or later.

Every change batch is also recorded in the authenticated History page with field-level diffs and redacted normalized before/after snapshots. Filters support collector, change type, severity, resource name or ID, and a single batch (`/history?batch=<id>`, the target of notification links); history is retained for 30 days. Normalized snapshots are capped at 1 MiB and each event before/after value at 512 KiB. Larger values retain their SHA-256, original byte count, configured limit, and a bounded truncation marker instead of the provider body; the authenticated UI calls this out explicitly. A normal history page reads at most 2 MiB of stored event data and displays a truncation notice with a cursor when that budget is reached. The hard 4 MiB raw-write ceiling prevents an unusually large normalized value from entering SQLite unbounded; the small marker remains queryable for audit.

## Evidence packs

The History page can download a filtered, redacted JSON evidence pack for incident reports and offline review. Packs (format version 5) include normalized snapshots, field diffs, each event's severity and `muted` flag, each batch's `attribution_status` and each attributed event's `attribution` record (see [Change attribution](monitoring.md#change-attribution)), destination delivery outcomes, a SHA-256 content hash, and an Ed25519 signature over a hash-linked event ledger; a pack holds at most 100 batches (fewer with the export's `limit` query parameter), 2,000 events, and 5 MiB. A changed export fails verification.

A history larger than one pack is exported as a chain of parts rather than refused. Each part holds the newest batches that fit, newest first; when a budget is reached the pack sets `"truncated": true` and `next_cursor` to its oldest batch ID, its file name ends in `-next-<cursor>`, and the response carries an `X-TailState-Evidence-Next-Cursor` header and a `Link: <...>; rel="next"` URL with the same filters. Enter that cursor in **Download next part** on the History page (the active collector, type, severity, resource, batch, and date filters carry over) to fetch the next part. Following the chain until a pack has `"truncated": false` covers every matching batch exactly once, and every part verifies on its own with `tailstate evidence verify`. Only a single batch that alone exceeds a budget is refused (`413`); narrow the filters to export it.

## Verifying an evidence pack

Verify an export offline with `tailstate evidence verify --file tailstate-drift-evidence.json`. Verification checks the content hash, embedded public key fingerprint, signature, and included ledger links; packs and public-key files are bounded before decoding (5 MiB and 4 KiB respectively). For independent trust, print the instance public key with `tailstate evidence public-key`, save it as a base64 file, and pass it with `--public-key public.key`. `evidence public-key` opens the database read-only and fails if the database, the current schema, or the stored signing key is missing; it never creates a database or a new key.

## Auditing the evidence ledger

Audit the persisted evidence ledger explicitly with `tailstate evidence audit`. The command opens the existing database read-only, verifies sequence continuity, predecessor hashes, signatures, key IDs, stored head, and canonical payload digests, then resumes through bounded pages until the chain is complete. Pass `--public-key public.key` to anchor verification to an independently trusted Ed25519 key; entries whose event snapshots have aged out are reported as cryptographically verified but payload-unverifiable. The audit never creates a database, runs migrations, generates keys, or changes metadata, and can run while TailState is serving from SQLite WAL mode.

# Code Review & Enhancement Backlog

## Review Metadata

- **Review date:** 2026-08-30
- **Reviewed ref:** `main` at `ae1070a9e043`
- **Review mode:** Holistic baseline review of the current repository; the worktree had no staged, unstaged, or branch diff
- **Verdict:** **NEEDS ACTION**
- **Priority counts:** P0: 0, P1: 2, P2: 2, P3: 1
- **Review inputs:** Go application and tests, SQLite schema/storage paths, monitor lifecycle, web trust boundaries, diagnostics, evidence ledger, documentation, Docker/Compose definitions, and CI/release workflows
- **Excluded:** Generated or third-party code, live provider behavior, production data, external endpoints, and destructive migration/failure injection against a real deployment
- **Previous report disposition:** The prior report's findings were confirmed resolved on the reviewed baseline. This file replaces that report and contains only current findings.

## Executive Summary

TailState is in strong condition: the full race-enabled test suite passes at the enforced 90.0% repository coverage baseline, `go vet`, `staticcheck`, and the invariant suite are clean, and the security-sensitive paths have extensive regression coverage. No P0 release blocker was found.

Two operational reliability gaps merit near-term work. First, the `doctor` command opens the database through the normal mutating bootstrap path. A diagnostic run can create a database, execute schema migrations, generate cryptographic state, backfill the evidence ledger, and persist storage settings. It also ignores the currently configured storage profile, so its report can disagree with what `serve` will apply. Second, retention cleanup performs unbounded deletes through TailState's only SQLite connection, including immediately at startup. A deployment with a large expired history can therefore make cleanup an availability event.

The remaining items harden security and auditability: fail closed for tokenless metrics behind a loopback proxy, provide an explicit on-database evidence-ledger audit, and report the physical SQLite/WAL footprint separately from the logical page budget.

## Px Summary

| ID | Priority | Type | Title | Area | Effort | Confidence | Status |
|---|---|---|---|---|---|---|---|
| R-007 | P1 | Risk | `doctor` mutates the database and reports a different storage profile from `serve` | Diagnostics / storage | M | High | Open |
| R-008 | P1 | Risk | Retention cleanup performs unbounded work on the only SQLite connection | Storage / monitor | M | High | Open |
| R-009 | P2 | Risk | Tokenless metrics authorization can fail open through a loopback proxy | Web security | S | High | Open |
| E-005 | P2 | Enhancement | Add an explicit, read-only audit of the persisted evidence chain | Evidence / diagnostics | M | High | Open |
| E-006 | P3 | Enhancement | Expose physical SQLite, WAL, and shared-memory disk usage | Observability / storage | S | Medium | Open |

## Detailed Findings

### R-007 — `doctor` mutates the database and reports a different storage profile from `serve`

- **Priority:** P1
- **Type:** Risk
- **Location:** `cmd/tailstate/main.go:184-235`; `internal/store/store.go:207-331`
- **Evidence:** `doctor` loads the operator configuration but calls `store.Open(config.DatabasePath(), box)` without the configured limits. `Open` delegates to the normal `OpenWithLimits` bootstrap path with an empty profile. That path creates the data directory, applies DDL and migrations, creates the master-key check, loads or creates the evidence signing key, backfills the ledger, persists storage limits, and changes database permissions. A local reproduction against an empty temporary data directory both created `tailstate.db` and reported the default 512 MiB database limit even though `TAILSTATE_DATABASE_LIMIT_BYTES=104857600` (100 MiB) was supplied.
- **Impact:** An operator invoking a command described as diagnostic can modify the evidence and recovery target they are trying to inspect, or initiate upgrade migrations before making the backup requested by the migration warning. The resulting report can also recommend action from limits that differ from the service's effective configuration. This weakens incident response and can make a preflight check give false assurance.
- **Recommendation:** Introduce a dedicated read-only inspection path for diagnostics. Open an existing database in SQLite read-only mode, validate the schema version and key compatibility without DDL or backfill, and report configured and persisted storage profiles separately. A missing database should produce an installation-state finding rather than create one. Keep schema upgrades, key creation, ledger backfill, and settings persistence exclusive to `serve` or an explicit maintenance command.
- **Acceptance criteria:**
  - Running `tailstate doctor` does not create a data directory or database when neither exists.
  - On an existing database, schema version, table contents, metadata, evidence-ledger head, file size, and modification timestamp are unchanged after the command.
  - An older supported schema is reported as migration-pending without being migrated.
  - The report distinguishes configured limits from persisted/effective limits and identifies a mismatch.
  - Tests cover a missing database, current schema, old schema, wrong key, configured/persisted limit mismatch, and inspection while the service owns the WAL database.
- **Effort:** M
- **Confidence:** High
- **Tradeoffs / dependencies:** A read-only path cannot reuse `Store.Open` safely and must tolerate tables or columns absent from older schemas. Decide whether `doctor` should require the master key for all checks or degrade gracefully to structural checks when key material is unavailable.

### R-008 — Retention cleanup performs unbounded work on the only SQLite connection

- **Priority:** P1
- **Type:** Risk
- **Location:** `internal/store/status.go:324-373`; `internal/store/store.go:222-227`; `internal/monitor/engine.go:908-923`
- **Evidence:** `Cleanup` issues whole-range `DELETE` and `UPDATE` statements for sessions, tokens, events, batches, trigger correlations, webhook triggers, and outbox rows. None has a row, transaction, or elapsed-time budget. The database pool is deliberately limited to one connection. The monitor invokes cleanup immediately at startup and then hourly, so accumulated expired data is processed before the first scheduled interval. Existing cleanup tests verify lifecycle correctness but do not assert bounded work or concurrent responsiveness on a large fixture.
- **Impact:** On a long-lived or previously stalled deployment, deleting a substantial expired history can monopolize the sole database connection, delay polling and notification delivery, and make web or readiness requests time out. A large write transaction can also temporarily expand the WAL and increase disk pressure precisely while the service is recovering.
- **Recommendation:** Convert retention into bounded, resumable batches using indexed keyset selection. Limit rows and elapsed time per transaction, commit between batches, observe cancellation, and schedule an early continuation while backlog remains. Emit per-table rows removed, elapsed time, remaining-work indication, and failures. Preserve the current rule that evidence-ledger rows outlive retained event snapshots.
- **Acceptance criteria:**
  - Every cleanup transaction has a documented maximum row count and stops within a tested elapsed-time budget under the representative maximum database size.
  - Cleanup resumes from partial progress without skipping eligible rows or deleting active leases.
  - Status reads, outbox claims, and collector persistence remain responsive while a large expired fixture is being drained.
  - Cancellation stops the current pass promptly, and a later pass completes the same retention result.
  - Metrics or structured logs expose rows deleted per table, duration, failures, and whether backlog remains.
  - Regression tests continue proving that the evidence ledger survives history cleanup.
- **Effort:** M
- **Confidence:** High
- **Tradeoffs / dependencies:** Smaller batches increase total SQL overhead and may leave expired data present for several passes. The batch size and latency budget should be derived from a representative slow-volume benchmark rather than chosen only from developer hardware.

### R-009 — Tokenless metrics authorization can fail open through a loopback proxy

- **Priority:** P2
- **Type:** Risk
- **Location:** `internal/web/server.go:994-1010`; `internal/web/server.go:1131-1151`; `internal/web/server_test.go:287-306`
- **Evidence:** When no metrics token is configured, authorization trusts `clientIP(r).IsLoopback()`. If a reverse proxy connects from loopback and is not included in `TrustedProxies`, forwarded client information is deliberately ignored and the proxy peer is treated as the client. If it is trusted but supplies no valid `X-Forwarded-For`, `clientIP` also falls back to the loopback peer. The current test covers only direct loopback and direct remote requests, not a public request relayed by a loopback proxy.
- **Impact:** A deployment that publishes all routes through a local reverse proxy can unintentionally expose operational and inventory metrics without a token when proxy trust or forwarding headers are incomplete. This is configuration-dependent and does not expose stored secrets, but it violates the intended remote-requests-require-authentication boundary.
- **Recommendation:** Treat tokenless metrics as direct-loopback-only. If the peer is a configured trusted proxy or forwarding headers are present, require a metrics token; document that all proxied metrics access requires one. Do not infer local user identity from a proxy's loopback socket.
- **Acceptance criteria:**
  - Direct requests from loopback continue to work without a token.
  - A loopback proxy request with a remote `X-Forwarded-For` value is rejected without a token.
  - A loopback proxy request with missing, malformed, or entirely ignored forwarding headers is rejected without a token.
  - Valid bearer-token requests continue to work through direct and proxied paths with constant-time token comparison.
  - Deployment documentation states that a token is mandatory whenever `/metrics` is reachable through a proxy.
- **Effort:** S
- **Confidence:** High
- **Tradeoffs / dependencies:** Existing users scraping through a local proxy without a token will need to configure one. That compatibility break should be called out in release notes.

### E-005 — Add an explicit, read-only audit of the persisted evidence chain

- **Priority:** P2
- **Type:** Enhancement
- **Location:** `internal/store/store.go:314-323`; `internal/store/signing.go:407-432`; `internal/store/signing.go:496-527`; `internal/store/evidence.go:228-311`
- **Evidence:** Startup loads or creates the signing key and backfills authorized historical rows, but it does not verify the existing ledger's sequence, predecessor hashes, payload digests, signatures, or stored head. Appending reads the latest hash and builds the next entry on it. Full link and signature validation exists for an exported evidence pack, so corruption is detected only after an operator exports and explicitly verifies the affected range.
- **Impact:** Database corruption or tampering can remain operationally silent while new evidence is appended. The cryptographic proof remains capable of exposing the break later, but delayed detection makes it harder to identify the first affected interval and preserve surrounding forensic material.
- **Recommendation:** Add a read-only `evidence audit` operation, reusable by the read-only diagnostic path from R-007. Verify sequence continuity, canonical payload digests, predecessor links, signatures, key ID, and the stored head against the independently trusted public key when supplied. Report the first invalid sequence and a non-secret reason. Keep a full audit explicit or scheduled with a bounded work budget rather than adding an unbounded startup scan.
- **Acceptance criteria:**
  - An intact ledger validates from genesis or a cryptographically anchored checkpoint to the current head.
  - Modified payloads, hashes, signatures, key IDs, missing/duplicate sequences, reordered rows, and head mismatches are detected with the first failing sequence.
  - Auditing does not mutate the database and can run against a live WAL database.
  - The command supports an independently trusted public key and clearly distinguishes embedded-key verification from external trust.
  - Large-ledger tests establish memory and elapsed-time bounds and exercise cancellation/resumption behavior.
- **Effort:** M
- **Confidence:** High
- **Tradeoffs / dependencies:** A progress cursor stored only in the same database is not an external trust anchor. Full-chain assurance either scans from genesis or resumes from an independently preserved signed checkpoint.

### E-006 — Expose physical SQLite, WAL, and shared-memory disk usage

- **Priority:** P3
- **Type:** Enhancement
- **Location:** `internal/store/store.go:222`; `internal/store/storage_limits.go:290-318`
- **Evidence:** TailState explicitly runs SQLite in WAL mode. `StorageMetrics` calculates `DatabaseBytes` from `PRAGMA page_count * page_size`, which represents the logical main-database page allocation but not the physical `tailstate.db-wal` and `tailstate.db-shm` files. Diagnostics and metrics therefore cannot show the complete temporary volume footprint.
- **Impact:** An operator can see comfortable logical storage pressure while a large transaction, long-lived reader, or checkpoint problem consumes materially more disk on the volume. The existing logical database ceiling remains useful, but it is not a volume-exhaustion alarm.
- **Recommendation:** Preserve the logical page-budget metric and add separately named physical gauges for the main file, WAL, shared-memory file, and their total. Add checkpoint age/backlog information if the driver exposes it safely. Warn on physical volume pressure without presenting WAL bytes as part of the SQLite logical maximum-page limit.
- **Acceptance criteria:**
  - Metrics and `doctor` distinguish logical database allocation from physical main/WAL/SHM bytes.
  - Missing transient WAL/SHM files report zero rather than an error.
  - Tests create WAL growth and confirm the physical total increases while the logical metric retains its existing meaning.
  - Documentation explains which limit is enforced and which metrics protect the hosting volume.
- **Effort:** S
- **Confidence:** Medium
- **Tradeoffs / dependencies:** File sizes are point-in-time observations and can race with checkpoints. They should be labeled as gauges, not accounting totals or enforcement values.

## Challenge & Decisions

1. **Must `doctor` be strictly read-only?** Recommended answer: yes. A diagnostic command should never create cryptographic state, migrate a schema, backfill evidence, or persist settings. If maintenance is desired, expose it under an explicit command with backup guidance.
2. **What cleanup latency is acceptable at the supported maximum database size?** Establish a target on slow persistent storage, such as a maximum writer-lock interval and a maximum percentage of one monitor cycle, before choosing batch sizes.
3. **Should any proxied `/metrics` request be accepted without a token?** Recommended answer: no. “Local” should describe the direct socket peer, not a user relayed by a local proxy.
4. **Is the evidence ledger an export-time proof or a live tamper alarm?** The implementation currently provides the former. If operators expect the latter, E-005 should be promoted and integrated into diagnostics/alerting.
5. **Is the storage ceiling intended only to bound SQLite pages or to protect the volume?** The current implementation does the former. If volume safety is an operational promise, physical footprint telemetry and filesystem-free-space alerting need explicit ownership.

## Recommended Next Slice

Implement **R-007** first. Safe, truthful diagnostics are foundational for every later storage and evidence improvement, especially when operators use `doctor` during an incident or before an upgrade.

Suggested slice:

1. Add a read-only database inspection API with version-tolerant queries.
2. Make `doctor` report missing, current, and migration-pending databases without mutation.
3. Report configured and persisted storage profiles side by side.
4. Add filesystem/database before-and-after assertions proving the command is read-only.
5. Document the boundary between diagnosis and explicit maintenance.

Do not combine the cleanup batching or metrics authorization change into this slice; each has a separate failure model and rollback surface.

## Validation & Delivery Plan

### Validation performed for this review

- `git diff --check` — passed.
- `go test -race -covermode=atomic -coverpkg=./... ./...` — passed; total coverage 90.0%.
- `go vet ./...` — passed.
- `go tool staticcheck ./...` — passed.
- `bash scripts/invariant-suite.sh` — passed.
- Temporary local `doctor -json` reproduction — confirmed database creation and configured/persisted storage-limit divergence; no project or production data was used.
- Docker builds, external dependency lookups, provider calls, and production-scale destructive tests were not run for this report.

### Planned validation by finding

- **R-007:** read-only filesystem/database invariants, old-schema fixtures, missing DB, wrong key, config mismatch, live WAL inspection, CLI JSON/text golden tests.
- **R-008:** large expired fixtures, concurrent store operations, cancellation and resumption, lease safety, WAL growth, slow-disk benchmark, evidence-retention regression.
- **R-009:** direct/proxied request matrix with trusted and untrusted loopback peers, missing/malformed forwarding headers, bearer-token regression.
- **E-005:** intact and adversarial ledger fixtures, independent key trust, first-failure reporting, cancellation, bounded-memory large-chain audit.
- **E-006:** WAL growth/checkpoint fixtures, transient file disappearance, metric naming/semantics, documentation examples.

### Delivery sequence

1. R-007 — read-only and configuration-faithful diagnostics.
2. R-008 — bounded retention cleanup with backlog observability.
3. R-009 — fail-closed tokenless metrics boundary.
4. E-005 — explicit persisted-ledger audit.
5. E-006 — physical SQLite footprint telemetry.

Each change should land independently with focused regression tests and release-note impact. R-009 requires a compatibility note for proxied tokenless scrapers.

## GitHub Publication Status

**Published on 2026-08-30.** All reviewed findings have individual GitHub issues:

- **R-007:** [#104 — Make doctor read-only and configuration-faithful](https://github.com/crypt0rr/TailState/issues/104) (`bug`)
- **R-008:** [#105 — Bound retention cleanup work and database lock time](https://github.com/crypt0rr/TailState/issues/105) (`bug`)
- **R-009:** [#106 — Fail closed for tokenless metrics behind loopback proxies](https://github.com/crypt0rr/TailState/issues/106) (`bug`)
- **E-005:** [#107 — Add a read-only persisted evidence ledger audit](https://github.com/crypt0rr/TailState/issues/107) (`enhancement`)
- **E-006:** [#108 — Expose physical SQLite and WAL disk usage](https://github.com/crypt0rr/TailState/issues/108) (`enhancement`)

## References

- `cmd/tailstate/main.go`
- `internal/store/store.go`
- `internal/store/status.go`
- `internal/store/storage_limits.go`
- `internal/store/signing.go`
- `internal/store/evidence.go`
- `internal/monitor/engine.go`
- `internal/web/server.go`
- `internal/web/server_test.go`
- `README.md`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/invariant-suite.sh`

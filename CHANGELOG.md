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

[Unreleased]: https://github.com/crypt0rr/TailState/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/crypt0rr/TailState/compare/v0.11.16...v0.12.0
[0.11.16]: https://github.com/crypt0rr/TailState/compare/v0.11.15...v0.11.16

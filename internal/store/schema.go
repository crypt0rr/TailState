package store

const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version(version) SELECT 11 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('setup','reset')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_tokens_expires_at ON auth_tokens(expires_at);
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  csrf_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  tailnet TEXT NOT NULL,
  oauth_client_id TEXT NOT NULL,
  oauth_secret_enc TEXT NOT NULL,
  mattermost_url_enc TEXT NOT NULL,
  webhook_secret_enc TEXT NOT NULL DEFAULT '',
  device_interval_seconds INTEGER NOT NULL,
  inventory_interval_seconds INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  configured_at TEXT NOT NULL,
  baseline_at TEXT
);
CREATE TABLE IF NOT EXISTS notification_destinations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  service_url_enc TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
-- Destination names are display labels, not identities. Duplicate names are
-- intentionally allowed so two endpoints from the same provider can retain
-- distinct durable IDs and delivery history.
CREATE INDEX IF NOT EXISTS notification_destinations_enabled ON notification_destinations(enabled, deleted_at);

-- Relationship policy: these links are intentionally application-managed
-- instead of SQLite foreign keys. The store methods enforce the following
-- invariants while preserving durable history:
--   * collector_state and snapshots are keyed by the active settings
--     generation; changing the tailnet or OAuth identity replaces that
--     generation in one transaction rather than cascading row deletes.
--   * events belong to event_batches, and outbox rows may point at a batch;
--     retention deletes events before empty batches and keeps delivered/dead
--     outbox history independently, so a cascading delete would erase audit
--     evidence or make retention order-dependent.
--   * event_batches.trigger_id and event_batch_triggers.trigger_id point at
--     webhook_triggers only as optional reconciliation correlation. Webhook
--     trigger rows have their own retry/retention lifecycle, so deleting or
--     compacting a trigger must not delete the already-recorded event batch;
--     event_batch_triggers rows are cleaned up only after their batch goes
--     away.
--   * evidence_ledger entries deliberately outlive event_batches to preserve
--     the signed chain and its checkpoints after history retention.
--   * outbox rows keep notification_destinations IDs after a destination is
--     soft-deleted so delivery history remains queryable and labels can be
--     rendered as "Removed destination".
-- Adding cascading constraints would therefore destroy audit history or make
-- migrations/retention impossible without rewriting old databases. Every
-- write path uses generation checks, existence checks, soft-delete predicates,
-- and cleanup queries for these relationships instead.
CREATE TABLE IF NOT EXISTS collector_state (
  generation INTEGER NOT NULL,
  collector TEXT NOT NULL,
  supported INTEGER NOT NULL DEFAULT 1,
  baseline INTEGER NOT NULL DEFAULT 0,
  last_success TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  failure_count INTEGER NOT NULL DEFAULT 0,
  unhealthy_notified INTEGER NOT NULL DEFAULT 0,
  next_poll TEXT,
  poll_duration_ms INTEGER NOT NULL DEFAULT 0,
  partial INTEGER NOT NULL DEFAULT 0,
  partial_error_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(generation, collector)
);
CREATE TABLE IF NOT EXISTS snapshots (
  generation INTEGER NOT NULL,
  collector TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  name TEXT NOT NULL,
  canonical_json BLOB NOT NULL,
  content_hash TEXT NOT NULL,
  missing_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(generation, collector, resource_id)
);
CREATE TABLE IF NOT EXISTS event_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  generation INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  change_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  trigger_id INTEGER
);
CREATE INDEX IF NOT EXISTS event_batches_observed_at ON event_batches(observed_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS event_batch_triggers (
  batch_id INTEGER NOT NULL,
  trigger_id INTEGER NOT NULL,
  PRIMARY KEY(batch_id, trigger_id)
);
CREATE INDEX IF NOT EXISTS event_batch_triggers_trigger_id ON event_batch_triggers(trigger_id, batch_id);
CREATE TABLE IF NOT EXISTS webhook_triggers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  body_hash TEXT NOT NULL UNIQUE,
  received_at TEXT NOT NULL,
  event_types_json BLOB NOT NULL,
  collectors_json BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  lease_until TEXT,
  lease_token TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  processed_at TEXT
);
CREATE INDEX IF NOT EXISTS webhook_triggers_received_at ON webhook_triggers(received_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER,
  generation INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  collector TEXT NOT NULL,
  event_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  name TEXT NOT NULL,
  changes_json BLOB NOT NULL,
  before_json BLOB,
  after_json BLOB
);
CREATE INDEX IF NOT EXISTS events_observed_at ON events(observed_at);
CREATE TABLE IF NOT EXISTS evidence_ledger (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER NOT NULL UNIQUE,
  generation INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL UNIQUE,
  signature TEXT NOT NULL,
  key_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_ledger_batch_id ON evidence_ledger(batch_id);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER,
  destination_id INTEGER NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt TEXT NOT NULL,
  first_attempt TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  lease_until TEXT,
  lease_token TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status, next_attempt);
`

package store

const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
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
  device_interval_seconds INTEGER NOT NULL,
  inventory_interval_seconds INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  configured_at TEXT NOT NULL,
  baseline_at TEXT
);
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
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  generation INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  collector TEXT NOT NULL,
  event_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  name TEXT NOT NULL,
  changes_json BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_observed_at ON events(observed_at);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt TEXT NOT NULL,
  first_attempt TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status, next_attempt);
`

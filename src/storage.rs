use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    config::DestinationConfig,
    destinations::matches,
    event::{Change, Event, severity_for},
};

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone)]
pub struct SnapshotItem {
    pub key: String,
    pub subject: String,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct OutboxItem {
    pub id: i64,
    pub destination: String,
    pub event: Event,
    pub attempts: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreStats {
    pub pending: u64,
    pub dead: u64,
    pub events: u64,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create storage directory {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open SQLite database {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(MIGRATIONS)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn is_baseline_complete(&self) -> Result<bool> {
        Ok(self.meta("baseline_complete")?.as_deref() == Some("1"))
    }
    pub fn set_baseline_complete(&self) -> Result<()> {
        self.set_meta("baseline_complete", "1")
    }
    pub fn reset_incomplete_baseline(&self) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM snapshots", [])?;
        tx.execute("DELETE FROM meta WHERE key LIKE 'collector:%'", [])?;
        tx.commit()?;
        Ok(())
    }
    pub fn collector_initialized(&self, name: &str) -> Result<bool> {
        Ok(self.meta(&format!("collector:{name}"))?.as_deref() == Some("1"))
    }

    pub fn apply_snapshot(
        &self,
        collection: &str,
        items: Vec<SnapshotItem>,
        tailnet: &str,
        destinations: &[DestinationConfig],
    ) -> Result<(usize, Vec<Event>)> {
        let initialized = self.collector_initialized(collection)?;
        let now = Utc::now();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let mut old = HashMap::<String, (String, Value)>::new();
        {
            let mut stmt =
                tx.prepare("SELECT item_key, hash, json FROM snapshots WHERE collection = ?1")?;
            let rows = stmt.query_map([collection], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (key, hash, json) = row?;
                old.insert(key, (hash, serde_json::from_str(&json)?));
            }
        }
        let mut current = HashMap::new();
        let mut events = vec![];
        for mut item in items {
            preserve_stale_hysteresis(&mut item.value, old.get(&item.key).map(|(_, value)| value));
            canonicalize(&mut item.value);
            let json = serde_json::to_string(&item.value)?;
            let hash = hex::encode(Sha256::digest(json.as_bytes()));
            current.insert(item.key.clone(), (hash.clone(), item.value.clone()));
            match old.get(&item.key) {
                None if initialized => events.push(snapshot_event(
                    tailnet,
                    collection,
                    "created",
                    &item.subject,
                    vec![],
                )),
                Some((old_hash, old_value)) if initialized && old_hash != &hash => {
                    let changes = changed_fields(old_value, &item.value);
                    events.push(snapshot_event(
                        tailnet,
                        collection,
                        "changed",
                        &item.subject,
                        changes,
                    ));
                }
                _ => {}
            }
            tx.execute(
                "INSERT INTO snapshots(collection,item_key,hash,json,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(collection,item_key) DO UPDATE SET hash=excluded.hash,json=excluded.json,updated_at=excluded.updated_at",
                params![collection, item.key, hash, json, now.to_rfc3339()],
            )?;
        }
        if initialized {
            for key in old.keys().filter(|k| !current.contains_key(*k)) {
                events.push(snapshot_event(
                    tailnet,
                    collection,
                    "deleted",
                    key.as_str(),
                    vec![],
                ));
            }
        }
        tx.execute(
            "DELETE FROM snapshots WHERE collection=?1 AND updated_at<>?2",
            params![collection, now.to_rfc3339()],
        )?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES(?1,'1') ON CONFLICT(key) DO UPDATE SET value='1'",
            [format!("collector:{collection}")],
        )?;
        for event in &events {
            insert_event_and_outbox(&tx, event, destinations)?;
        }
        tx.commit()?;
        Ok((current.len(), events))
    }

    pub fn enqueue_event(
        &self,
        event: &Event,
        dedupe_key: Option<&str>,
        destinations: &[DestinationConfig],
    ) -> Result<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(key) = dedupe_key {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO dedupe(key,created_at) VALUES(?1,?2)",
                params![key, Utc::now().to_rfc3339()],
            )?;
            if inserted == 0 {
                tx.rollback()?;
                return Ok(false);
            }
        }
        insert_event_and_outbox(&tx, event, destinations)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn due_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id,destination,event_json,attempts,created_at FROM outbox WHERE status='pending' AND next_attempt_at<=?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![Utc::now().to_rfc3339(), limit as i64], |row| {
            let json: String = row.get(2)?;
            let created: String = row.get(4)?;
            Ok(OutboxItem {
                id: row.get(0)?,
                destination: row.get(1)?,
                event: serde_json::from_str(&json).map_err(to_sql_error)?,
                attempts: row.get::<_, u32>(3)?,
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map_err(to_sql_error)?
                    .with_timezone(&Utc),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn delivery_succeeded(&self, id: i64) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE outbox SET status='delivered',delivered_at=?2,last_error=NULL WHERE id=?1",
            params![id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn delivery_failed(
        &self,
        item: &OutboxItem,
        error: &str,
        retry_horizon_seconds: u64,
        max_attempts: u32,
    ) -> Result<bool> {
        let attempts = item.attempts + 1;
        let expired = Utc::now() - item.created_at
            > Duration::seconds(retry_horizon_seconds as i64)
            || attempts >= max_attempts;
        let status = if expired { "dead" } else { "pending" };
        let backoff = (2u64.saturating_pow(attempts.min(10)) + rand::random_range(0..=5)).min(3600);
        let next = Utc::now() + Duration::seconds(backoff as i64);
        self.conn.lock().unwrap().execute(
            "UPDATE outbox SET attempts=?2,status=?3,next_attempt_at=?4,last_error=?5 WHERE id=?1",
            params![
                item.id,
                attempts,
                status,
                next.to_rfc3339(),
                truncate(error, 1000)
            ],
        )?;
        Ok(expired)
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let conn = self.conn.lock().unwrap();
        let count = |sql: &str| -> Result<u64> { Ok(conn.query_row(sql, [], |r| r.get(0))?) };
        Ok(StoreStats {
            pending: count("SELECT COUNT(*) FROM outbox WHERE status='pending'")?,
            dead: count("SELECT COUNT(*) FROM outbox WHERE status='dead'")?,
            events: count("SELECT COUNT(*) FROM events")?,
        })
    }

    pub fn cleanup(&self, retention_days: u32) -> Result<()> {
        let cutoff = (Utc::now() - Duration::days(retention_days as i64)).to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM dedupe WHERE created_at<?1", [&cutoff])?;
        conn.execute(
            "DELETE FROM outbox WHERE status='delivered' AND delivered_at<?1",
            [&cutoff],
        )?;
        conn.execute(
            "DELETE FROM events WHERE created_at<?1 AND id NOT IN (SELECT event_id FROM outbox)",
            [&cutoff],
        )?;
        Ok(())
    }

    fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .optional()?)
    }
    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.lock().unwrap().execute("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,value])?;
        Ok(())
    }
}

fn insert_event_and_outbox(
    tx: &rusqlite::Transaction<'_>,
    event: &Event,
    destinations: &[DestinationConfig],
) -> Result<()> {
    let json = serde_json::to_string(event)?;
    tx.execute(
        "INSERT OR IGNORE INTO events(id,event_json,created_at) VALUES(?1,?2,?3)",
        params![event.id, json, Utc::now().to_rfc3339()],
    )?;
    for destination in destinations
        .iter()
        .filter(|d| d.enabled && matches(d, event))
    {
        tx.execute("INSERT OR IGNORE INTO outbox(event_id,destination,event_json,status,attempts,next_attempt_at,created_at) VALUES(?1,?2,?3,'pending',0,?4,?4)", params![event.id, destination.name, json, Utc::now().to_rfc3339()])?;
    }
    Ok(())
}

fn snapshot_event(
    tailnet: &str,
    collection: &str,
    action: &str,
    subject: &str,
    changes: Vec<Change>,
) -> Event {
    let singular = match collection {
        "devices" => "device",
        "users" => "user",
        "dns" => "dns",
        "keys" => "key",
        "webhooks" => "webhook",
        "contacts" => "contact",
        "settings" => "setting",
        other => other,
    };
    let event_type = format!("tailscale.{singular}.{action}");
    let mut event = Event::new(
        tailnet,
        "api",
        &event_type,
        collection,
        subject,
        format!("Tailscale {singular} {subject} was {action}"),
    );
    event.severity = severity_for(&event_type);
    event.changes = changes;
    event
}

fn preserve_stale_hysteresis(new: &mut Value, old: Option<&Value>) {
    let Some(object) = new.as_object_mut() else {
        return;
    };
    if object.get("tailstateInferredStale") != Some(&Value::Null) {
        return;
    }
    let previous = old
        .and_then(|value| value.get("tailstateInferredStale"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    object.insert("tailstateInferredStale".into(), Value::Bool(previous));
}

fn changed_fields(old: &Value, new: &Value) -> Vec<Change> {
    let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else {
        return vec![Change {
            field: "value".into(),
            old: None,
            new: None,
        }];
    };
    let mut keys = old.keys().chain(new.keys()).collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|key| old.get(*key) != new.get(*key))
        .map(|key| Change {
            field: redact_field(key),
            old: None,
            new: None,
        })
        .collect()
}

fn redact_field(field: &str) -> String {
    let lower = field.to_ascii_lowercase();
    if ["token", "secret", "credential", "policy", "acl"]
        .iter()
        .any(|x| lower.contains(x))
    {
        format!("{field} (redacted)")
    } else {
        field.into()
    }
}

pub fn canonicalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let old = std::mem::take(map);
            let mut sorted = BTreeMap::new();
            for (key, mut value) in old {
                canonicalize(&mut value);
                sorted.insert(key, value);
            }
            map.extend(sorted);
        }
        Value::Array(values) => {
            values.iter_mut().for_each(canonicalize);
            values.sort_by_key(|v| serde_json::to_string(v).unwrap_or_default());
        }
        _ => {}
    }
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
fn to_sql_error(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

const MIGRATIONS: &str = r#"
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots(collection TEXT NOT NULL,item_key TEXT NOT NULL,hash TEXT NOT NULL,json TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(collection,item_key));
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,event_json TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dedupe(key TEXT PRIMARY KEY,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox(
 id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,destination TEXT NOT NULL,event_json TEXT NOT NULL,status TEXT NOT NULL,
 attempts INTEGER NOT NULL,next_attempt_at TEXT NOT NULL,created_at TEXT NOT NULL,delivered_at TEXT,last_error TEXT,
 UNIQUE(event_id,destination),FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status,next_attempt_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_arrays_do_not_depend_on_order() {
        let mut a = serde_json::json!({"x":[{"id":2},{"id":1}]});
        let mut b = serde_json::json!({"x":[{"id":1},{"id":2}]});
        canonicalize(&mut a);
        canonicalize(&mut b);
        assert_eq!(a, b);
    }
    #[test]
    fn first_snapshot_is_silent_and_next_diff_emits() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db.sqlite")).unwrap();
        let item = |name: &str| SnapshotItem {
            key: "1".into(),
            subject: "one".into(),
            value: serde_json::json!({"name":name}),
        };
        assert!(
            store
                .apply_snapshot("devices", vec![item("a")], "tail", &[])
                .unwrap()
                .1
                .is_empty()
        );
        assert_eq!(
            store
                .apply_snapshot("devices", vec![item("b")], "tail", &[])
                .unwrap()
                .1
                .len(),
            1
        );
    }

    #[test]
    fn dns_event_name_is_stable() {
        let event = snapshot_event("tail", "dns", "changed", "DNS", vec![]);
        assert_eq!(event.event_type, "tailscale.dns.changed");
    }

    #[test]
    fn stale_state_uses_hysteresis() {
        let old = serde_json::json!({"tailstateInferredStale":true});
        let mut new = serde_json::json!({"tailstateInferredStale":null});
        preserve_stale_hysteresis(&mut new, Some(&old));
        assert_eq!(new["tailstateInferredStale"], true);
    }

    #[test]
    fn outbox_is_filtered_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db.sqlite")).unwrap();
        let destination = crate::config::DestinationConfig {
            name: "ops".into(),
            include: vec!["tailscale.device.*".into()],
            ..Default::default()
        };
        let event = Event::new(
            "tail",
            "api",
            "tailscale.device.changed",
            "devices",
            "one",
            "changed",
        );
        assert!(
            store
                .enqueue_event(&event, Some("one"), &[destination])
                .unwrap()
        );
        assert!(!store.enqueue_event(&event, Some("one"), &[]).unwrap());
        assert_eq!(store.stats().unwrap().pending, 1);
    }
}

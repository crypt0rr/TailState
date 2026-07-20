use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Change {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub schema_version: u8,
    pub id: String,
    pub occurred_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub source: String,
    pub tailnet: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub category: String,
    pub severity: Severity,
    pub subject: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Event {
    pub fn new(
        tailnet: &str,
        source: &str,
        event_type: impl Into<String>,
        category: impl Into<String>,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            schema_version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            occurred_at: now,
            observed_at: now,
            source: source.into(),
            tailnet: tailnet.into(),
            event_type: event_type.into(),
            category: category.into(),
            severity: Severity::Info,
            subject: subject.into(),
            message: message.into(),
            changes: vec![],
            metadata: BTreeMap::new(),
        }
    }
}

pub fn severity_for(event_type: &str) -> Severity {
    let lower = event_type.to_ascii_lowercase();
    if [
        "needsapproval",
        "expired",
        "expiring",
        "misconfiguration",
        "unhealthy",
        "dead_letter",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        Severity::Warning
    } else {
        Severity::Info
    }
}

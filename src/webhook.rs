use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use axum::{body::Bytes, http::HeaderMap};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::event::{Event, severity_for};

#[derive(Debug, Deserialize, Serialize)]
struct NativeEvent {
    timestamp: DateTime<Utc>,
    #[allow(dead_code)]
    version: u32,
    #[serde(rename = "type")]
    event_type: String,
    tailnet: String,
    message: String,
    data: Option<Value>,
}

pub fn verify_and_parse(
    headers: &HeaderMap,
    body: &Bytes,
    secret: &str,
    replay_window_seconds: i64,
) -> Result<Vec<(Event, String)>> {
    let header = headers
        .get("Tailscale-Webhook-Signature")
        .context("missing Tailscale-Webhook-Signature header")?
        .to_str()
        .context("signature header is not valid ASCII")?;
    let (timestamp, signature) = parse_signature(header)?;
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > replay_window_seconds {
        bail!("webhook signature timestamp is outside the replay window")
    }
    let signature = hex::decode(signature).context("signature is not hexadecimal")?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&signature)
        .map_err(|_| anyhow::anyhow!("webhook signature mismatch"))?;

    let native: Vec<NativeEvent> =
        serde_json::from_slice(body).context("webhook payload must be an array of events")?;
    let mut output = Vec::with_capacity(native.len());
    for source in native {
        let mut source_value = serde_json::to_value(&source)?;
        crate::storage::canonicalize(&mut source_value);
        let dedupe = format!(
            "webhook:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(&source_value)?))
        );
        let full_type = format!("tailscale.webhook.{}", source.event_type);
        let mut event = Event::new(
            &source.tailnet,
            "webhook",
            &full_type,
            category(&source.event_type),
            subject(&source),
            &source.message,
        );
        event.occurred_at = source.timestamp;
        event.severity = severity_for(&source.event_type);
        event.metadata = sanitized_metadata(source.data.as_ref());
        output.push((event, dedupe));
    }
    Ok(output)
}

fn parse_signature(value: &str) -> Result<(i64, &str)> {
    let mut timestamp = None;
    let mut signature = None;
    for part in value.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key {
            "t" => {
                timestamp = Some(
                    value
                        .parse::<i64>()
                        .context("invalid signature timestamp")?,
                )
            }
            "v1" => signature = Some(value),
            _ => {}
        }
    }
    Ok((
        timestamp.context("signature timestamp missing")?,
        signature.context("v1 signature missing")?,
    ))
}

fn category(event_type: &str) -> &'static str {
    if event_type.starts_with("node")
        || event_type.starts_with("user")
        || event_type == "policyUpdate"
    {
        "tailnet_management"
    } else if event_type.starts_with("webhook") || event_type == "test" {
        "webhook_management"
    } else if event_type.contains("IPForwarding") {
        "device_misconfiguration"
    } else {
        "unknown"
    }
}

fn subject(event: &NativeEvent) -> String {
    event
        .data
        .as_ref()
        .and_then(|d| d.get("deviceName").or_else(|| d.get("user")))
        .and_then(Value::as_str)
        .unwrap_or(&event.event_type)
        .to_string()
}

fn sanitized_metadata(data: Option<&Value>) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let Some(object) = data.and_then(Value::as_object) else {
        return out;
    };
    for key in [
        "actor",
        "url",
        "deviceName",
        "nodeID",
        "managedBy",
        "expiration",
        "user",
        "oldRoles",
        "newRoles",
    ] {
        if let Some(value) = object.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    #[test]
    fn verifies_signed_batch() {
        let timestamp = Utc::now().timestamp();
        let body = Bytes::from(format!(
            r#"[{{"timestamp":"{}","version":1,"type":"test","tailnet":"example.com","message":"test","data":null}}]"#,
            Utc::now().to_rfc3339()
        ));
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(&body);
        let mut headers = HeaderMap::new();
        headers.insert(
            "Tailscale-Webhook-Signature",
            HeaderValue::from_str(&format!(
                "t={timestamp},v1={}",
                hex::encode(mac.finalize().into_bytes())
            ))
            .unwrap(),
        );
        let first = verify_and_parse(&headers, &body, "secret", 300).unwrap();
        let second = verify_and_parse(&headers, &body, "secret", 300).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1, second[0].1, "retry dedupe keys must be stable");
    }
    #[test]
    fn rejects_old_timestamp() {
        let body = Bytes::from_static(b"[]");
        let timestamp = Utc::now().timestamp() - 1000;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(&body);
        let mut headers = HeaderMap::new();
        headers.insert(
            "Tailscale-Webhook-Signature",
            HeaderValue::from_str(&format!(
                "t={timestamp},v1={}",
                hex::encode(mac.finalize().into_bytes())
            ))
            .unwrap(),
        );
        assert!(verify_and_parse(&headers, &body, "secret", 300).is_err());
    }
}

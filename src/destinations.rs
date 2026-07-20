use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use globset::{Glob, GlobSetBuilder};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
    config::{DestinationConfig, DestinationKind},
    event::Event,
};

pub fn matches(config: &DestinationConfig, event: &Event) -> bool {
    if event.severity < config.min_severity {
        return false;
    }
    let build = |patterns: &[String]| {
        let mut builder = GlobSetBuilder::new();
        for p in patterns {
            if let Ok(g) = Glob::new(p) {
                builder.add(g);
            }
        }
        builder.build().ok()
    };
    if build(&config.exclude).is_some_and(|s| s.is_match(&event.event_type)) {
        return false;
    }
    config.include.is_empty()
        || build(&config.include).is_some_and(|s| s.is_match(&event.event_type))
}

#[derive(Clone)]
pub struct Sender {
    client: Client,
}

impl Sender {
    pub fn new(timeout_seconds: u64) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_seconds))
                .user_agent(concat!("tailstate/", env!("CARGO_PKG_VERSION")))
                .build()?,
        })
    }

    pub async fn send(&self, destination: &DestinationConfig, event: &Event) -> Result<()> {
        let text = render(event, limit(destination.kind));
        let (url, body) = payload(destination, event, &text)?;
        let bytes = serde_json::to_vec(&body)?;
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json");
        for (key, value) in &destination.headers {
            request = request.header(key, value);
        }
        if let Some(token) = &destination.bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(user) = &destination.basic_username {
            let encoded = STANDARD.encode(format!(
                "{user}:{}",
                destination.basic_password.as_deref().unwrap_or("")
            ));
            request = request.header("Authorization", format!("Basic {encoded}"));
        }
        if let Some(secret) = &destination.hmac_secret {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .expect("HMAC accepts any key size");
            mac.update(format!("{timestamp}.").as_bytes());
            mac.update(&bytes);
            request = request.header(
                "X-TailState-Signature",
                format!(
                    "t={timestamp},v1={}",
                    hex::encode(mac.finalize().into_bytes())
                ),
            );
        }
        let response = request
            .body(bytes)
            .send()
            .await
            .context("send notification")?;
        if !response.status().is_success() {
            let status = response.status();
            bail!("destination returned {status}");
        }
        Ok(())
    }
}

fn payload(destination: &DestinationConfig, event: &Event, text: &str) -> Result<(String, Value)> {
    Ok(match destination.kind {
        DestinationKind::Telegram => {
            let token = destination
                .token
                .as_deref()
                .context("missing Telegram token")?;
            (
                format!("https://api.telegram.org/bot{token}/sendMessage"),
                json!({"chat_id":destination.chat_id,"text":text,"disable_web_page_preview":true}),
            )
        }
        DestinationKind::Discord => (required_url(destination)?.into(), json!({"content":text})),
        DestinationKind::MicrosoftTeams => (
            required_url(destination)?.into(),
            json!({
                "type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.4","body":[{"type":"TextBlock","text":text,"wrap":true}]}}]
            }),
        ),
        DestinationKind::Mattermost | DestinationKind::Slack | DestinationKind::GoogleChat => {
            (required_url(destination)?.into(), json!({"text":text}))
        }
        DestinationKind::GenericWebhook => (
            required_url(destination)?.into(),
            serde_json::to_value(event)?,
        ),
    })
}

fn required_url(config: &DestinationConfig) -> Result<&str> {
    config.url.as_deref().context("destination URL missing")
}
fn limit(kind: DestinationKind) -> usize {
    match kind {
        DestinationKind::Telegram => 4096,
        DestinationKind::Discord => 2000,
        _ => 12_000,
    }
}

pub fn render(event: &Event, max: usize) -> String {
    let icon = match event.severity {
        crate::event::Severity::Info => "ℹ️",
        crate::event::Severity::Warning => "⚠️",
        crate::event::Severity::Critical => "🚨",
    };
    let mut lines = vec![
        format!("{icon} {}", event.message),
        format!(
            "Tailnet: {} · Source: {} · Type: {}",
            event.tailnet, event.source, event.event_type
        ),
    ];
    for change in &event.changes {
        lines.push(format!("• {} changed", change.field));
    }
    if let Some(actor) = safe_metadata(event, "actor") {
        lines.push(format!("Actor: {actor}"));
    }
    if let Some(url) = safe_metadata(event, "url") {
        lines.push(url);
    }
    truncate_lines(lines, max)
}

fn safe_metadata(event: &Event, key: &str) -> Option<String> {
    let value = event.metadata.get(key)?.as_str()?;
    if key == "url"
        && url::Url::parse(value)
            .ok()
            .is_some_and(|u| !u.username().is_empty() || u.password().is_some())
    {
        return None;
    }
    Some(value.to_string())
}

fn truncate_lines(lines: Vec<String>, max: usize) -> String {
    let mut out = String::new();
    for line in lines {
        let candidate = if out.is_empty() {
            line.clone()
        } else {
            format!("{out}\n{line}")
        };
        if candidate.chars().count() > max.saturating_sub(2) {
            out.push('…');
            break;
        }
        out = candidate;
    }
    out
}

pub fn generic_payload(event: &Event) -> Result<BTreeMap<String, Value>> {
    serde_json::from_value(serde_json::to_value(event)?).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::DestinationConfig, event::Event};
    #[test]
    fn exclusions_win() {
        let d = DestinationConfig {
            include: vec!["tailscale.*".into()],
            exclude: vec!["*.test".into()],
            ..Default::default()
        };
        let e = Event::new(
            "t",
            "webhook",
            "tailscale.webhook.test",
            "test",
            "test",
            "test",
        );
        assert!(!matches(&d, &e));
    }
    #[test]
    fn truncation_keeps_bound() {
        let e = Event::new(
            "t",
            "api",
            "tailscale.device.changed",
            "devices",
            "x",
            "x".repeat(100),
        );
        assert!(render(&e, 80).chars().count() <= 80);
    }

    #[test]
    fn every_adapter_produces_its_documented_shape() {
        let event = Event::new(
            "t",
            "api",
            "tailscale.device.changed",
            "devices",
            "x",
            "changed",
        );
        for kind in [
            DestinationKind::Mattermost,
            DestinationKind::Slack,
            DestinationKind::GoogleChat,
        ] {
            let config = DestinationConfig {
                kind,
                url: Some("https://example.test/hook".into()),
                ..Default::default()
            };
            assert!(
                payload(&config, &event, "message")
                    .unwrap()
                    .1
                    .get("text")
                    .is_some()
            );
        }
        let discord = DestinationConfig {
            kind: DestinationKind::Discord,
            url: Some("https://example.test/hook".into()),
            ..Default::default()
        };
        assert!(
            payload(&discord, &event, "message")
                .unwrap()
                .1
                .get("content")
                .is_some()
        );
        let teams = DestinationConfig {
            kind: DestinationKind::MicrosoftTeams,
            url: Some("https://example.test/hook".into()),
            ..Default::default()
        };
        assert!(
            payload(&teams, &event, "message")
                .unwrap()
                .1
                .get("attachments")
                .is_some()
        );
        let telegram = DestinationConfig {
            kind: DestinationKind::Telegram,
            token: Some("token".into()),
            chat_id: Some("chat".into()),
            ..Default::default()
        };
        assert!(
            payload(&telegram, &event, "message")
                .unwrap()
                .0
                .contains("bottoken")
        );
        let generic = DestinationConfig {
            kind: DestinationKind::GenericWebhook,
            url: Some("https://example.test/hook".into()),
            ..Default::default()
        };
        assert_eq!(
            payload(&generic, &event, "message").unwrap().1["schema_version"],
            1
        );
    }
}

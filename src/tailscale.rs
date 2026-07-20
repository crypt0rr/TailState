use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    config::{AuthConfig, TailscaleConfig},
    storage::{SnapshotItem, canonicalize},
};

#[derive(Clone)]
pub struct TailscaleClient {
    config: TailscaleConfig,
    client: Client,
    token: Arc<Mutex<Option<CachedToken>>>,
}

#[derive(Clone)]
struct CachedToken {
    value: String,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct OAuthResponse {
    access_token: String,
    expires_in: i64,
}

impl TailscaleClient {
    pub fn new(config: &TailscaleConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .user_agent(concat!("tailstate/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            config: config.clone(),
            client,
            token: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn check(&self) -> Result<()> {
        for collector in &self.config.collectors {
            self.collect(collector)
                .await
                .with_context(|| format!("collector {collector} is inaccessible"))?;
        }
        Ok(())
    }

    pub async fn collect(&self, collector: &str) -> Result<Vec<SnapshotItem>> {
        match collector {
            "devices" => self.devices().await,
            "users" => {
                self.collection("users", "users", &["id", "userId", "loginName"])
                    .await
            }
            "dns" => self.dns().await,
            "policy" => self.policy().await,
            "keys" => {
                self.collection("keys", "keys", &["id", "keyId", "keyID"])
                    .await
            }
            "webhooks" => {
                self.collection("webhooks", "webhooks", &["id", "endpointId", "endpointID"])
                    .await
            }
            "log_streaming" => self.log_streaming().await,
            "contacts" => self.single("contacts", "contacts").await,
            "posture" => {
                self.collection(
                    "posture/integrations",
                    "integrations",
                    &["id", "integrationId", "integrationID"],
                )
                .await
            }
            "settings" => self.single("settings", "settings").await,
            other => bail!("unknown collector {other}"),
        }
    }

    async fn devices(&self) -> Result<Vec<SnapshotItem>> {
        let devices = self
            .collection_pages("devices?fields=all", "devices")
            .await?;
        let mut output = Vec::with_capacity(devices.len());
        for mut device in devices {
            let id = id_for(&device, &["id", "nodeId", "nodeID"]);
            if id == "unknown" {
                continue;
            }
            let routes = self.get_global(&format!("device/{id}/routes")).await?;
            let attributes = self.get_global(&format!("device/{id}/attributes")).await?;
            let invites = self
                .get_global(&format!("device/{id}/device-invites"))
                .await?;
            if let Some(object) = device.as_object_mut() {
                object.insert("routes".into(), routes);
                object.insert("postureAttributes".into(), attributes);
                object.insert("deviceInvites".into(), invites);
                if self.config.stale_device.enabled
                    && let Some(last_seen) = object
                        .get("lastSeen")
                        .and_then(Value::as_str)
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                {
                    let age = Utc::now()
                        .signed_duration_since(last_seen.with_timezone(&Utc))
                        .num_seconds();
                    let state = if age > self.config.stale_device.threshold_seconds as i64 {
                        Value::Bool(true)
                    } else if age < self.config.stale_device.recovery_seconds as i64 {
                        Value::Bool(false)
                    } else {
                        Value::Null
                    };
                    object.insert("tailstateInferredStale".into(), state);
                }
                object.remove("lastSeen");
            }
            sanitize(&mut device);
            let subject = subject_for(&device, &id);
            output.push(SnapshotItem {
                key: id,
                subject,
                value: device,
            });
        }
        Ok(output)
    }

    async fn dns(&self) -> Result<Vec<SnapshotItem>> {
        let mut object = Map::new();
        for endpoint in ["nameservers", "preferences", "searchpaths", "split-dns"] {
            object.insert(
                endpoint.into(),
                self.get_tailnet(&format!("dns/{endpoint}")).await?,
            );
        }
        let mut value = Value::Object(object);
        sanitize(&mut value);
        Ok(vec![SnapshotItem {
            key: "dns".into(),
            subject: "DNS configuration".into(),
            value,
        }])
    }

    async fn policy(&self) -> Result<Vec<SnapshotItem>> {
        let mut policy = self.get_tailnet("acl").await?;
        canonicalize(&mut policy);
        let mut sections = Map::new();
        match policy {
            Value::Object(object) => {
                for (key, value) in object {
                    sections.insert(key, Value::String(hash_value(&value)));
                }
            }
            value => {
                sections.insert("policy".into(), Value::String(hash_value(&value)));
            }
        }
        Ok(vec![SnapshotItem {
            key: "policy".into(),
            subject: "tailnet policy".into(),
            value: Value::Object(sections),
        }])
    }

    async fn log_streaming(&self) -> Result<Vec<SnapshotItem>> {
        let mut object = Map::new();
        for log_type in ["configuration", "network"] {
            let stream = self
                .get_tailnet(&format!("logging/{log_type}/stream"))
                .await?;
            let status = self
                .get_tailnet(&format!("logging/{log_type}/status"))
                .await?;
            object.insert(log_type.into(), json!({"stream":stream,"status":status}));
        }
        let mut value = Value::Object(object);
        sanitize(&mut value);
        Ok(vec![SnapshotItem {
            key: "log_streaming".into(),
            subject: "log streaming configuration".into(),
            value,
        }])
    }

    async fn collection(
        &self,
        endpoint: &str,
        array_key: &str,
        ids: &[&str],
    ) -> Result<Vec<SnapshotItem>> {
        let values = self.collection_pages(endpoint, array_key).await?;
        Ok(values
            .into_iter()
            .enumerate()
            .map(|(index, mut value)| {
                sanitize(&mut value);
                let id = id_for(&value, ids);
                let key = if id == "unknown" {
                    format!("{array_key}-{index}-{}", hash_value(&value))
                } else {
                    id
                };
                SnapshotItem {
                    subject: subject_for(&value, &key),
                    key,
                    value,
                }
            })
            .collect())
    }

    async fn single(&self, endpoint: &str, subject: &str) -> Result<Vec<SnapshotItem>> {
        let mut value = self.get_tailnet(endpoint).await?;
        sanitize(&mut value);
        Ok(vec![SnapshotItem {
            key: subject.into(),
            subject: subject.into(),
            value,
        }])
    }

    async fn get_tailnet(&self, suffix: &str) -> Result<Value> {
        self.get(&self.tailnet_url(suffix)).await
    }
    async fn get_global(&self, suffix: &str) -> Result<Value> {
        self.get(&format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            suffix
        ))
        .await
    }

    fn tailnet_url(&self, suffix: &str) -> String {
        format!(
            "{}/tailnet/{}/{}",
            self.config.base_url.trim_end_matches('/'),
            encode(&self.config.tailnet),
            suffix
        )
    }

    async fn collection_pages(&self, endpoint: &str, array_key: &str) -> Result<Vec<Value>> {
        let mut url = self.tailnet_url(endpoint);
        let mut all = Vec::new();
        for _ in 0..100 {
            let page = self.get(&url).await?;
            let next = pagination_next(&page, &url)?;
            all.extend(find_array(page, array_key)?);
            match next {
                Some(next) => url = next,
                None => return Ok(all),
            }
        }
        bail!("pagination for {endpoint} exceeded 100 pages")
    }

    async fn get(&self, url: &str) -> Result<Value> {
        for attempt in 0..4 {
            let token = self.access_token().await?;
            let response = self
                .client
                .get(url)
                .bearer_auth(&token)
                .send()
                .await
                .with_context(|| format!("GET {url}"))?;
            if response.status() == StatusCode::UNAUTHORIZED
                && attempt == 0
                && matches!(self.config.auth, Some(AuthConfig::Oauth { .. }))
            {
                *self.token.lock().await = None;
                continue;
            }
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                let delay = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(2u64.pow(attempt + 1));
                tokio::time::sleep(Duration::from_secs(delay.min(60))).await;
                continue;
            }
            let status = response.status();
            let bytes = response.bytes().await?;
            if !status.is_success() {
                bail!("GET {url} returned {status}")
            }
            if bytes.is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_slice(&bytes)
                .or_else(|_| {
                    Ok::<Value, serde_json::Error>(Value::String(
                        String::from_utf8_lossy(&bytes).into_owned(),
                    ))
                })
                .map_err(Into::into);
        }
        bail!("GET {url} exhausted retries")
    }

    async fn access_token(&self) -> Result<String> {
        match self
            .config
            .auth
            .as_ref()
            .context("Tailscale auth missing")?
        {
            AuthConfig::ApiToken { token, .. } => token.clone().context("API token missing"),
            AuthConfig::Oauth {
                client_id,
                client_secret,
                scope,
                ..
            } => {
                let mut cache = self.token.lock().await;
                if let Some(token) = cache
                    .as_ref()
                    .filter(|t| t.expires_at > Utc::now() + chrono::Duration::seconds(30))
                {
                    return Ok(token.value.clone());
                }
                let secret = client_secret
                    .as_deref()
                    .context("OAuth client secret missing")?;
                let url = format!("{}/oauth/token", self.config.base_url.trim_end_matches('/'));
                let response = self
                    .client
                    .post(url)
                    .form(&[
                        ("client_id", client_id.as_str()),
                        ("client_secret", secret),
                        ("grant_type", "client_credentials"),
                        ("scope", scope.as_str()),
                    ])
                    .send()
                    .await?;
                let status = response.status();
                let bytes = response.bytes().await?;
                if !status.is_success() {
                    bail!("OAuth token request returned {status}")
                }
                let oauth: OAuthResponse =
                    serde_json::from_slice(&bytes).context("parse OAuth token response")?;
                *cache = Some(CachedToken {
                    value: oauth.access_token.clone(),
                    expires_at: Utc::now() + chrono::Duration::seconds(oauth.expires_in),
                });
                Ok(oauth.access_token)
            }
        }
    }
}

fn find_array(value: Value, key: &str) -> Result<Vec<Value>> {
    if let Value::Array(values) = value {
        return Ok(values);
    }
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .with_context(|| format!("API response did not contain {key} array"))
}
fn id_for(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key))
        .map(string_value)
        .unwrap_or_else(|| "unknown".into())
}
fn subject_for(value: &Value, fallback: &str) -> String {
    ["name", "hostname", "deviceName", "loginName", "email"]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or(fallback)
        .to_string()
}
fn string_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}
fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn pagination_next(value: &Value, current: &str) -> Result<Option<String>> {
    let candidate = value
        .get("next")
        .or_else(|| value.get("nextPage"))
        .or_else(|| value.get("next_page"))
        .or_else(|| value.pointer("/links/next"));
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let candidate = candidate
        .as_str()
        .or_else(|| candidate.get("href").and_then(Value::as_str));
    let Some(candidate) = candidate.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        return Ok(Some(candidate.to_string()));
    }
    let mut url = url::Url::parse(current)?;
    if candidate.starts_with('/') {
        return Ok(Some(url.join(candidate)?.to_string()));
    }
    url.query_pairs_mut().append_pair("cursor", candidate);
    Ok(Some(url.to_string()))
}
fn hash_value(value: &Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).unwrap_or_default(),
    ))
}

fn sanitize(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let sensitive = object
                .keys()
                .filter(|key| {
                    let lower = key.to_ascii_lowercase();
                    lower.contains("secret")
                        || lower == "token"
                        || lower == "access_token"
                        || lower == "clientsecret"
                        || lower == "newpolicy"
                        || lower == "oldpolicy"
                })
                .cloned()
                .collect::<Vec<_>>();
            for key in sensitive {
                object.remove(&key);
            }
            for value in object.values_mut() {
                sanitize(value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sanitize),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removes_secrets_recursively() {
        let mut value = json!({"id":"1","secret":"x","nested":{"access_token":"y","ok":true}});
        sanitize(&mut value);
        assert_eq!(value, json!({"id":"1","nested":{"ok":true}}));
    }
    #[test]
    fn policy_only_keeps_hashes() {
        assert_ne!(hash_value(&json!({"a":1})), hash_value(&json!({"a":2})));
    }
    #[test]
    fn pagination_supports_next_urls_and_cursors() {
        let current = "https://api.tailscale.com/api/v2/tailnet/t/devices";
        assert_eq!(
            pagination_next(&json!({"next":"abc"}), current)
                .unwrap()
                .unwrap(),
            format!("{current}?cursor=abc")
        );
        assert_eq!(
            pagination_next(&json!({"next":"https://example.test/page/2"}), current)
                .unwrap()
                .unwrap(),
            "https://example.test/page/2"
        );
    }
}

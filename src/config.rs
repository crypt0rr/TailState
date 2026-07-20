use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::event::Severity;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub tailscale: TailscaleConfig,
    pub storage: StorageConfig,
    pub delivery: DeliveryConfig,
    pub destinations: Vec<DestinationConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub replay_window_seconds: i64,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".parse().unwrap(),
            replay_window_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TailscaleConfig {
    pub tailnet: String,
    pub base_url: String,
    pub polling_enabled: bool,
    pub webhook_enabled: bool,
    pub webhook_secret: Option<String>,
    pub webhook_secret_file: Option<PathBuf>,
    pub auth: Option<AuthConfig>,
    pub core_interval_seconds: u64,
    pub secondary_interval_seconds: u64,
    pub collector_intervals_seconds: BTreeMap<String, u64>,
    pub request_timeout_seconds: u64,
    pub startup_jitter_seconds: u64,
    pub collectors: Vec<String>,
    pub stale_device: StaleDeviceConfig,
}
impl Default for TailscaleConfig {
    fn default() -> Self {
        Self {
            tailnet: String::new(),
            base_url: "https://api.tailscale.com/api/v2".into(),
            polling_enabled: true,
            webhook_enabled: true,
            webhook_secret: None,
            webhook_secret_file: None,
            auth: None,
            core_interval_seconds: 60,
            secondary_interval_seconds: 300,
            collector_intervals_seconds: BTreeMap::new(),
            request_timeout_seconds: 20,
            startup_jitter_seconds: 10,
            collectors: [
                "devices",
                "users",
                "dns",
                "policy",
                "keys",
                "webhooks",
                "log_streaming",
                "contacts",
                "posture",
                "settings",
            ]
            .map(str::to_string)
            .to_vec(),
            stale_device: StaleDeviceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthConfig {
    Oauth {
        client_id: String,
        client_secret: Option<String>,
        client_secret_file: Option<PathBuf>,
        #[serde(default = "default_scope")]
        scope: String,
    },
    ApiToken {
        token: Option<String>,
        token_file: Option<PathBuf>,
    },
}
fn default_scope() -> String {
    "all:read".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaleDeviceConfig {
    pub enabled: bool,
    pub threshold_seconds: u64,
    pub recovery_seconds: u64,
}
impl Default for StaleDeviceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold_seconds: 900,
            recovery_seconds: 120,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub retention_days: u32,
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: "/data/tailstate.db".into(),
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeliveryConfig {
    pub retry_horizon_seconds: u64,
    pub poll_interval_seconds: u64,
    pub max_attempts: u32,
}
impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            retry_horizon_seconds: 86_400,
            poll_interval_seconds: 2,
            max_attempts: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Telegram,
    Mattermost,
    Slack,
    Discord,
    MicrosoftTeams,
    GoogleChat,
    GenericWebhook,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DestinationConfig {
    pub name: String,
    pub kind: DestinationKind,
    pub enabled: bool,
    pub url: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub chat_id: Option<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub min_severity: Severity,
    pub headers: BTreeMap<String, String>,
    pub bearer_token: Option<String>,
    pub bearer_token_file: Option<PathBuf>,
    pub basic_username: Option<String>,
    pub basic_password: Option<String>,
    pub basic_password_file: Option<PathBuf>,
    pub hmac_secret: Option<String>,
    pub hmac_secret_file: Option<PathBuf>,
}
impl Default for DestinationConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: DestinationKind::GenericWebhook,
            enabled: true,
            url: None,
            token: None,
            token_file: None,
            chat_id: None,
            include: vec!["*".into()],
            exclude: vec![],
            min_severity: Severity::Info,
            headers: BTreeMap::new(),
            bearer_token: None,
            bearer_token_file: None,
            basic_username: None,
            basic_password: None,
            basic_password_file: None,
            hmac_secret: None,
            hmac_secret_file: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        let expanded = expand_env(&raw)?;
        let mut config: Config =
            serde_yaml_ng::from_str(&expanded).context("parse YAML configuration")?;
        config.resolve_files()?;
        config.validate()?;
        Ok(config)
    }

    fn resolve_files(&mut self) -> Result<()> {
        resolve_secret(
            &mut self.tailscale.webhook_secret,
            &self.tailscale.webhook_secret_file,
        )?;
        if let Some(auth) = &mut self.tailscale.auth {
            match auth {
                AuthConfig::Oauth {
                    client_secret,
                    client_secret_file,
                    ..
                } => resolve_secret(client_secret, client_secret_file)?,
                AuthConfig::ApiToken { token, token_file } => resolve_secret(token, token_file)?,
            }
        }
        for d in &mut self.destinations {
            resolve_secret(&mut d.token, &d.token_file)?;
            resolve_secret(&mut d.bearer_token, &d.bearer_token_file)?;
            resolve_secret(&mut d.basic_password, &d.basic_password_file)?;
            resolve_secret(&mut d.hmac_secret, &d.hmac_secret_file)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.tailscale.tailnet.trim().is_empty() {
            bail!("tailscale.tailnet is required")
        }
        if self.tailscale.polling_enabled && self.tailscale.auth.is_none() {
            bail!("tailscale.auth is required when polling is enabled")
        }
        if self.tailscale.webhook_enabled
            && self
                .tailscale
                .webhook_secret
                .as_deref()
                .unwrap_or("")
                .is_empty()
        {
            bail!("webhook_secret or webhook_secret_file is required when webhooks are enabled")
        }
        let allowed = [
            "devices",
            "users",
            "dns",
            "policy",
            "keys",
            "webhooks",
            "log_streaming",
            "contacts",
            "posture",
            "settings",
        ];
        for c in &self.tailscale.collectors {
            if !allowed.contains(&c.as_str()) {
                bail!("unknown collector {c}")
            }
        }
        for (collector, interval) in &self.tailscale.collector_intervals_seconds {
            if !allowed.contains(&collector.as_str()) {
                bail!("unknown collector interval override {collector}")
            }
            if *interval == 0 {
                bail!("collector interval for {collector} must be positive")
            }
        }
        let mut names = std::collections::HashSet::new();
        for d in self.destinations.iter().filter(|d| d.enabled) {
            if d.name.trim().is_empty() || !names.insert(&d.name) {
                bail!("destination names must be non-empty and unique")
            }
            match d.kind {
                DestinationKind::Telegram if d.token.is_none() || d.chat_id.is_none() => {
                    bail!("Telegram destination {} requires token and chat_id", d.name)
                }
                DestinationKind::Telegram => {}
                _ if d.url.is_none() => bail!("destination {} requires url", d.name),
                _ => {}
            }
            let auth_modes =
                usize::from(d.bearer_token.is_some()) + usize::from(d.basic_username.is_some());
            if auth_modes > 1 {
                bail!(
                    "destination {} configures multiple HTTP authentication modes",
                    d.name
                )
            }
            if d.basic_password.is_some() && d.basic_username.is_none() {
                bail!(
                    "destination {} has a basic password without a username",
                    d.name
                )
            }
            for pattern in d.include.iter().chain(&d.exclude) {
                globset::Glob::new(pattern)
                    .with_context(|| format!("invalid glob {pattern} for {}", d.name))?;
            }
        }
        if self.server.replay_window_seconds <= 0 {
            bail!("server.replay_window_seconds must be positive")
        }
        if self.tailscale.core_interval_seconds == 0
            || self.tailscale.secondary_interval_seconds == 0
            || self.tailscale.request_timeout_seconds == 0
        {
            bail!("poll and request intervals must be positive")
        }
        if self.tailscale.stale_device.enabled
            && self.tailscale.stale_device.recovery_seconds
                >= self.tailscale.stale_device.threshold_seconds
        {
            bail!("stale_device.recovery_seconds must be less than threshold_seconds")
        }
        if self.delivery.max_attempts == 0 || self.delivery.poll_interval_seconds == 0 {
            bail!("delivery max_attempts and poll_interval_seconds must be positive")
        }
        Ok(())
    }
}

fn resolve_secret(value: &mut Option<String>, file: &Option<PathBuf>) -> Result<()> {
    if value.is_some() && file.is_some() {
        bail!("a secret value and its _file alternative are mutually exclusive")
    }
    if let Some(path) = file {
        *value = Some(
            fs::read_to_string(path)
                .with_context(|| format!("read secret {}", path.display()))?
                .trim_end()
                .to_string(),
        );
    }
    Ok(())
}

fn expand_env(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            bail!("unterminated environment variable expression")
        };
        let name = &after[..end];
        if name.is_empty() || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) {
            bail!("invalid environment variable name {name:?}")
        }
        out.push_str(
            &std::env::var(name)
                .with_context(|| format!("environment variable {name} is not set"))?,
        );
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn duration(seconds: u64) -> Duration {
    Duration::from_secs(seconds.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expands_environment() {
        unsafe { std::env::set_var("TAILSTATE_TEST_VALUE", "hello") };
        assert_eq!(
            expand_env("x-${TAILSTATE_TEST_VALUE}-y").unwrap(),
            "x-hello-y"
        );
    }
}

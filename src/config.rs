//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::agent::AgentState;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Agent runtime configuration loaded from TOML.
///
/// Private keys are stored outside this file (OS keychain or 0600 key file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    pub server_url: String,
    pub agent_id: Option<Uuid>,
    pub agent_state: Option<AgentState>,
    #[serde(default = "default_pull_interval", alias = "poll_interval_secs")]
    pub pull_interval_secs: u64,
    #[serde(default = "default_backoff_max")]
    pub backoff_max_secs: u64,
    #[serde(default = "default_config_path")]
    pub config_path: PathBuf,
    #[serde(default = "default_key_path")]
    pub key_path: PathBuf,
    /// Operator-defined custom tags sent with enrollment and heartbeats.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Ed25519 public key (base64) used to verify signed release artifacts.
    #[serde(default)]
    pub release_public_key_b64: Option<String>,
    /// Previous release pubkey accepted during dual-key overlap.
    #[serde(default)]
    pub release_public_key_previous_b64: Option<String>,
    #[serde(default)]
    pub release_key_overlap_until: Option<String>,
    /// Ed25519 public key (base64) used to verify server-signed pull tasks.
    #[serde(default)]
    pub task_signing_pubkey_b64: Option<String>,
    /// Previous task-signing pubkey accepted during dual-key overlap.
    #[serde(default)]
    pub task_signing_pubkey_previous_b64: Option<String>,
    #[serde(default)]
    pub task_signing_overlap_until: Option<String>,
}

fn default_pull_interval() -> u64 {
    5
}

fn default_backoff_max() -> u64 {
    300
}

fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/hecate-lampad/config.toml")
}

fn default_key_path() -> PathBuf {
    PathBuf::from("/etc/hecate-lampad/agent.key")
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            agent_id: None,
            agent_state: None,
            pull_interval_secs: default_pull_interval(),
            backoff_max_secs: default_backoff_max(),
            config_path: default_config_path(),
            key_path: default_key_path(),
            tags: Vec::new(),
            release_public_key_b64: None,
            release_public_key_previous_b64: None,
            release_key_overlap_until: None,
            task_signing_pubkey_b64: None,
            task_signing_pubkey_previous_b64: None,
            task_signing_overlap_until: None,
        }
    }
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let mut config: AgentConfig = toml::from_str(&content)?;
        config.config_path = path.as_ref().to_path_buf();
        Ok(config)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let nonce = rand::random::<u64>();
        let temp_path = self.config_path.with_file_name(format!(
            ".{}.hecate-tmp-{nonce:016x}",
            self.config_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config.toml")
        ));
        {
            use std::io::Write;
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&temp_path)?;
                file.write_all(content.as_bytes())?;
                file.sync_all()?;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&temp_path)?;
                file.write_all(content.as_bytes())?;
                file.sync_all()?;
            }
            #[cfg(not(any(unix, windows)))]
            {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_path)?;
                file.write_all(content.as_bytes())?;
                file.sync_all()?;
            }
        }
        std::fs::rename(&temp_path, &self.config_path).map_err(|error| {
            let _ = std::fs::remove_file(&temp_path);
            error
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn roundtrip_toml() {
        let file = NamedTempFile::new().unwrap();
        let config = AgentConfig {
            server_url: "https://hecate.example.com".into(),
            agent_id: Some(Uuid::new_v4()),
            ..Default::default()
        };
        let content = toml::to_string_pretty(&config).unwrap();
        std::fs::write(file.path(), content).unwrap();
        let loaded = AgentConfig::load(file.path()).unwrap();
        assert_eq!(loaded.server_url, config.server_url);
        assert_eq!(loaded.agent_id, config.agent_id);
    }
}

//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Pull-session self-repair: reload credentials from disk and reset stale transports.

use crate::config::AgentConfig;
use crate::pull::AgentSessionState;
use crate::signing::AgentKeypair;
use std::path::Path;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Consecutive pull failures before tearing down the session and rebuilding the HTTP client.
pub const MAX_CONSECUTIVE_PULL_FAILURES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileGeneration {
    pub modified_unix: u64,
    pub len: u64,
    /// Content fingerprint for small identity files (detects in-place key rotation).
    pub content_tag: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChange {
    Unchanged,
    KeyUpdated,
    ConfigUpdated,
    ServerIdentityChanged,
}

pub fn file_generation(path: &Path) -> Option<FileGeneration> {
    let meta = std::fs::metadata(path).ok()?;
    let len = meta.len();
    let modified_unix = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(FileGeneration {
        modified_unix,
        len,
        content_tag: content_tag(path, len),
    })
}

fn content_tag(path: &Path, len: u64) -> u64 {
    if len > 4096 {
        return 0;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return 0;
    };
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    u64::from_le_bytes(digest[..8].try_into().unwrap_or([0; 8]))
}

/// Tracks on-disk enrollment material so a running service picks up enroll/re-enroll without restart.
#[derive(Debug, Clone)]
pub struct CredentialWatch {
    key_gen: Option<FileGeneration>,
    config_gen: Option<FileGeneration>,
    server_url: String,
    agent_id: Option<Uuid>,
}

impl CredentialWatch {
    pub fn new(config_path: &Path, key_path: &Path, config: &AgentConfig) -> Self {
        Self {
            key_gen: file_generation(key_path),
            config_gen: file_generation(config_path),
            server_url: config.server_url.clone(),
            agent_id: config.agent_id,
        }
    }

    /// Reload config/key snapshots from disk and report what changed.
    pub fn check(
        &mut self,
        config_path: &Path,
        key_path: &Path,
        config: &mut AgentConfig,
    ) -> CredentialChange {
        let key_gen = file_generation(key_path);
        let config_gen = file_generation(config_path);

        let key_updated = key_gen != self.key_gen;
        let config_updated = config_gen != self.config_gen;

        self.key_gen = key_gen;
        self.config_gen = config_gen;

        if config_updated {
            if let Ok(reloaded) = AgentConfig::load(config_path) {
                *config = reloaded;
            }
        }

        let server_identity_changed = config.server_url != self.server_url
            || config.agent_id != self.agent_id;

        if server_identity_changed {
            self.server_url = config.server_url.clone();
            self.agent_id = config.agent_id;
            return CredentialChange::ServerIdentityChanged;
        }

        if key_updated {
            return CredentialChange::KeyUpdated;
        }

        if config_updated {
            self.server_url = config.server_url.clone();
            self.agent_id = config.agent_id;
            return CredentialChange::ConfigUpdated;
        }

        CredentialChange::Unchanged
    }
}

/// Returns true when the pull session should exit and rebuild its HTTP client + heartbeat thread.
pub fn should_reset_pull_session(
    consecutive_pull_failures: u32,
    session_started: Instant,
    session_state: &AgentSessionState,
    pull_stale_after: Duration,
) -> bool {
    if consecutive_pull_failures >= MAX_CONSECUTIVE_PULL_FAILURES {
        return true;
    }

    if session_state.last_pull_ok_at().is_none()
        && session_started.elapsed() > pull_stale_after.saturating_mul(2)
    {
        return true;
    }

    false
}

pub fn reload_keypair(key_path: &Path) -> Option<AgentKeypair> {
    AgentKeypair::load(key_path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_state_sync::runtime_mode_for_agent_state;
    use crate::config::AgentConfig;
    use tempfile::TempDir;

    fn write_test_config(config_path: &Path, config: &AgentConfig) {
        let mut cfg = config.clone();
        cfg.config_path = config_path.to_path_buf();
        cfg.save().expect("save config");
    }

    #[test]
    fn credential_watch_detects_key_rotation() {
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let key_path = dir.path().join("agent.key");

        AgentKeypair::generate_at(&key_path).expect("save key");

        let config = AgentConfig {
            server_url: "https://hecate.example".into(),
            agent_id: Some(Uuid::new_v4()),
            agent_state: Some(hecate_protocol::agent::AgentState::Active),
            key_path: key_path.clone(),
            ..AgentConfig::default()
        };
        write_test_config(&config_path, &config);

        let mut watch = CredentialWatch::new(&config_path, &key_path, &config);
        assert_eq!(
            watch.check(&config_path, &key_path, &mut config.clone()),
            CredentialChange::Unchanged
        );

        AgentKeypair::regenerate_at(&key_path).expect("rotate key");

        let mut live = config.clone();
        assert_eq!(
            watch.check(&config_path, &key_path, &mut live),
            CredentialChange::KeyUpdated
        );
    }

    #[test]
    fn credential_watch_detects_server_identity_change() {
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let key_path = dir.path().join("agent.key");

        AgentKeypair::generate_at(&key_path).expect("save key");

        let mut config = AgentConfig {
            server_url: "https://hecate.example".into(),
            agent_id: Some(Uuid::new_v4()),
            agent_state: Some(hecate_protocol::agent::AgentState::Active),
            key_path: key_path.clone(),
            ..AgentConfig::default()
        };
        write_test_config(&config_path, &config);

        let mut watch = CredentialWatch::new(&config_path, &key_path, &config);
        assert_eq!(
            watch.check(&config_path, &key_path, &mut config),
            CredentialChange::Unchanged
        );

        config.server_url = "https://hecate-other.example".into();
        write_test_config(&config_path, &config);

        let mut reloaded = AgentConfig::load(&config_path).expect("reload");
        assert_eq!(
            watch.check(&config_path, &key_path, &mut reloaded),
            CredentialChange::ServerIdentityChanged
        );
        assert_eq!(reloaded.server_url, "https://hecate-other.example");
        assert_eq!(
            runtime_mode_for_agent_state(reloaded.agent_state),
            crate::runtime::RuntimeMode::Pulling
        );
    }

    #[test]
    fn reset_after_consecutive_pull_failures() {
        let state = AgentSessionState::new(AgentKeypair::generate(), &[]);
        assert!(!should_reset_pull_session(
            MAX_CONSECUTIVE_PULL_FAILURES - 1,
            Instant::now(),
            state.as_ref(),
            Duration::from_secs(30),
        ));
        assert!(should_reset_pull_session(
            MAX_CONSECUTIVE_PULL_FAILURES,
            Instant::now(),
            state.as_ref(),
            Duration::from_secs(30),
        ));
    }

    #[test]
    fn reset_when_never_pulled_past_grace() {
        let state = AgentSessionState::with_pull_stale_after(
            AgentKeypair::generate(),
            &[],
            Duration::from_millis(30),
        );
        let session_started = Instant::now();
        assert!(!should_reset_pull_session(
            0,
            session_started,
            state.as_ref(),
            Duration::from_millis(30),
        ));
        std::thread::sleep(Duration::from_millis(80));
        assert!(should_reset_pull_session(
            0,
            session_started,
            state.as_ref(),
            Duration::from_millis(30),
        ));
    }
}

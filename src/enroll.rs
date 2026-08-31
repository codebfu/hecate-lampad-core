//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared enrollment helpers.

use crate::client::AgentClient;
use crate::config::AgentConfig;
use crate::paths::secure_agent_paths;
use crate::signing::AgentKeypair;
use hecate_protocol::agent::{AgentState, EnrollRequest, EnrollResponse};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct EnrollmentPrep {
    pub keypair: AgentKeypair,
    pub existing_agent_id: Option<Uuid>,
    pub reenroll: bool,
    /// Previous key material when re-enroll regenerated the key; restored if enrollment fails.
    pub key_backup: Option<KeyBackup>,
}

/// Saved agent key bytes for rollback when re-enroll fails after key regeneration.
pub struct KeyBackup {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

fn backup_agent_key(path: &Path) -> anyhow::Result<KeyBackup> {
    let bytes = if path.exists() {
        Some(std::fs::read(path)?)
    } else {
        None
    };
    Ok(KeyBackup {
        path: path.to_path_buf(),
        bytes,
    })
}

fn restore_agent_key(backup: &KeyBackup) -> anyhow::Result<()> {
    if let Some(bytes) = &backup.bytes {
        std::fs::write(&backup.path, bytes)?;
    } else if backup.path.exists() {
        std::fs::remove_file(&backup.path)?;
    }
    Ok(())
}

pub fn read_enrollment_token(
    token: Option<String>,
    token_file: Option<PathBuf>,
) -> anyhow::Result<String> {
    if let Some(t) = token {
        return Ok(t);
    }
    if let Some(path) = token_file {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    anyhow::bail!("provide --token or --token-file for enrollment")
}

pub fn load_enrollment_keypair(
    key_path: &Path,
    default_key_path: &Path,
    key_path_explicit: bool,
) -> anyhow::Result<AgentKeypair> {
    Ok(AgentKeypair::resolve(
        key_path,
        default_key_path,
        key_path_explicit,
    )?)
}

/// Prepare key material for enroll or re-enroll.
///
/// When an enrolled agent id is already on disk, a fresh Ed25519 key is written
/// so the server can replace credential material atomically.
pub fn prepare_agent_enrollment(
    config_path: &Path,
    key_path: &Path,
    default_key_path: &Path,
    key_path_explicit: bool,
) -> anyhow::Result<EnrollmentPrep> {
    let existing_agent_id = AgentConfig::load(config_path)
        .ok()
        .and_then(|config| config.agent_id);

    if let Some(agent_id) = existing_agent_id {
        let key_backup = backup_agent_key(key_path)?;
        let keypair = AgentKeypair::regenerate_at(key_path)?;
        return Ok(EnrollmentPrep {
            keypair,
            existing_agent_id: Some(agent_id),
            reenroll: true,
            key_backup: Some(key_backup),
        });
    }

    let keypair = load_enrollment_keypair(key_path, default_key_path, key_path_explicit)?;
    Ok(EnrollmentPrep {
        keypair,
        existing_agent_id: None,
        reenroll: false,
        key_backup: None,
    })
}

pub fn build_enroll_request(
    enrollment_token: String,
    keypair: &AgentKeypair,
    hostname: String,
    os: String,
    arch: String,
    tags: Vec<String>,
    agent_id: Option<Uuid>,
) -> EnrollRequest {
    EnrollRequest {
        enrollment_token,
        agent_id,
        public_key: keypair.public_key_base64(),
        hostname,
        os,
        arch,
        tags,
        attestation: serde_json::json!({}),
    }
}

pub async fn submit_enrollment(
    server_url: String,
    config_path: PathBuf,
    key_path: PathBuf,
    request: EnrollRequest,
    config_tags: Vec<String>,
    public_key: &str,
    service_start_hint: &str,
    prior_agent_id: Option<Uuid>,
    reenroll: bool,
    key_backup: Option<KeyBackup>,
) -> anyhow::Result<EnrollResponse> {
    let client = AgentClient::new()?;
    let response = match client.enroll(&server_url, &request).await {
        Ok(response) => response,
        Err(error) => {
            if let Some(backup) = key_backup.as_ref() {
                if let Err(restore_error) = restore_agent_key(backup) {
                    return Err(anyhow::anyhow!(
                        "{error}; additionally failed to restore previous agent key: {restore_error}"
                    ));
                }
            }
            return Err(error.into());
        }
    };

    if let Some(expected) = prior_agent_id {
        if response.agent_id != expected {
            anyhow::bail!(
                "server returned agent_id {} but local config expects {}; \
                 use a machine-bound re-enrollment token from Machines → agent detail",
                response.agent_id,
                expected
            );
        }
    }

    let config = config_from_enrollment(
        server_url,
        config_path.clone(),
        key_path,
        config_tags,
        &response,
    );
    config.save()?;
    secure_agent_paths(&config_path, &config.key_path);

    print_enroll_success(
        &response,
        &config.server_url,
        &config_path,
        public_key,
        service_start_hint,
        reenroll,
    );
    Ok(response)
}

fn config_from_enrollment(
    server_url: String,
    config_path: PathBuf,
    key_path: PathBuf,
    config_tags: Vec<String>,
    response: &EnrollResponse,
) -> AgentConfig {
    AgentConfig {
        server_url,
        agent_id: Some(response.agent_id),
        agent_state: Some(response.state),
        key_path,
        config_path,
        tags: config_tags,
        task_signing_pubkey_b64: Some(response.task_signing_pubkey_b64.clone()),
        release_public_key_b64: response.release_public_key_b64.clone(),
        release_public_key_previous_b64: None,
        release_key_overlap_until: None,
        task_signing_pubkey_previous_b64: None,
        task_signing_overlap_until: None,
        ..AgentConfig::default()
    }
}

pub fn print_enroll_success(
    response: &EnrollResponse,
    server_url: &str,
    config_path: &Path,
    public_key: &str,
    service_start_hint: &str,
    reenroll: bool,
) {
    println!("Enrollment submitted successfully.");
    if reenroll {
        println!("  Mode:       re-enroll (same agent id)");
    }
    println!("  Server:     {server_url}");
    println!("  Agent ID:   {}", response.agent_id);
    println!("  State:      {}", format_agent_state(response.state));
    println!("  Public key: {public_key}");
    println!("  Config:     {}", config_path.display());
    println!();
    if reenroll {
        println!(
            "Re-enroll updated local credentials. Restart the running agent service so it loads the new key:"
        );
        println!("  {service_start_hint}");
        println!();
    }
    match response.state {
        AgentState::PendingApproval => {
            println!("Next: wait for admin approval in the Hecate UI, then verify with:");
            println!("  hecate-lampad status");
            if !reenroll {
                println!("The running agent service will pick up enrollment automatically.");
            }
        }
        AgentState::Active => {
            if reenroll {
                println!("Re-enroll complete. Restart the agent service before expecting pull/sign to succeed.");
            } else {
                println!("Enrollment complete. The running agent service will connect automatically.");
                println!("If the service is not running yet:");
                println!("  {service_start_hint}");
            }
        }
        AgentState::Revoked => {
            println!("Warning: server reported agent state as revoked.");
        }
    }
}

fn format_agent_state(state: AgentState) -> &'static str {
    match state {
        AgentState::PendingApproval => "pending_approval",
        AgentState::Active => "active",
        AgentState::Revoked => "revoked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn config_from_enrollment_persists_release_public_key() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let key_path = dir.path().join("agent.key");
        let agent_id = Uuid::from_u128(42);
        let response = EnrollResponse {
            agent_id,
            machine_id: agent_id,
            state: AgentState::Active,
            task_signing_pubkey_b64: "task-pubkey".into(),
            release_public_key_b64: Some("release-pubkey".into()),
        };

        let config = config_from_enrollment(
            "https://hecate.example.com".into(),
            config_path.clone(),
            key_path,
            vec!["role:lab".into()],
            &response,
        );
        config.save().unwrap();

        let loaded = AgentConfig::load(&config_path).unwrap();
        assert_eq!(loaded.agent_id, Some(agent_id));
        assert_eq!(
            loaded.task_signing_pubkey_b64.as_deref(),
            Some("task-pubkey")
        );
        assert_eq!(
            loaded.release_public_key_b64.as_deref(),
            Some("release-pubkey")
        );
        assert!(loaded.task_signing_pubkey_previous_b64.is_none());
        assert!(loaded.release_public_key_previous_b64.is_none());
    }

    #[test]
    fn config_from_enrollment_allows_missing_release_key() {
        let response = EnrollResponse {
            agent_id: Uuid::nil(),
            machine_id: Uuid::nil(),
            state: AgentState::PendingApproval,
            task_signing_pubkey_b64: "task-pubkey".into(),
            release_public_key_b64: None,
        };
        let config = config_from_enrollment(
            "https://hecate.example.com".into(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/agent.key"),
            Vec::new(),
            &response,
        );
        assert!(config.release_public_key_b64.is_none());
    }

    #[test]
    fn prepare_agent_enrollment_regenerates_when_config_has_agent_id() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let key_path = dir.path().join("agent.key");
        let agent_id = Uuid::new_v4();

        let config = AgentConfig {
            server_url: "https://hecate.example".into(),
            agent_id: Some(agent_id),
            config_path: config_path.clone(),
            key_path: key_path.clone(),
            ..AgentConfig::default()
        };
        config.save().unwrap();
        AgentKeypair::generate_at(&key_path).unwrap();
        let old_pub = AgentKeypair::load(&key_path).unwrap().public_key_base64();

        let prep = prepare_agent_enrollment(&config_path, &key_path, &key_path, true).unwrap();
        assert_eq!(prep.existing_agent_id, Some(agent_id));
        assert!(prep.reenroll);
        assert_ne!(prep.keypair.public_key_base64(), old_pub);
    }

    #[test]
    fn build_enroll_request_includes_agent_id_when_provided() {
        let agent_id = Uuid::new_v4();
        let kp = AgentKeypair::generate();
        let req = build_enroll_request(
            "enr_a".repeat(48),
            &kp,
            "host".into(),
            "linux".into(),
            "x86_64".into(),
            vec![],
            Some(agent_id),
        );
        assert_eq!(req.agent_id, Some(agent_id));
    }
}

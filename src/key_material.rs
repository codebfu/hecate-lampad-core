//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Apply server-advertised key material and rotate agent identity credentials.

use crate::client::{ClientError, HttpPullClient};
use crate::config::AgentConfig;
use crate::signing::AgentKeypair;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hecate_protocol::agent::RotateCredentialRequest;
use hecate_protocol::task::{continuity_message, KeyContinuityAttestation, KeyMaterialPayload};
use std::path::Path;
use tracing::{info, warn};
use uuid::Uuid;

/// Merge pull/update-offer key material into local config and persist when changed.
pub fn apply_key_material(config: &mut AgentConfig, material: &KeyMaterialPayload) -> anyhow::Result<bool> {
    let mut changed = false;

    if let Some(pubkey) = material.task_signing_pubkey_b64.as_ref() {
        if !pubkey.trim().is_empty() {
            match accept_successor_key(
                config.task_signing_pubkey_b64.as_deref(),
                pubkey,
                material.task_signing_pubkey_previous_b64.as_deref(),
                material.task_signing_continuity_sig_b64.as_deref(),
                &material.task_signing_continuity_chain,
            ) {
                AcceptKey::Noop => {}
                AcceptKey::Promote => {
                    if let Some(old) = config.task_signing_pubkey_b64.take() {
                        config.task_signing_pubkey_previous_b64 = Some(old);
                    }
                    config.task_signing_pubkey_b64 = Some(pubkey.clone());
                    changed = true;
                }
                AcceptKey::Reject => {
                    warn!("ignoring untrusted task signing public key from key_material");
                }
            }
        }
    }
    let prev_task = material
        .task_signing_pubkey_previous_b64
        .as_ref()
        .filter(|k| !k.trim().is_empty())
        .cloned();
    if prev_task.is_some() && config.task_signing_pubkey_previous_b64 != prev_task {
        config.task_signing_pubkey_previous_b64 = prev_task;
        changed = true;
    }
    if config.task_signing_overlap_until != material.task_signing_overlap_until {
        config.task_signing_overlap_until = material.task_signing_overlap_until.clone();
        changed = true;
    }

    if let Some(pubkey) = material.release_public_key_b64.as_ref() {
        if !pubkey.trim().is_empty() {
            match accept_successor_key(
                config.release_public_key_b64.as_deref(),
                pubkey,
                material.release_public_key_previous_b64.as_deref(),
                material.release_key_continuity_sig_b64.as_deref(),
                &[],
            ) {
                AcceptKey::Noop => {}
                AcceptKey::Promote => {
                    if let Some(old) = config.release_public_key_b64.take() {
                        if config.release_public_key_previous_b64.as_deref() != Some(old.as_str()) {
                            config.release_public_key_previous_b64 = Some(old);
                        }
                    }
                    config.release_public_key_b64 = Some(pubkey.clone());
                    changed = true;
                }
                AcceptKey::Reject => {
                    warn!("ignoring untrusted release public key from key_material");
                }
            }
        }
    }

    let prev_release = material
        .release_public_key_previous_b64
        .as_ref()
        .filter(|k| !k.trim().is_empty())
        .cloned();
    if prev_release.is_some() && config.release_public_key_previous_b64 != prev_release {
        config.release_public_key_previous_b64 = prev_release;
        changed = true;
    }
    if config.release_key_overlap_until != material.release_key_overlap_until {
        config.release_key_overlap_until = material.release_key_overlap_until.clone();
        changed = true;
    }

    if changed {
        config.save()?;
    }
    Ok(changed)
}

enum AcceptKey {
    Noop,
    Promote,
    Reject,
}

fn accept_successor_key(
    current: Option<&str>,
    candidate: &str,
    advertised_previous: Option<&str>,
    continuity_sig: Option<&str>,
    chain: &[KeyContinuityAttestation],
) -> AcceptKey {
    match current {
        None => AcceptKey::Promote, // TOFU after enroll
        Some(current) if current == candidate => AcceptKey::Noop,
        Some(current) => {
            if advertised_previous == Some(current)
                && continuity_sig.is_some_and(|sig| verify_continuity(current, candidate, sig))
            {
                return AcceptKey::Promote;
            }
            if walk_continuity_chain(current, candidate, chain) {
                return AcceptKey::Promote;
            }
            AcceptKey::Reject
        }
    }
}

fn walk_continuity_chain(
    start: &str,
    target: &str,
    chain: &[KeyContinuityAttestation],
) -> bool {
    let mut cursor = start.to_string();
    for attestation in chain {
        if attestation.previous_pubkey_b64 != cursor {
            continue;
        }
        if !verify_continuity(
            &attestation.previous_pubkey_b64,
            &attestation.successor_pubkey_b64,
            &attestation.signature_b64,
        ) {
            return false;
        }
        cursor = attestation.successor_pubkey_b64.clone();
        if cursor == target {
            return true;
        }
    }
    cursor == target
}

fn verify_continuity(previous_pubkey_b64: &str, successor_pubkey_b64: &str, signature_b64: &str) -> bool {
    let Ok(pk_bytes) = BASE64.decode(previous_pubkey_b64.trim()) else {
        return false;
    };
    let Ok(pk_array) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pk_array) else {
        return false;
    };
    let Ok(sig_bytes) = BASE64.decode(signature_b64.trim()) else {
        return false;
    };
    let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_array);
    let message = continuity_message(previous_pubkey_b64, successor_pubkey_b64);
    verifying.verify(message.as_bytes(), &signature).is_ok()
}

/// Generate a new identity key, register it with the server, and hot-swap local key files.
pub async fn rotate_agent_credential(
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &mut AgentKeypair,
    key_path: &Path,
) -> Result<(), CredentialRotateError> {
    let next_path = key_path.with_extension("key.next");
    let previous_path = key_path.with_extension("key.previous");

    let new_keypair =
        AgentKeypair::generate_at(&next_path).map_err(|e| CredentialRotateError::Io(e.to_string()))?;
    let new_public_key = new_keypair.public_key_base64();

    let response = client
        .rotate_credentials(agent_id, keypair, &RotateCredentialRequest { new_public_key })
        .await
        .map_err(CredentialRotateError::Request)?;

    if !response.ok {
        let _ = std::fs::remove_file(&next_path);
        return Err(CredentialRotateError::Rejected);
    }

    if key_path.exists() {
        let _ = std::fs::rename(key_path, &previous_path);
    }
    std::fs::rename(&next_path, key_path).map_err(|e| CredentialRotateError::Io(e.to_string()))?;
    *keypair = new_keypair;
    info!(
        previous_expires_at = ?response.previous_expires_at,
        "agent identity credential rotated"
    );
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialRotateError {
    #[error("credential rotation request failed: {0}")]
    Request(ClientError),
    #[error("server rejected credential rotation")]
    Rejected,
    #[error("io error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn apply_key_material_tofu_task_key_when_empty() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut config = AgentConfig {
            server_url: "https://hecate.example".into(),
            config_path: config_path.clone(),
            release_public_key_b64: Some("old-key".into()),
            ..Default::default()
        };
        config.save().unwrap();

        let material = KeyMaterialPayload {
            release_public_key_b64: Some("old-key".into()),
            task_signing_pubkey_b64: Some("task-new".into()),
            ..Default::default()
        };
        assert!(apply_key_material(&mut config, &material).unwrap());
        assert_eq!(config.task_signing_pubkey_b64.as_deref(), Some("task-new"));
    }

    #[test]
    fn apply_key_material_rejects_untrusted_release_key() {
        let dir = TempDir::new().unwrap();
        let mut config = AgentConfig {
            server_url: "https://hecate.example".into(),
            config_path: dir.path().join("config.toml"),
            release_public_key_b64: Some("known".into()),
            ..Default::default()
        };
        config.save().unwrap();
        let material = KeyMaterialPayload {
            release_public_key_b64: Some("attacker".into()),
            release_public_key_previous_b64: Some("other".into()),
            ..Default::default()
        };
        let _ = apply_key_material(&mut config, &material).unwrap();
        assert_eq!(config.release_public_key_b64.as_deref(), Some("known"));
    }

    #[test]
    fn apply_key_material_rejects_untrusted_task_signing_key() {
        let dir = TempDir::new().unwrap();
        let mut config = AgentConfig {
            server_url: "https://hecate.example".into(),
            config_path: dir.path().join("config.toml"),
            task_signing_pubkey_b64: Some("known-task".into()),
            ..Default::default()
        };
        config.save().unwrap();
        let material = KeyMaterialPayload {
            task_signing_pubkey_b64: Some("attacker".into()),
            task_signing_pubkey_previous_b64: Some("other".into()),
            ..Default::default()
        };
        let _ = apply_key_material(&mut config, &material).unwrap();
        assert_eq!(config.task_signing_pubkey_b64.as_deref(), Some("known-task"));
    }
}

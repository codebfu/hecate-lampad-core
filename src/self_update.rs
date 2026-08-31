//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Self-update helpers shared by the pull loop and the CLI `update` command.

use std::path::Path;
use std::time::Duration;

use hecate_protocol::task::AgentTask;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::client::HttpPullClient;
use crate::config::AgentConfig;
use crate::package_update::{uses_installer_packages, wait_for_installer_stop};
use crate::signing::AgentKeypair;
use crate::updater::{perform_self_update, SelfUpdateParams, UpdaterError};

pub fn task_signing_keys(config: &AgentConfig) -> Vec<&str> {
    std::iter::once(config.task_signing_pubkey_b64.as_deref())
        .chain(std::iter::once(
            config.task_signing_pubkey_previous_b64.as_deref(),
        ))
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .collect()
}

pub fn verify_self_update_envelope(
    config: &AgentConfig,
    machine_id: Uuid,
    kind: &str,
    artifact_path: &str,
    sha256: &str,
    target_version: &str,
    server_task_sig: &str,
) -> Result<(), SelfUpdateError> {
    crate::updater::validate_release_artifact_path(artifact_path)
        .map_err(|error| SelfUpdateError::Apply(error))?;
    let keys = task_signing_keys(config);
    crate::task_verify::verify_self_update_task_sig(
        &keys,
        server_task_sig,
        machine_id,
        kind,
        artifact_path,
        sha256,
        target_version,
    )
    .map_err(|error| SelfUpdateError::Apply(UpdaterError::Aborted(error)))
}

#[derive(Debug, Error)]
pub enum SelfUpdateError {
    #[error("agent is not enrolled: {0}")]
    NotEnrolled(String),
    #[error("self-update failed: {0}")]
    Apply(#[from] UpdaterError),
    #[error("release signing public key is not configured on the agent or server")]
    ReleaseKeyMissing,
}

pub async fn apply_self_update_task(
    task: &AgentTask,
    config: &AgentConfig,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    server_url: &str,
) -> Result<(), SelfUpdateError> {
    let AgentTask::SelfUpdate {
        target_version,
        artifact_path,
        sha256,
        signature,
        release_public_key_b64,
        server_task_sig,
    } = task
    else {
        return Err(SelfUpdateError::NotEnrolled(
            "expected SelfUpdate task".into(),
        ));
    };

    crate::self_update::verify_self_update_envelope(
        config,
        agent_id,
        "self_update",
        artifact_path,
        sha256,
        target_version,
        server_task_sig,
    )?;

    let release_public_key_b64 = release_public_key_b64
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config.release_public_key_b64.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or(SelfUpdateError::ReleaseKeyMissing)?;

    let params = SelfUpdateParams {
        server_url: server_url.to_string(),
        target_version: target_version.clone(),
        artifact_path: artifact_path.clone(),
        sha256: sha256.clone(),
        signature: signature.clone(),
        release_public_key_b64: release_public_key_b64.to_string(),
        release_public_key_previous_b64: config.release_public_key_previous_b64.clone(),
        install_path: None,
        kind: "self_update".into(),
        server_task_sig: server_task_sig.clone(),
    };

    perform_self_update(&params, Some(client), agent_id, keypair)
        .await
        .map_err(SelfUpdateError::Apply)
}

pub async fn apply_self_update_task_or_log(
    task: AgentTask,
    config: &AgentConfig,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    server_url: &str,
) {
    let AgentTask::SelfUpdate { target_version, .. } = &task else {
        return;
    };

    match apply_self_update_task(&task, config, client, agent_id, keypair, server_url).await {
        Ok(()) => {
            if uses_installer_packages() {
                info!(
                    %target_version,
                    "package installer launched; waiting for service stop"
                );
                // Do not exit(0): Restart=always would respawn the old binary
                // while dpkg/msiexec is still running. The installer stops us.
                wait_for_installer_stop(Duration::from_secs(120));
            } else {
                info!(%target_version, "self-update applied; exiting for service restart");
                crate::service_restart::schedule_restart_after_self_update();
                std::process::exit(0);
            }
        }
        Err(error) => {
            warn!(%target_version, error = %error, "self-update failed");
        }
    }
}

pub fn load_enrolled_agent(
    config_path: &Path,
    key_path: &Path,
) -> Result<(AgentConfig, Uuid, AgentKeypair), SelfUpdateError> {
    let config = AgentConfig::load(config_path).map_err(|error| {
        SelfUpdateError::NotEnrolled(format!("failed to load config: {error}"))
    })?;

    let Some(agent_id) = config.agent_id else {
        return Err(SelfUpdateError::NotEnrolled(
            "agent_id not set — run enroll first".into(),
        ));
    };

    if config.agent_state == Some(hecate_protocol::agent::AgentState::Revoked) {
        return Err(SelfUpdateError::NotEnrolled(
            "agent credential is revoked".into(),
        ));
    }

    if !key_path.exists() {
        return Err(SelfUpdateError::NotEnrolled(format!(
            "agent key not found at {}",
            key_path.display()
        )));
    }

    let keypair = AgentKeypair::load(key_path).map_err(|error| {
        SelfUpdateError::NotEnrolled(format!("failed to load agent key: {error}"))
    })?;

    Ok((config, agent_id, keypair))
}

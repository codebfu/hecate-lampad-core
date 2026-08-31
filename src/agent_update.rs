//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! CLI `update` command: check for and apply a server release.

use std::path::PathBuf;
use std::time::Duration;

use hecate_protocol::agent::{DesktopUpdateOffer, ProxmoxUpdateOffer, UpdateOfferResponse};
use hecate_protocol::command::CommandResultPayload;
use hecate_protocol::task::AgentTask;
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

use crate::client::{AgentClient, HttpPullClient, UPDATE_OFFER_PATH};
use crate::config::AgentConfig;
use crate::desktop_update::{
    find_desktop_binary, installed_desktop_version, invalidate_desktop_version_cache,
};
use crate::package_update::{
    apply_package_update_blocking, launch_package_updates, uses_installer_packages,
    wait_for_installer_stop,
};
use crate::proxmox_update::{
    find_proxmox_binary, installed_proxmox_version, invalidate_proxmox_version_cache,
};
use crate::self_update::{apply_self_update_task, load_enrolled_agent, SelfUpdateError};
use crate::signing::{AgentKeypair, SignedRequestHeaders};
use crate::updater::{perform_binary_self_update, SelfUpdateParams};
use crate::AGENT_VERSION;

#[derive(Debug, Error)]
pub enum AgentUpdateCliError {
    #[error(transparent)]
    NotEnrolled(#[from] SelfUpdateError),
    #[error("server request failed: {0}")]
    Server(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("desktop update failed: {0}")]
    Desktop(String),
    #[error("agent update failed: {0}")]
    Agent(String),
}

pub struct AgentUpdateOptions {
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub check_only: bool,
}

pub async fn run_agent_update(options: AgentUpdateOptions) -> Result<(), AgentUpdateCliError> {
    let (config, agent_id, keypair) =
        load_enrolled_agent(&options.config_path, &options.key_path)?;

    let client = HttpPullClient::new(config.server_url.clone())
        .map_err(|error| AgentUpdateCliError::Server(error.to_string()))?;

    let offer = fetch_update_offer(&client, agent_id, &keypair).await?;

    if options.check_only {
        print_check_result(&offer);
        if offer.available {
            return Ok(());
        }
        return Err(AgentUpdateCliError::Unavailable(
            offer
                .reason
                .unwrap_or_else(|| "no update available".into()),
        ));
    }

    if !offer.available {
        return Err(AgentUpdateCliError::Unavailable(
            offer
                .reason
                .unwrap_or_else(|| "no update available".into()),
        ));
    }

    let summary = apply_offer(&offer, &config, &client, agent_id, &keypair).await?;
    println!("{summary}");
    Ok(())
}

pub async fn run_agent_update_command(
    config: &AgentConfig,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
) -> CommandResultPayload {
    match apply_agent_update(config, client, agent_id, keypair).await {
        Ok(summary) => CommandResultPayload {
            command_id,
            stdout: summary,
            stderr: String::new(),
            exit_code: Some(0),
            truncated: false,
        },
        Err(error) => CommandResultPayload {
            command_id,
            stdout: String::new(),
            stderr: error.to_string(),
            exit_code: Some(1),
            truncated: false,
        },
    }
}

async fn apply_agent_update(
    config: &AgentConfig,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
) -> Result<String, AgentUpdateCliError> {
    let offer = fetch_update_offer(client, agent_id, keypair).await?;
    if !offer.available {
        return Err(AgentUpdateCliError::Unavailable(
            offer
                .reason
                .unwrap_or_else(|| "no update available".into()),
        ));
    }

    apply_offer(&offer, config, client, agent_id, keypair).await
}

async fn apply_offer(
    offer: &UpdateOfferResponse,
    config: &AgentConfig,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
) -> Result<String, AgentUpdateCliError> {
    let mut config = config.clone();
    if let Some(material) = offer.key_material.as_ref() {
        let _ = crate::key_material::apply_key_material(&mut config, material);
    } else if let Some(key) = offer.release_public_key_b64.as_ref() {
        let material = hecate_protocol::task::KeyMaterialPayload {
            release_public_key_b64: Some(key.clone()),
            ..Default::default()
        };
        let _ = crate::key_material::apply_key_material(&mut config, &material);
    }

    let mut agent_updated = false;
    let mut desktop_updated = false;
    let mut proxmox_updated = false;
    let mut agent_target = None;
    let mut desktop_target = None;
    let mut proxmox_target = None;
    let mut installer_launched = false;

    let desktop_offer = offer.desktop.as_ref().filter(|desktop| desktop.available);
    let proxmox_offer = offer.proxmox.as_ref().filter(|proxmox| proxmox.available);
    let agent_available = offer.artifact_path.is_some();

    if uses_installer_packages() {
        let mut packages = Vec::new();

        if let Some(desktop) = desktop_offer {
            packages.push(desktop_params(desktop, offer, &config)?);
            desktop_target = desktop.target_version.clone();
            desktop_updated = true;
        }

        if let Some(proxmox) = proxmox_offer {
            packages.push(proxmox_params(proxmox, offer, &config)?);
            proxmox_target = proxmox.target_version.clone();
            proxmox_updated = true;
        }

        if agent_available {
            let task = offer_to_task(offer)?;
            let target = offer
                .target_version
                .clone()
                .unwrap_or_else(|| "unknown".into());
            info!(
                current = %offer.current_version,
                %target,
                "applying agent package update"
            );
            println!(
                "Updating agent {} -> {}…",
                offer.current_version, target
            );
            packages.push(agent_params_from_task(&task, &config)?);
            agent_updated = true;
            agent_target = Some(target);
        }

        if packages.is_empty() {
            return Err(AgentUpdateCliError::Unavailable(
                "update offer had no applyable artifacts".into(),
            ));
        }

        if agent_updated {
            // Helpers then agent in one detached install; installer stops the service.
            if desktop_updated {
                println!(
                    "Updating desktop helper{}…",
                    desktop_target
                        .as_deref()
                        .map(|v| format!(" -> {v}"))
                        .unwrap_or_default()
                );
            }
            if proxmox_updated {
                println!(
                    "Updating proxmox helper{}…",
                    proxmox_target
                        .as_deref()
                        .map(|v| format!(" -> {v}"))
                        .unwrap_or_default()
                );
            }
            launch_package_updates(&packages, Some(client), agent_id, keypair)
                .await
                .map_err(|error| AgentUpdateCliError::Agent(error.to_string()))?;
            installer_launched = true;
            invalidate_desktop_version_cache();
            invalidate_proxmox_version_cache();
        } else if packages.len() == 1 {
            if desktop_updated {
                println!(
                    "Updating desktop helper{}…",
                    desktop_target
                        .as_deref()
                        .map(|v| format!(" -> {v}"))
                        .unwrap_or_default()
                );
            }
            if proxmox_updated {
                println!(
                    "Updating proxmox helper{}…",
                    proxmox_target
                        .as_deref()
                        .map(|v| format!(" -> {v}"))
                        .unwrap_or_default()
                );
            }
            apply_package_update_blocking(&packages[0], Some(client), agent_id, keypair)
                .await
                .map_err(|error| AgentUpdateCliError::Desktop(error.to_string()))?;
            invalidate_desktop_version_cache();
            invalidate_proxmox_version_cache();
        } else {
            launch_package_updates(&packages, Some(client), agent_id, keypair)
                .await
                .map_err(|error| AgentUpdateCliError::Agent(error.to_string()))?;
            installer_launched = true;
            invalidate_desktop_version_cache();
            invalidate_proxmox_version_cache();
        }
    } else {
        // macOS (and other binary-replace platforms).
        if agent_available {
            let task = offer_to_task(offer)?;
            let target = offer
                .target_version
                .clone()
                .unwrap_or_else(|| "unknown".into());
            info!(
                current = %offer.current_version,
                %target,
                "applying agent update"
            );
            println!(
                "Updating agent {} -> {}…",
                offer.current_version, target
            );
            apply_self_update_task(
                &task,
                &config,
                client,
                agent_id,
                keypair,
                &config.server_url,
            )
            .await?;
            agent_updated = true;
            agent_target = Some(target);
        }

        if let Some(desktop) = desktop_offer {
            apply_desktop_binary_update(desktop, offer, &config, client, agent_id, keypair).await?;
            invalidate_desktop_version_cache();
            desktop_updated = true;
            desktop_target = desktop.target_version.clone();
        }

        if !agent_updated && !desktop_updated && !proxmox_updated {
            return Err(AgentUpdateCliError::Unavailable(
                "update offer had no applyable artifacts".into(),
            ));
        }
    }

    if agent_updated && installer_launched {
        info!("package installer launched; service will restart via the installer");
        println!(
            "Agent package installer launched. The service will restart when the install finishes."
        );
    } else if agent_updated {
        info!("self-update applied; restart the agent service");
        println!("Agent update applied. Restart the hecate-lampad service to run the new version.");
    }
    if desktop_updated {
        println!(
            "Desktop helper update{}{}.",
            if installer_launched && agent_updated {
                " queued"
            } else {
                " applied"
            },
            desktop_target
                .as_deref()
                .map(|v| format!(" ({v})"))
                .unwrap_or_default()
        );
    }
    if proxmox_updated {
        println!(
            "Proxmox helper update{}{}.",
            if installer_launched && agent_updated {
                " queued"
            } else {
                " applied"
            },
            proxmox_target
                .as_deref()
                .map(|v| format!(" ({v})"))
                .unwrap_or_default()
        );
    }

    // Binary replace requires process exit; package install must NOT exit (Restart=always).
    let restart_required = agent_updated && !installer_launched;

    Ok(format!(
        "{{\"current_version\":\"{}\",\"target_version\":{},\"desktop_target_version\":{},\"proxmox_target_version\":{},\"agent_updated\":{},\"desktop_updated\":{},\"proxmox_updated\":{},\"restart_required\":{},\"installer_launched\":{}}}",
        offer.current_version,
        json_opt_str(agent_target.as_deref()),
        json_opt_str(desktop_target.as_deref()),
        json_opt_str(proxmox_target.as_deref()),
        agent_updated,
        desktop_updated,
        proxmox_updated,
        restart_required,
        installer_launched
    ))
}

fn agent_params_from_task(
    task: &AgentTask,
    config: &AgentConfig,
) -> Result<SelfUpdateParams, AgentUpdateCliError> {
    let AgentTask::SelfUpdate {
        target_version,
        artifact_path,
        sha256,
        signature,
        release_public_key_b64,
        server_task_sig,
    } = task
    else {
        return Err(AgentUpdateCliError::Unavailable(
            "expected SelfUpdate task".into(),
        ));
    };

    crate::self_update::verify_self_update_envelope(
        config,
        config.agent_id.unwrap_or_default(),
        "self_update",
        artifact_path,
        sha256,
        target_version,
        server_task_sig,
    )
    .map_err(AgentUpdateCliError::NotEnrolled)?;

    let release_public_key_b64 = release_public_key_b64
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config.release_public_key_b64.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or(AgentUpdateCliError::NotEnrolled(SelfUpdateError::ReleaseKeyMissing))?;

    Ok(SelfUpdateParams {
        server_url: config.server_url.clone(),
        target_version: target_version.clone(),
        artifact_path: artifact_path.clone(),
        sha256: sha256.clone(),
        signature: signature.clone(),
        release_public_key_b64: release_public_key_b64.to_string(),
        release_public_key_previous_b64: config.release_public_key_previous_b64.clone(),
        install_path: None,
        kind: "self_update".into(),
        server_task_sig: server_task_sig.clone(),
    })
}

fn desktop_params(
    desktop: &DesktopUpdateOffer,
    offer: &UpdateOfferResponse,
    config: &AgentConfig,
) -> Result<SelfUpdateParams, AgentUpdateCliError> {
    // Prefer a known install path for staging; package installs can proceed even
    // when the binary is temporarily missing (orphaned/partial installs).
    let install_path = find_desktop_binary().or_else(|| {
        crate::desktop_update::desktop_binary_candidates()
            .into_iter()
            .next()
    });
    let target = desktop
        .target_version
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing desktop target version".into()))?;
    let artifact_path = desktop
        .artifact_path
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing desktop artifact path".into()))?;
    let sha256 = desktop
        .sha256
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing desktop artifact hash".into()))?;
    let signature = desktop
        .signature
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing desktop release signature".into()))?;
    let release_public_key_b64 = offer
        .release_public_key_b64
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config.release_public_key_b64.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or(AgentUpdateCliError::NotEnrolled(SelfUpdateError::ReleaseKeyMissing))?;

    crate::self_update::verify_self_update_envelope(
        config,
        config.agent_id.unwrap_or_default(),
        "desktop_update",
        &artifact_path,
        &sha256,
        &target,
        desktop.server_task_sig.as_deref().unwrap_or(""),
    )
    .map_err(AgentUpdateCliError::NotEnrolled)?;

    Ok(SelfUpdateParams {
        server_url: config.server_url.clone(),
        target_version: target,
        artifact_path,
        sha256,
        signature,
        release_public_key_b64: release_public_key_b64.to_string(),
        release_public_key_previous_b64: config.release_public_key_previous_b64.clone(),
        install_path,
        kind: "desktop_update".into(),
        server_task_sig: desktop.server_task_sig.clone().unwrap_or_default(),
    })
}

fn proxmox_params(
    proxmox: &ProxmoxUpdateOffer,
    offer: &UpdateOfferResponse,
    config: &AgentConfig,
) -> Result<SelfUpdateParams, AgentUpdateCliError> {
    let install_path = find_proxmox_binary().or_else(|| {
        crate::proxmox_update::proxmox_binary_candidates()
            .into_iter()
            .next()
    });
    let target = proxmox
        .target_version
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing proxmox target version".into()))?;
    let artifact_path = proxmox
        .artifact_path
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing proxmox artifact path".into()))?;
    let sha256 = proxmox
        .sha256
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing proxmox artifact hash".into()))?;
    let signature = proxmox
        .signature
        .clone()
        .ok_or_else(|| AgentUpdateCliError::Desktop("missing proxmox release signature".into()))?;
    let release_public_key_b64 = offer
        .release_public_key_b64
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config.release_public_key_b64.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or(AgentUpdateCliError::NotEnrolled(SelfUpdateError::ReleaseKeyMissing))?;

    crate::self_update::verify_self_update_envelope(
        config,
        config.agent_id.unwrap_or_default(),
        "proxmox_update",
        &artifact_path,
        &sha256,
        &target,
        proxmox.server_task_sig.as_deref().unwrap_or(""),
    )
    .map_err(AgentUpdateCliError::NotEnrolled)?;

    Ok(SelfUpdateParams {
        server_url: config.server_url.clone(),
        target_version: target,
        artifact_path,
        sha256,
        signature,
        release_public_key_b64: release_public_key_b64.to_string(),
        release_public_key_previous_b64: config.release_public_key_previous_b64.clone(),
        install_path,
        kind: "proxmox_update".into(),
        server_task_sig: proxmox.server_task_sig.clone().unwrap_or_default(),
    })
}

async fn apply_desktop_binary_update(
    desktop: &DesktopUpdateOffer,
    offer: &UpdateOfferResponse,
    config: &AgentConfig,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
) -> Result<(), AgentUpdateCliError> {
    let params = desktop_params(desktop, offer, config)?;
    let current = desktop
        .current_version
        .clone()
        .unwrap_or_else(|| "unknown".into());
    info!(
        %current,
        target = %params.target_version,
        path = %params.install_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
        "applying desktop helper binary update"
    );
    println!(
        "Updating desktop helper {current} -> {}…",
        params.target_version
    );

    perform_binary_self_update(&params, Some(client), agent_id, keypair)
        .await
        .map_err(|error| AgentUpdateCliError::Desktop(error.to_string()))
}

async fn fetch_update_offer(
    client: &HttpPullClient,
    agent_id: uuid::Uuid,
    keypair: &crate::signing::AgentKeypair,
) -> Result<UpdateOfferResponse, AgentUpdateCliError> {
    let body = hecate_protocol::agent::UpdateOfferRequest {
        agent_version: AGENT_VERSION.to_string(),
        desktop_version: installed_desktop_version(),
        proxmox_version: installed_proxmox_version(),
    };
    let body_bytes =
        serde_json::to_vec(&body).map_err(|error| AgentUpdateCliError::Server(error.to_string()))?;
    let headers = SignedRequestHeaders::new(
        agent_id,
        keypair,
        "POST",
        UPDATE_OFFER_PATH,
        &body_bytes,
    );
    let url = format!(
        "{}{}",
        AgentClient::normalize_base_url(client.server_url()),
        UPDATE_OFFER_PATH
    );
    let response = headers
        .apply_to_request(
            client
                .http_client()
                .post(url)
                .header("content-type", "application/json")
                .body(body_bytes),
        )
        .send()
        .await
        .map_err(|error| AgentUpdateCliError::Server(error.to_string()))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| AgentUpdateCliError::Server(error.to_string()))?;
    if !status.is_success() {
        return Err(AgentUpdateCliError::Server(format!("HTTP {status}: {text}")));
    }

    serde_json::from_str(&text).map_err(|error| AgentUpdateCliError::Server(error.to_string()))
}

fn offer_to_task(offer: &UpdateOfferResponse) -> Result<AgentTask, AgentUpdateCliError> {
    Ok(AgentTask::SelfUpdate {
        target_version: offer
            .target_version
            .clone()
            .ok_or_else(|| AgentUpdateCliError::Unavailable("missing target version".into()))?,
        artifact_path: offer
            .artifact_path
            .clone()
            .ok_or_else(|| AgentUpdateCliError::Unavailable("missing artifact path".into()))?,
        sha256: offer
            .sha256
            .clone()
            .ok_or_else(|| AgentUpdateCliError::Unavailable("missing artifact hash".into()))?,
        signature: offer
            .signature
            .clone()
            .ok_or_else(|| AgentUpdateCliError::Unavailable("missing release signature".into()))?,
        release_public_key_b64: offer.release_public_key_b64.clone(),
        server_task_sig: offer.server_task_sig.clone().unwrap_or_default(),
    })
}

fn print_check_result(offer: &UpdateOfferResponse) {
    if offer.available {
        if offer.artifact_path.is_some() {
            let target = offer.target_version.as_deref().unwrap_or("unknown");
            println!(
                "Agent update available: {} -> {}",
                offer.current_version, target
            );
        }
        if let Some(desktop) = &offer.desktop {
            if desktop.available {
                println!(
                    "Desktop helper update available: {} -> {}",
                    desktop.current_version.as_deref().unwrap_or("unknown"),
                    desktop.target_version.as_deref().unwrap_or("unknown")
                );
            }
        }
        return;
    }

    if let Some(reason) = &offer.reason {
        println!("No update available: {reason}");
    } else {
        println!("No update available.");
    }
}

fn json_opt_str(value: Option<&str>) -> String {
    match value {
        Some(v) => format!("\"{v}\""),
        None => "null".into(),
    }
}

/// Used by the service loop after a successful agent.update that launched an installer.
pub fn installer_launched_after_update(stdout: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|value| value.get("installer_launched")?.as_bool())
        .unwrap_or(false)
}

pub fn wait_after_installer_launch() {
    wait_for_installer_stop(Duration::from_secs(120));
}

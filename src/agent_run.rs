//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Long-running agent service: idle until enrolled, then pull loop.

use crate::agent_update::{
    installer_launched_after_update, run_agent_update_command, wait_after_installer_launch,
};
use crate::client::HttpPullClient;
use crate::commands::desktop::{
    run_desktop_clipboard_get_command, run_desktop_clipboard_set_command, run_desktop_info_command,
    run_desktop_json_command, run_desktop_screenshot_command, run_desktop_session_frame_command,
};
use crate::commands::proxmox::{
    run_proxmox_console_frame_command, run_proxmox_info_command, run_proxmox_json_command,
};
use crate::commands::file_pull::run_file_pull_command;
use crate::commands::file_push::run_file_push_command;
use crate::commands::remote_download::run_remote_download_command;
use crate::commands::system_reboot::run_system_reboot_command;
use crate::commands::{CommandContext, CommandRegistry, DefaultCommandRegistry};
use crate::config::AgentConfig;
use crate::desktop_ipc::client::DesktopIpcClient;
use crate::desktop_ipc::{collect_gui_tags, helper_package_installed};
use crate::proxmox_ipc::client::ProxmoxIpcClient;
use crate::proxmox_ipc::{
    collect_proxmox_tags, helper_package_installed as proxmox_helper_package_installed,
};
use crate::policy::AgentPolicy;
use crate::pull::{HeartbeatThread, PullConfig, PullError, PullLoop};
use crate::runtime::{write_runtime_status, RuntimeMode, IDLE_POLL_INTERVAL};
use crate::signing::AgentKeypair;
use crate::tags::collect_agent_tags;
use crate::AGENT_VERSION;
use hecate_protocol::agent::AgentState;
use hecate_protocol::command::CommandResultPayload;
use hecate_protocol::task::AgentTask;
use crate::self_update::apply_self_update_task_or_log;
use crate::key_material::{apply_key_material, rotate_agent_credential};
use crate::task_verify::verify_server_task_sig_any;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

enum AgentReadiness {
    Ready {
        config: AgentConfig,
        agent_id: Uuid,
        keypair: AgentKeypair,
        mode: RuntimeMode,
    },
    Waiting {
        mode: RuntimeMode,
        detail: Option<String>,
    },
}

pub struct AgentRunOptions {
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub runtime_status_path: PathBuf,
}

pub async fn run_agent_service(options: AgentRunOptions) -> ! {
    let started_at = Instant::now();
    info!(version = AGENT_VERSION, "agent service starting");

    loop {
        match assess_readiness(&options.config_path, &options.key_path) {
            AgentReadiness::Waiting { mode, detail } => {
                if let Err(error) = write_runtime_status(
                    &options.runtime_status_path,
                    mode,
                    started_at,
                    detail.clone(),
                ) {
                    warn!(error = %error, "failed to write runtime status");
                }
                info!(
                    mode = format_runtime_mode(mode),
                    detail = detail.as_deref().unwrap_or(""),
                    "waiting for enrollment"
                );
                tokio::time::sleep(IDLE_POLL_INTERVAL).await;
            }
            AgentReadiness::Ready {
                mut config,
                agent_id,
                keypair,
                mode,
            } => {
                config.key_path = options.key_path.clone();
                if let Err(error) = write_runtime_status(
                    &options.runtime_status_path,
                    mode,
                    started_at,
                    None,
                ) {
                    warn!(error = %error, "failed to write runtime status");
                }

                run_pull_session(
                    &options.runtime_status_path,
                    started_at,
                    mode,
                    &config,
                    agent_id,
                    keypair,
                )
                .await;
            }
        }
    }
}

fn assess_readiness(config_path: &Path, key_path: &Path) -> AgentReadiness {
    if !config_path.exists() {
        return AgentReadiness::Waiting {
            mode: RuntimeMode::WaitingForEnrollment,
            detail: Some(format!("config not found: {}", config_path.display())),
        };
    }

    let config = match AgentConfig::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            return AgentReadiness::Waiting {
                mode: RuntimeMode::ConfigInvalid,
                detail: Some(error.to_string()),
            };
        }
    };

    let Some(agent_id) = config.agent_id else {
        return AgentReadiness::Waiting {
            mode: RuntimeMode::WaitingForEnrollment,
            detail: Some("agent_id not set — run enroll".into()),
        };
    };

    if !key_path.exists() {
        return AgentReadiness::Waiting {
            mode: RuntimeMode::WaitingForEnrollment,
            detail: Some(format!("agent key not found: {}", key_path.display())),
        };
    }

    let keypair = match AgentKeypair::load(key_path) {
        Ok(keypair) => keypair,
        Err(error) => {
            return AgentReadiness::Waiting {
                mode: RuntimeMode::WaitingForEnrollment,
                detail: Some(error.to_string()),
            };
        }
    };

    let mode = if config.agent_state == Some(AgentState::PendingApproval) {
        RuntimeMode::PendingApproval
    } else {
        RuntimeMode::Pulling
    };

    AgentReadiness::Ready {
        config,
        agent_id,
        keypair,
        mode,
    }
}

async fn run_pull_session(
    runtime_status_path: &Path,
    started_at: Instant,
    mode: RuntimeMode,
    config: &AgentConfig,
    agent_id: Uuid,
    keypair: AgentKeypair,
) {
    let pull_config = PullConfig::from_agent_config(config);
    let registry = Arc::new(DefaultCommandRegistry::with_builtins());

    let client = match HttpPullClient::new(config.server_url.clone()) {
        Ok(client) => client,
        Err(error) => {
            warn!(error = %error, "failed to create pull client");
            tokio::time::sleep(IDLE_POLL_INTERVAL).await;
            return;
        }
    };
    let submit_client = client.clone();

    let pull_loop = PullLoop::new(
        client,
        agent_id,
        keypair,
        pull_config.clone(),
        &config.tags,
    );
    // Heartbeats run on a dedicated OS thread so long-running commands (e.g. shell.run)
    // cannot starve last_seen_at updates and mark the agent offline.
    let _heartbeat = HeartbeatThread::spawn(
        submit_client.clone(),
        agent_id,
        pull_loop.session_state(),
        pull_config.interval,
    );
    info!(agent_id = %agent_id, version = AGENT_VERSION, "entering pull loop");

    let mut last_gui_tags: Option<Vec<String>> = None;
    let mut last_proxmox_tags: Option<Vec<String>> = None;
    let mut config = config.clone();

    loop {
        if let Err(error) = write_runtime_status(runtime_status_path, mode, started_at, None) {
            warn!(error = %error, "failed to refresh runtime status");
        }

        // Refresh gui/display tags when helper connectivity changes.
        if helper_package_installed() {
            let info = DesktopIpcClient::default().try_info().await;
            let gui_tags = collect_gui_tags(info.as_ref());
            if last_gui_tags.as_ref() != Some(&gui_tags) {
                if let Ok(base) = collect_agent_tags(&config.tags) {
                    let mut merged: Vec<String> = base
                        .into_iter()
                        .filter(|tag| {
                            !tag.starts_with("gui:")
                                && !tag.starts_with("display:")
                                && !tag.starts_with("proxmox:")
                        })
                        .collect();
                    merged.extend(gui_tags.clone());
                    if let Some(proxmox_tags) = last_proxmox_tags.as_ref() {
                        merged.extend(proxmox_tags.iter().cloned());
                    }
                    merged.sort();
                    merged.dedup();
                    pull_loop.queue_tag_refresh(merged);
                }
                last_gui_tags = Some(gui_tags);
            }
        }

        if proxmox_helper_package_installed() {
            let info = ProxmoxIpcClient::default().try_info().await;
            let proxmox_tags = collect_proxmox_tags(info.as_ref());
            if last_proxmox_tags.as_ref() != Some(&proxmox_tags) {
                if let Ok(base) = collect_agent_tags(&config.tags) {
                    let mut merged: Vec<String> = base
                        .into_iter()
                        .filter(|tag| {
                            !tag.starts_with("gui:")
                                && !tag.starts_with("display:")
                                && !tag.starts_with("proxmox:")
                        })
                        .collect();
                    if let Some(gui_tags) = last_gui_tags.as_ref() {
                        merged.extend(gui_tags.iter().cloned());
                    }
                    merged.extend(proxmox_tags.clone());
                    merged.sort();
                    merged.dedup();
                    pull_loop.queue_tag_refresh(merged);
                }
                last_proxmox_tags = Some(proxmox_tags);
            }
        }

        match pull_loop.pull_once().await {
            Ok(response) => {
                pull_loop.session_state().mark_pull_ok();
                if let Some(material) = response.key_material.as_ref() {
                    if let Err(error) = apply_key_material(&mut config, material) {
                        warn!(error = %error, "failed to apply key material");
                    }
                    if material.rotate_credential {
                        let mut kp = pull_loop.keypair();
                        match rotate_agent_credential(
                            &submit_client,
                            agent_id,
                            &mut kp,
                            &config.key_path,
                        )
                        .await
                        {
                            Ok(()) => pull_loop.set_keypair(kp),
                            Err(error) => {
                                warn!(error = %error, "credential rotation failed")
                            }
                        }
                    }
                }

                for task in response.tasks {
                    let mark_busy = match &task {
                        AgentTask::ExecuteCommand { command_id, .. } => {
                            if !pull_loop.session_state().remember_command_id(*command_id) {
                                warn!(
                                    command_id = %command_id,
                                    "skipping duplicate command_id (already executed recently)"
                                );
                                continue;
                            }
                            pull_loop.session_state().begin_command(*command_id);
                            true
                        }
                        AgentTask::SelfUpdate { .. } => {
                            // Long download/install; keep heartbeats healthy while pull is paused.
                            pull_loop.session_state().begin_busy(None);
                            true
                        }
                        AgentTask::NoOp => false,
                    };
                    let keypair = pull_loop.keypair();
                    handle_task(
                        task,
                        Arc::clone(&registry),
                        &submit_client,
                        agent_id,
                        &keypair,
                        &config,
                        &config.server_url,
                    )
                    .await;
                    if mark_busy {
                        pull_loop.session_state().end_command();
                    }
                }
                tokio::time::sleep(pull_config.interval).await;
            }
            Err(PullError::Revoked) => {
                error!("agent credential revoked; stopping pull loop");
                return;
            }
            Err(error) => {
                warn!(error = %error, "pull failed");
                tokio::time::sleep(pull_config.interval).await;
            }
        }
    }
}

async fn handle_task(
    task: AgentTask,
    registry: Arc<DefaultCommandRegistry>,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    config: &AgentConfig,
    server_url: &str,
) {
    match task {
        AgentTask::ExecuteCommand {
            command_id,
            command_name,
            params,
            timeout_secs,
            execution_policy,
            server_task_sig,
        } => {
            if let Some(pubkey) = config.task_signing_pubkey_b64.as_deref() {
                let previous = config.task_signing_pubkey_previous_b64.as_deref();
                let keys: Vec<&str> = std::iter::once(pubkey)
                    .chain(previous)
                    .collect();
                if let Err(error) = verify_server_task_sig_any(
                    &keys,
                    &server_task_sig,
                    command_id,
                    &command_name,
                    &params,
                    &execution_policy,
                ) {
                    let result = CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: format!("task signature verification failed: {error}"),
                        exit_code: Some(1),
                        truncated: false,
                    };
                    if let Err(submit_error) = client.submit_result(agent_id, keypair, &result).await {
                        warn!(command_id = %command_id, error = %submit_error, "failed to submit command result");
                    }
                    return;
                }
            } else {
                let result = CommandResultPayload {
                    command_id,
                    stdout: String::new(),
                    stderr: "task signing public key is not configured; re-enroll required".into(),
                    exit_code: Some(1),
                    truncated: false,
                };
                if let Err(submit_error) = client.submit_result(agent_id, keypair, &result).await {
                    warn!(command_id = %command_id, error = %submit_error, "failed to submit command result");
                }
                return;
            }

            let ctx = CommandContext::new(
                agent_id,
                AgentPolicy::from_execution_policy(&execution_policy, timeout_secs),
            );

            if command_name == "agent.update" || command_name == "helper.install" {
                if !ctx.policy.allows_command(&command_name) {
                    let result = CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: "command not allowed by execution policy".into(),
                        exit_code: Some(1),
                        truncated: false,
                    };
                    if let Err(error) = client.submit_result(agent_id, keypair, &result).await {
                        warn!(command_id = %command_id, error = %error, "failed to submit command result");
                    }
                    return;
                }

                let result =
                    run_agent_update_command(config, client, agent_id, keypair, command_id).await;
                info!(
                    command_id = %command_id,
                    command = %command_name,
                    ?result.exit_code,
                    "package update command completed"
                );
                if let Err(error) = client.submit_result(agent_id, keypair, &result).await {
                    warn!(command_id = %command_id, error = %error, "failed to submit command result");
                }
                // Binary replace: exit so the supervisor picks up the new binary.
                // Helper-only installs never replace the agent; skip restart.
                // Package install: do NOT exit — Restart=always would race dpkg/msiexec.
                if command_name == "agent.update"
                    && result.exit_code == Some(0)
                    && restart_required_after_update(&result.stdout)
                {
                    info!("agent.update replaced agent binary; exiting for service restart");
                    crate::service_restart::schedule_restart_after_self_update();
                    std::process::exit(0);
                }
                if result.exit_code == Some(0) && installer_launched_after_update(&result.stdout) {
                    info!("{command_name} launched package installer; deferring pull loop in background");
                    std::thread::spawn(|| wait_after_installer_launch());
                }
                return;
            }

            if command_name == "system.reboot" {
                if let Some(result) = run_system_reboot_command(&ctx, command_id) {
                    info!(command_id = %command_id, ?result.exit_code, "system.reboot finished with result");
                    if let Err(error) = client.submit_result(agent_id, keypair, &result).await {
                        warn!(command_id = %command_id, error = %error, "failed to submit command result");
                    }
                } else {
                    info!(command_id = %command_id, "system.reboot initiated without terminal result");
                }
                return;
            }

            let result = if command_name == "file.pull" {
                if !ctx.policy.allows_command("file.pull") {
                    CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: "command not allowed by execution policy".into(),
                        exit_code: Some(1),
                        truncated: false,
                    }
                } else {
                    run_file_pull_command(
                        &ctx,
                        client,
                        agent_id,
                        keypair,
                        command_id,
                        params,
                    )
                    .await
                    .into_result_payload(command_id)
                }
            } else if command_name == "file.push" {
                if !ctx.policy.allows_command("file.push") {
                    CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: "command not allowed by execution policy".into(),
                        exit_code: Some(1),
                        truncated: false,
                    }
                } else {
                    run_file_push_command(&ctx, client, agent_id, keypair, params)
                        .await
                        .into_result_payload(command_id)
                }
            } else if command_name == "remote.download" {
                if !ctx.policy.allows_command("remote.download") {
                    CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: "command not allowed by execution policy".into(),
                        exit_code: Some(1),
                        truncated: false,
                    }
                } else {
                    run_remote_download_command(
                        &ctx,
                        client,
                        agent_id,
                        keypair,
                        command_id,
                        params,
                    )
                    .await
                    .into_result_payload(command_id)
                }
            } else if command_name.starts_with("desktop.") {
                if !ctx.policy.allows_command(&command_name) {
                    CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: "command not allowed by execution policy".into(),
                        exit_code: Some(1),
                        truncated: false,
                    }
                } else {
                    let output = match command_name.as_str() {
                        "desktop.info" => run_desktop_info_command().await,
                        "desktop.screenshot" => {
                            run_desktop_screenshot_command(
                                client, agent_id, keypair, command_id, params,
                            )
                            .await
                        }
                        "desktop.clipboard.get" => {
                            run_desktop_clipboard_get_command(
                                client, agent_id, keypair, command_id, params,
                            )
                            .await
                        }
                        "desktop.clipboard.set" => {
                            run_desktop_clipboard_set_command(
                                &ctx, client, agent_id, keypair, params,
                            )
                            .await
                        }
                        "desktop.session.frame" => {
                            run_desktop_session_frame_command(
                                client, agent_id, keypair, command_id, params,
                            )
                            .await
                        }
                        "desktop.move" => run_desktop_json_command("move", params).await,
                        "desktop.click" => run_desktop_json_command("click", params).await,
                        "desktop.scroll" => run_desktop_json_command("scroll", params).await,
                        "desktop.drag" => run_desktop_json_command("drag", params).await,
                        "desktop.type" => run_desktop_json_command("type", params).await,
                        "desktop.key" => run_desktop_json_command("key", params).await,
                        "desktop.session.open" => {
                            run_desktop_json_command("session.open", params).await
                        }
                        "desktop.session.input" => {
                            run_desktop_json_command("session.input", params).await
                        }
                        "desktop.session.close" => {
                            run_desktop_json_command("session.close", params).await
                        }
                        "desktop.app.launch" => {
                            run_desktop_json_command("app.launch", params).await
                        }
                        "desktop.window.list" => {
                            run_desktop_json_command("window.list", params).await
                        }
                        "desktop.window.focus" => {
                            run_desktop_json_command("window.focus", params).await
                        }
                        "desktop.window.wait" => {
                            run_desktop_json_command("window.wait", params).await
                        }
                        "desktop.shell.run" => {
                            let argv: Vec<String> = params
                                .get("argv")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let cwd = params
                                .get("cwd")
                                .and_then(|v| v.as_str())
                                .unwrap_or(".");
                            let elevated = params
                                .get("elevated")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let mut env = std::collections::HashMap::new();
                            if let Some(obj) = params.get("env").and_then(|v| v.as_object()) {
                                for (key, value) in obj {
                                    if let Some(val) = value.as_str() {
                                        env.insert(key.clone(), val.to_string());
                                    }
                                }
                            }
                            if let Err(error) =
                                ctx.policy.validate_shell_run(&argv, cwd, &env, elevated)
                            {
                                crate::commands::desktop::json_err(
                                    crate::commands::CommandError::Policy(error),
                                )
                            } else {
                                run_desktop_json_command("shell.run", params).await
                            }
                        }
                        other => crate::commands::desktop::json_err(
                            crate::commands::CommandError::NotFound(other.to_string()),
                        ),
                    };
                    output.into_result_payload(command_id)
                }
            } else if command_name.starts_with("proxmox.") {
                if !ctx.policy.allows_command(&command_name) {
                    CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: "command not allowed by execution policy".into(),
                        exit_code: Some(1),
                        truncated: false,
                    }
                } else {
                    let output = match command_name.as_str() {
                        "proxmox.info" => run_proxmox_info_command().await,
                        "proxmox.vm.list" => {
                            run_proxmox_json_command("vm.list", params).await
                        }
                        "proxmox.console.open" => {
                            run_proxmox_json_command("console.open", params).await
                        }
                        "proxmox.console.frame" => {
                            run_proxmox_console_frame_command(
                                client, agent_id, keypair, command_id, params,
                            )
                            .await
                        }
                        "proxmox.console.input" => {
                            run_proxmox_json_command("console.input", params).await
                        }
                        "proxmox.console.close" => {
                            run_proxmox_json_command("console.close", params).await
                        }
                        other => crate::commands::proxmox::json_err(
                            crate::commands::CommandError::NotFound(other.to_string()),
                        ),
                    };
                    output.into_result_payload(command_id)
                }
            } else {
                // Sync handlers (shell.run, file ops, …) must not block the async runtime.
                let registry = registry.clone();
                let ctx = ctx.clone();
                let command_name = command_name.clone();
                match tokio::task::spawn_blocking(move || {
                    registry.execute(&ctx, &command_name, params)
                })
                .await
                {
                    Ok(Ok(output)) => output.into_result_payload(command_id),
                    Ok(Err(error)) => CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: error.to_string(),
                        exit_code: Some(1),
                        truncated: false,
                    },
                    Err(error) => CommandResultPayload {
                        command_id,
                        stdout: String::new(),
                        stderr: format!("command worker failed: {error}"),
                        exit_code: Some(1),
                        truncated: false,
                    },
                }
            };
            info!(command_id = %command_id, ?result.exit_code, "command completed");
            if let Err(error) = client.submit_result(agent_id, keypair, &result).await {
                warn!(command_id = %command_id, error = %error, "failed to submit command result");
            }
        }
        AgentTask::SelfUpdate { .. } => {
            apply_self_update_task_or_log(
                task,
                config,
                client,
                agent_id,
                keypair,
                server_url,
            )
            .await;
        }
        AgentTask::NoOp => {}
    }
}

fn format_runtime_mode(mode: RuntimeMode) -> &'static str {
    crate::runtime::format_runtime_mode(mode)
}

/// Parse agent.update stdout JSON; only restart when the agent binary was replaced.
fn restart_required_after_update(stdout: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|value| value.get("restart_required")?.as_bool())
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn assess_readiness_missing_config() {
        let dir = TempDir::new().unwrap();
        let readiness = assess_readiness(
            &dir.path().join("config.toml"),
            &dir.path().join("agent.key"),
        );
        match readiness {
            AgentReadiness::Waiting { mode, .. } => {
                assert_eq!(mode, RuntimeMode::WaitingForEnrollment);
            }
            AgentReadiness::Ready { .. } => panic!("expected waiting state"),
        }
    }

    #[test]
    fn restart_required_reads_update_summary() {
        assert!(restart_required_after_update(
            r#"{"agent_updated":true,"desktop_updated":false,"restart_required":true}"#
        ));
        assert!(!restart_required_after_update(
            r#"{"agent_updated":false,"desktop_updated":true,"restart_required":false}"#
        ));
        assert!(!restart_required_after_update(
            r#"{"agent_updated":true,"desktop_updated":false,"restart_required":false,"installer_launched":true}"#
        ));
        // Unknown/legacy success payloads: prefer restart so a replaced binary is picked up.
        assert!(restart_required_after_update("ok"));
    }
}

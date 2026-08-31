//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Proxmox console helper agent commands (via hecate-lampad-proxmox IPC).

mod console;
mod info;
mod vm_list;

use super::{CommandError, CommandOutput, CommandRegistry, DefaultCommandRegistry};
use crate::client::HttpPullClient;
use crate::proxmox_ipc::client::ProxmoxIpcClient;
use crate::proxmox_ipc::{CaptureResult, ProxmoxIpcError};
use crate::signing::AgentKeypair;
use serde_json::{json, Value};
use uuid::Uuid;

pub use console::{
    ProxmoxConsoleCloseCommand, ProxmoxConsoleFrameCommand, ProxmoxConsoleInputCommand,
    ProxmoxConsoleOpenCommand,
};
pub use info::ProxmoxInfoCommand;
pub use vm_list::ProxmoxVmListCommand;

pub(crate) fn ipc_client() -> ProxmoxIpcClient {
    ProxmoxIpcClient::default()
}

pub(crate) fn map_ipc_error(error: ProxmoxIpcError) -> CommandError {
    CommandError::Execution(error.to_string())
}

pub(crate) fn sync_stub(name: &str) -> Result<CommandOutput, CommandError> {
    Err(CommandError::Execution(format!(
        "{name} requires async execution"
    )))
}

pub(crate) fn json_ok(result: Value) -> CommandOutput {
    CommandOutput {
        stdout: result.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    }
}

pub fn json_err(error: CommandError) -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: error.to_string(),
        exit_code: Some(1),
        truncated: false,
    }
}

async fn upload_capture(
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    capture: CaptureResult,
    default_name: &str,
) -> Result<CommandOutput, CommandError> {
    if capture.bytes.is_empty() {
        return Err(CommandError::Execution("empty capture payload".into()));
    }
    let sha256 = crate::commands::file_ops::sha256_hex(&capture.bytes);
    let filename = capture
        .meta
        .get("filename")
        .and_then(|v| v.as_str())
        .unwrap_or(default_name)
        .to_string();

    let stored = client
        .upload_artifact(
            agent_id,
            keypair,
            command_id,
            &capture.bytes,
            &sha256,
            &filename,
        )
        .await
        .map_err(|e| CommandError::Execution(e.to_string()))?;

    let mut stdout = capture.meta.clone();
    if let Some(obj) = stdout.as_object_mut() {
        obj.insert("artifact_id".into(), json!(stored.artifact_id));
        obj.insert("sha256".into(), json!(stored.sha256));
        obj.insert("size_bytes".into(), json!(stored.size_bytes));
    } else {
        stdout = json!({
            "artifact_id": stored.artifact_id,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "meta": capture.meta,
        });
    }

    Ok(CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    })
}

pub fn register_proxmox_commands(registry: &mut DefaultCommandRegistry) {
    use std::sync::Arc;
    registry.register(Arc::new(ProxmoxInfoCommand));
    registry.register(Arc::new(ProxmoxVmListCommand));
    registry.register(Arc::new(ProxmoxConsoleOpenCommand));
    registry.register(Arc::new(ProxmoxConsoleFrameCommand));
    registry.register(Arc::new(ProxmoxConsoleInputCommand));
    registry.register(Arc::new(ProxmoxConsoleCloseCommand));
}

pub async fn run_proxmox_info_command() -> CommandOutput {
    match ipc_client().info().await {
        Ok(info) => json_ok(serde_json::to_value(info).unwrap_or_else(|_| json!({}))),
        Err(error) => {
            if matches!(error, ProxmoxIpcError::HelperUnavailable) {
                json_ok(json!({
                    "helper_connected": false,
                    "helper_package_installed": crate::proxmox_ipc::helper_package_installed(),
                    "error": "helper_unavailable",
                }))
            } else {
                json_err(map_ipc_error(error))
            }
        }
    }
}

pub async fn run_proxmox_json_command(method: &str, params: Value) -> CommandOutput {
    match ipc_client().call_json(method, params).await {
        Ok(result) => json_ok(result),
        Err(error) => json_err(map_ipc_error(error)),
    }
}

pub async fn run_proxmox_console_frame_command(
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> CommandOutput {
    match ipc_client().console_frame(params).await {
        Ok(capture) => match upload_capture(
            client,
            agent_id,
            keypair,
            command_id,
            capture,
            "console-frame.png",
        )
        .await
        {
            Ok(output) => output,
            Err(error) => json_err(error),
        },
        Err(error) => json_err(map_ipc_error(error)),
    }
}

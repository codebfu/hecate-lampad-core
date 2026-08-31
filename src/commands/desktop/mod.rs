//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Desktop / computer-use agent commands (via hecate-lampad-desktop IPC).

mod app;
mod clipboard;
mod info;
mod input;
mod screenshot;
mod session;
mod shell;
mod window;

use super::{CommandContext, CommandError, CommandOutput, CommandRegistry, DefaultCommandRegistry};
use crate::client::HttpPullClient;
use crate::desktop_ipc::client::DesktopIpcClient;
use crate::desktop_ipc::{CaptureResult, DesktopIpcError};
use crate::signing::AgentKeypair;
use serde_json::{json, Value};
use uuid::Uuid;

pub use app::DesktopAppLaunchCommand;
pub use clipboard::{DesktopClipboardGetCommand, DesktopClipboardSetCommand};
pub use info::DesktopInfoCommand;
pub use input::{
    DesktopClickCommand, DesktopDragCommand, DesktopKeyCommand, DesktopMoveCommand,
    DesktopScrollCommand, DesktopTypeCommand,
};
pub use screenshot::DesktopScreenshotCommand;
pub use session::{
    DesktopSessionCloseCommand, DesktopSessionFrameCommand, DesktopSessionInputCommand,
    DesktopSessionOpenCommand,
};
pub use shell::DesktopShellRunCommand;
pub use window::{DesktopWindowFocusCommand, DesktopWindowListCommand, DesktopWindowWaitCommand};

pub(crate) fn ipc_client() -> DesktopIpcClient {
    DesktopIpcClient::default()
}

pub(crate) fn map_ipc_error(error: DesktopIpcError) -> CommandError {
    CommandError::Execution(error.to_string())
}

pub(crate) async fn upload_capture(
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

/// Register all desktop commands on a registry builder helper.
pub fn register_desktop_commands(registry: &mut DefaultCommandRegistry) {
    use std::sync::Arc;
    registry.register(Arc::new(DesktopInfoCommand));
    registry.register(Arc::new(DesktopScreenshotCommand));
    registry.register(Arc::new(DesktopMoveCommand));
    registry.register(Arc::new(DesktopClickCommand));
    registry.register(Arc::new(DesktopScrollCommand));
    registry.register(Arc::new(DesktopDragCommand));
    registry.register(Arc::new(DesktopTypeCommand));
    registry.register(Arc::new(DesktopKeyCommand));
    registry.register(Arc::new(DesktopClipboardGetCommand));
    registry.register(Arc::new(DesktopClipboardSetCommand));
    registry.register(Arc::new(DesktopSessionOpenCommand));
    registry.register(Arc::new(DesktopSessionFrameCommand));
    registry.register(Arc::new(DesktopSessionInputCommand));
    registry.register(Arc::new(DesktopSessionCloseCommand));
    registry.register(Arc::new(DesktopAppLaunchCommand));
    registry.register(Arc::new(DesktopWindowListCommand));
    registry.register(Arc::new(DesktopWindowFocusCommand));
    registry.register(Arc::new(DesktopWindowWaitCommand));
    registry.register(Arc::new(DesktopShellRunCommand));
}

pub async fn run_desktop_info_command() -> CommandOutput {
    match ipc_client().info().await {
        Ok(info) => json_ok(serde_json::to_value(info).unwrap_or_else(|_| json!({}))),
        Err(error) => {
            // Degraded info when helper missing.
            if matches!(error, DesktopIpcError::HelperUnavailable) {
                json_ok(json!({
                    "helper_connected": false,
                    "helper_package_installed": crate::desktop_ipc::helper_package_installed(),
                    "error": "helper_unavailable",
                }))
            } else {
                json_err(map_ipc_error(error))
            }
        }
    }
}

pub async fn run_desktop_screenshot_command(
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> CommandOutput {
    match ipc_client().screenshot(params).await {
        Ok(capture) => match upload_capture(
            client,
            agent_id,
            keypair,
            command_id,
            capture,
            "screenshot.png",
        )
        .await
        {
            Ok(output) => output,
            Err(error) => json_err(error),
        },
        Err(error) => json_err(map_ipc_error(error)),
    }
}

pub async fn run_desktop_json_command(method: &str, params: Value) -> CommandOutput {
    match ipc_client().call_json(method, params).await {
        Ok(result) => json_ok(result),
        Err(error) => json_err(map_ipc_error(error)),
    }
}

pub async fn run_desktop_clipboard_get_command(
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> CommandOutput {
    let format = params
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("text");
    if format == "image" {
        match ipc_client().clipboard_get_image(params).await {
            Ok(capture) => match upload_capture(
                client,
                agent_id,
                keypair,
                command_id,
                capture,
                "clipboard.png",
            )
            .await
            {
                Ok(output) => output,
                Err(error) => json_err(error),
            },
            Err(error) => json_err(map_ipc_error(error)),
        }
    } else {
        run_desktop_json_command("clipboard.get", params).await
    }
}

pub async fn run_desktop_clipboard_set_command(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    params: Value,
) -> CommandOutput {
    if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
        return run_desktop_json_command("clipboard.set", json!({ "text": text })).await;
    }

    let download_path = params
        .get("artifact_download_path")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let sha256 = params
        .get("sha256")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if download_path.is_empty() || sha256.is_empty() {
        return json_err(CommandError::InvalidParams(
            "artifact_download_path and sha256 required for image clipboard set".into(),
        ));
    }

    let bytes = match client
        .download_signed(agent_id, keypair, download_path)
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => return json_err(CommandError::Execution(error.to_string())),
    };
    if bytes.len() > ctx.policy.max_file_bytes as usize {
        return json_err(CommandError::Execution(format!(
            "artifact exceeds max size of {} bytes",
            ctx.policy.max_file_bytes
        )));
    }
    let actual = crate::commands::file_ops::sha256_hex(&bytes);
    if !actual.eq_ignore_ascii_case(sha256) {
        return json_err(CommandError::Execution(format!(
            "sha256 mismatch: expected {sha256}, got {actual}"
        )));
    }

    // Send image bytes via a dedicated IPC method with payload — encode as base64 in params
    // for simplicity on the set path (images for clipboard are typically small).
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
    run_desktop_json_command(
        "clipboard.set",
        json!({
            "format": params.get("format").and_then(|v| v.as_str()).unwrap_or("image/png"),
            "image_base64": b64,
        }),
    )
    .await
}

pub async fn run_desktop_session_frame_command(
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> CommandOutput {
    match ipc_client().session_frame(params).await {
        Ok(capture) => match upload_capture(
            client,
            agent_id,
            keypair,
            command_id,
            capture,
            "frame.png",
        )
        .await
        {
            Ok(output) => output,
            Err(error) => json_err(error),
        },
        Err(error) => json_err(map_ipc_error(error)),
    }
}

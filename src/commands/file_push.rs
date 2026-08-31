//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::file_ops::{atomic_write_file, parse_file_mode, resolve_write_path, sha256_hex};
use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use crate::client::HttpPullClient;
use crate::signing::AgentKeypair;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub struct FilePushCommand;

#[derive(Debug, Deserialize)]
struct FilePushParams {
    dest_path: String,
    artifact_download_path: String,
    sha256: String,
    #[serde(default)]
    mode: Option<String>,
}

pub async fn run_file_push_command(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    params: Value,
) -> CommandOutput {
    match execute_file_push(ctx, client, agent_id, keypair, params).await {
        Ok(output) => output,
        Err(error) => CommandOutput {
            stdout: String::new(),
            stderr: error.to_string(),
            exit_code: Some(1),
            truncated: false,
        },
    }
}

async fn execute_file_push(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    params: Value,
) -> Result<CommandOutput, CommandError> {
    let params: FilePushParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;

    let dest_path = resolve_write_path(&params.dest_path, &ctx.policy.shell_policy.allowed_cwd)?;
    let mode = parse_file_mode(params.mode.as_deref())?;

    let bytes = client
        .download_signed(agent_id, keypair, &params.artifact_download_path)
        .await
        .map_err(|error| CommandError::Execution(error.to_string()))?;

    if bytes.len() > ctx.policy.max_file_bytes as usize {
        return Err(CommandError::Execution(format!(
            "artifact exceeds max size of {} bytes",
            ctx.policy.max_file_bytes
        )));
    }

    let actual = sha256_hex(&bytes);
    if !actual.eq_ignore_ascii_case(&params.sha256) {
        return Err(CommandError::Execution(format!(
            "sha256 mismatch: expected {}, got {actual}",
            params.sha256
        )));
    }

    atomic_write_file(&dest_path, &bytes, mode)?;

    Ok(CommandOutput {
        stdout: json!({
            "dest_path": params.dest_path,
            "bytes_written": bytes.len(),
            "sha256": actual,
        })
        .to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    })
}

impl AgentCommand for FilePushCommand {
    fn name(&self) -> &'static str {
        "file.push"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["dest_path", "artifact_id", "sha256"],
            "properties": {
                "dest_path": { "type": "string" },
                "artifact_id": { "type": "string", "format": "uuid" },
                "sha256": { "type": "string" },
                "mode": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        Err(CommandError::Execution(
            "file.push requires async execution".into(),
        ))
    }
}

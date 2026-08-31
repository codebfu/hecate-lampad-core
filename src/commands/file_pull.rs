//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::file_ops::{read_file_limited, resolve_read_path, sha256_hex};
use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use crate::client::HttpPullClient;
use crate::signing::AgentKeypair;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub struct FilePullCommand;

#[derive(Debug, Deserialize)]
struct FilePullParams {
    path: String,
}

pub async fn run_file_pull_command(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> CommandOutput {
    match execute_file_pull(ctx, client, agent_id, keypair, command_id, params).await {
        Ok(output) => output,
        Err(error) => CommandOutput {
            stdout: String::new(),
            stderr: error.to_string(),
            exit_code: Some(1),
            truncated: false,
        },
    }
}

async fn execute_file_pull(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> Result<CommandOutput, CommandError> {
    let params: FilePullParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;

    let resolved = resolve_read_path(&params.path, &ctx.policy.shell_policy.allowed_cwd)?;
    let bytes = read_file_limited(&resolved, ctx.policy.max_file_bytes)?;
    let sha256 = sha256_hex(&bytes);
    let original_name = resolved
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact.bin");

    let stored = client
        .upload_artifact(agent_id, keypair, command_id, &bytes, &sha256, original_name)
        .await
        .map_err(|error| CommandError::Execution(error.to_string()))?;

    Ok(CommandOutput {
        stdout: json!({
            "artifact_id": stored.artifact_id,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "path": params.path,
        })
        .to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    })
}

impl AgentCommand for FilePullCommand {
    fn name(&self) -> &'static str {
        "file.pull"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        Err(CommandError::Execution(
            "file.pull requires async execution".into(),
        ))
    }
}

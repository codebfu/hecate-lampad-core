//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::file_ops::{
    copy_file_path, delete_file_path, move_path, resolve_read_path, resolve_rename_target,
    resolve_write_path, success_output,
};
use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use serde::Deserialize;
use serde_json::{json, Value};

pub struct FileCopyCommand;
pub struct FileMoveCommand;
pub struct FileRenameCommand;
pub struct FileDeleteCommand;

#[derive(Debug, Deserialize)]
struct SrcDestParams {
    src: String,
    dest: String,
}

#[derive(Debug, Deserialize)]
struct RenameParams {
    path: String,
    new_name: String,
}

#[derive(Debug, Deserialize)]
struct PathParams {
    path: String,
}

macro_rules! impl_file_command {
    ($type:ty, $name:literal, $schema:expr, $exec:expr) => {
        impl AgentCommand for $type {
            fn name(&self) -> &'static str {
                $name
            }

            fn input_schema(&self) -> Value {
                $schema
            }

            fn execute(&self, ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
                $exec(ctx, params)
            }
        }
    };
}

fn execute_file_copy(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: SrcDestParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let src = resolve_read_path(&params.src, allowed)?;
    let dest = resolve_write_path(&params.dest, allowed)?;
    copy_file_path(&src, &dest)?;
    Ok(success_output(json!({
        "src": params.src,
        "dest": params.dest,
    })))
}

fn execute_file_move(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: SrcDestParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let src = resolve_read_path(&params.src, allowed)?;
    let dest = resolve_write_path(&params.dest, allowed)?;
    move_path(&src, &dest)?;
    Ok(success_output(json!({
        "src": params.src,
        "dest": params.dest,
    })))
}

fn execute_file_rename(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: RenameParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let (src, dest) = resolve_rename_target(&params.path, &params.new_name, allowed, false)?;
    move_path(&src, &dest)?;
    Ok(success_output(json!({
        "path": params.path,
        "new_name": params.new_name,
        "dest": dest.to_string_lossy(),
    })))
}

fn execute_file_delete(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: PathParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let path = resolve_read_path(&params.path, allowed)?;
    delete_file_path(&path)?;
    Ok(success_output(json!({ "path": params.path })))
}

impl_file_command!(
    FileCopyCommand,
    "file.copy",
    json!({
        "type": "object",
        "required": ["src", "dest"],
        "properties": {
            "src": { "type": "string" },
            "dest": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_file_copy
);

impl_file_command!(
    FileMoveCommand,
    "file.move",
    json!({
        "type": "object",
        "required": ["src", "dest"],
        "properties": {
            "src": { "type": "string" },
            "dest": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_file_move
);

impl_file_command!(
    FileRenameCommand,
    "file.rename",
    json!({
        "type": "object",
        "required": ["path", "new_name"],
        "properties": {
            "path": { "type": "string" },
            "new_name": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_file_rename
);

impl_file_command!(
    FileDeleteCommand,
    "file.delete",
    json!({
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_file_delete
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AgentPolicy;
    use hecate_protocol::permissions::ShellPolicy;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn test_context(allowed: Vec<String>) -> CommandContext {
        CommandContext::new(
            Uuid::new_v4(),
            AgentPolicy::new(
                vec![
                    "file.copy".into(),
                    "file.move".into(),
                    "file.rename".into(),
                    "file.delete".into(),
                ],
                ShellPolicy {
                    allowed_cwd: allowed,
                    ..Default::default()
                },
            ),
        )
    }

    #[test]
    fn file_copy_duplicates_file() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let src = dir.path().join("source.txt");
        std::fs::write(&src, b"payload").unwrap();
        let dest = dir.path().join("dest.txt");
        let ctx = test_context(vec![root]);
        let out = execute_file_copy(
            &ctx,
            json!({
                "src": src.to_string_lossy(),
                "dest": dest.to_string_lossy(),
            }),
        )
        .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    }

    #[test]
    fn file_delete_removes_file() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let target = dir.path().join("delete-me.txt");
        std::fs::write(&target, b"x").unwrap();
        let ctx = test_context(vec![root]);
        execute_file_delete(
            &ctx,
            json!({ "path": target.to_string_lossy() }),
        )
        .unwrap();
        assert!(!target.exists());
    }
}

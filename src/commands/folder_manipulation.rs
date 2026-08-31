//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::file_ops::{
    copy_dir_recursive, create_dir_path, move_path, parse_dir_mode, remove_empty_dir,
    resolve_dir_create_path, resolve_existing_dir, resolve_rename_target, resolve_write_path,
    success_output,
};
use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use serde::Deserialize;
use serde_json::{json, Value};

pub struct FolderMkdirCommand;
pub struct FolderRmdirCommand;
pub struct FolderRenameCommand;
pub struct FolderMoveCommand;
pub struct FolderCopyCommand;

#[derive(Debug, Deserialize)]
struct PathParams {
    path: String,
}

#[derive(Debug, Deserialize)]
struct MkdirParams {
    path: String,
    #[serde(default)]
    mode: Option<String>,
}

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

macro_rules! impl_folder_command {
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

fn execute_folder_mkdir(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: MkdirParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let path = resolve_dir_create_path(&params.path, allowed)?;
    let mode = parse_dir_mode(params.mode.as_deref())?;
    create_dir_path(&path, mode)?;
    Ok(success_output(json!({
        "path": params.path,
        "mode": format!("{mode:04o}"),
    })))
}

fn execute_folder_rmdir(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: PathParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let path = resolve_existing_dir(&params.path, allowed)?;
    remove_empty_dir(&path)?;
    Ok(success_output(json!({ "path": params.path })))
}

fn execute_folder_rename(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: RenameParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let (src, dest) = resolve_rename_target(&params.path, &params.new_name, allowed, true)?;
    move_path(&src, &dest)?;
    Ok(success_output(json!({
        "path": params.path,
        "new_name": params.new_name,
        "dest": dest.to_string_lossy(),
    })))
}

fn execute_folder_move(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: SrcDestParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let src = resolve_existing_dir(&params.src, allowed)?;
    let dest = resolve_write_path(&params.dest, allowed)?;
    move_path(&src, &dest)?;
    Ok(success_output(json!({
        "src": params.src,
        "dest": params.dest,
    })))
}

fn execute_folder_copy(ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
    let params: SrcDestParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
    let allowed = &ctx.policy.shell_policy.allowed_cwd;
    let src = resolve_existing_dir(&params.src, allowed)?;
    let dest = resolve_write_path(&params.dest, allowed)?;
    copy_dir_recursive(&src, &dest)?;
    Ok(success_output(json!({
        "src": params.src,
        "dest": params.dest,
    })))
}

impl_folder_command!(
    FolderMkdirCommand,
    "folder.mkdir",
    json!({
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": { "type": "string" },
            "mode": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_folder_mkdir
);

impl_folder_command!(
    FolderRmdirCommand,
    "folder.rmdir",
    json!({
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_folder_rmdir
);

impl_folder_command!(
    FolderRenameCommand,
    "folder.rename",
    json!({
        "type": "object",
        "required": ["path", "new_name"],
        "properties": {
            "path": { "type": "string" },
            "new_name": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_folder_rename
);

impl_folder_command!(
    FolderMoveCommand,
    "folder.move",
    json!({
        "type": "object",
        "required": ["src", "dest"],
        "properties": {
            "src": { "type": "string" },
            "dest": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_folder_move
);

impl_folder_command!(
    FolderCopyCommand,
    "folder.copy",
    json!({
        "type": "object",
        "required": ["src", "dest"],
        "properties": {
            "src": { "type": "string" },
            "dest": { "type": "string" }
        },
        "additionalProperties": false
    }),
    execute_folder_copy
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
                    "folder.mkdir".into(),
                    "folder.rmdir".into(),
                    "folder.copy".into(),
                ],
                ShellPolicy {
                    allowed_cwd: allowed,
                    ..Default::default()
                },
            ),
        )
    }

    #[test]
    fn folder_mkdir_and_rmdir_roundtrip() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let nested = dir.path().join("nested");
        let ctx = test_context(vec![root]);
        execute_folder_mkdir(
            &ctx,
            json!({ "path": nested.to_string_lossy(), "mode": "0755" }),
        )
        .unwrap();
        assert!(nested.is_dir());
        execute_folder_rmdir(&ctx, json!({ "path": nested.to_string_lossy() })).unwrap();
        assert!(!nested.exists());
    }

    #[test]
    fn folder_copy_is_recursive() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("file.txt"), b"data").unwrap();
        let dest = dir.path().join("dest-copy");
        let ctx = test_context(vec![root]);
        execute_folder_copy(
            &ctx,
            json!({
                "src": src.to_string_lossy(),
                "dest": dest.to_string_lossy(),
            }),
        )
        .unwrap();
        assert_eq!(std::fs::read(dest.join("file.txt")).unwrap(), b"data");
    }
}

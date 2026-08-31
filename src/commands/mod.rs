//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::policy::AgentPolicy;
use hecate_protocol::command::CommandResultPayload;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub mod agent_update;
pub mod helper_install;
pub mod desktop;
pub mod proxmox;
pub mod file_manipulation;
pub mod file_ops;
pub mod file_pull;
pub mod file_push;
pub mod folder_manipulation;
pub mod remote_download;
pub mod shell_run;
pub mod system_info;
pub mod system_reboot;

pub use agent_update::AgentUpdateCommand;
pub use helper_install::HelperInstallCommand;
pub use desktop::{
    DesktopClickCommand, DesktopClipboardGetCommand, DesktopClipboardSetCommand,
    DesktopDragCommand, DesktopInfoCommand, DesktopKeyCommand, DesktopMoveCommand,
    DesktopScreenshotCommand, DesktopScrollCommand, DesktopSessionCloseCommand,
    DesktopSessionFrameCommand, DesktopSessionInputCommand, DesktopSessionOpenCommand,
    DesktopTypeCommand, json_err,
};
pub use file_manipulation::{
    FileCopyCommand, FileDeleteCommand, FileMoveCommand, FileRenameCommand,
};
pub use file_pull::FilePullCommand;
pub use file_push::FilePushCommand;
pub use folder_manipulation::{
    FolderCopyCommand, FolderMkdirCommand, FolderMoveCommand, FolderRenameCommand,
    FolderRmdirCommand,
};
pub use remote_download::RemoteDownloadCommand;
pub use shell_run::ShellRunCommand;
pub use system_info::SystemInfoCommand;
pub use system_reboot::SystemRebootCommand;

/// Execution context passed to every command handler.
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub agent_id: Uuid,
    pub policy: AgentPolicy,
    pub max_output_bytes: u32,
}

impl CommandContext {
    pub fn new(agent_id: Uuid, policy: AgentPolicy) -> Self {
        let max_output_bytes = policy.max_output_bytes;
        Self {
            agent_id,
            policy,
            max_output_bytes,
        }
    }
}

/// Successful command output before protocol wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub truncated: bool,
}

impl CommandOutput {
    pub fn into_result_payload(self, command_id: Uuid) -> CommandResultPayload {
        CommandResultPayload {
            command_id,
            stdout: self.stdout,
            stderr: self.stderr,
            exit_code: self.exit_code,
            truncated: self.truncated,
        }
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("command not allowed: {0}")]
    NotAllowed(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("policy violation: {0}")]
    Policy(#[from] hecate_protocol::policy::PolicyError),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("command not found: {0}")]
    NotFound(String),
}

/// Built-in or plugin command handler.
pub trait AgentCommand: Send + Sync {
    fn name(&self) -> &'static str;
    fn input_schema(&self) -> Value;
    fn execute(&self, ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError>;
}

/// Registry trait for command dispatch.
pub trait CommandRegistry: Send + Sync {
    fn register(&mut self, command: Arc<dyn AgentCommand>);
    fn get(&self, name: &str) -> Option<Arc<dyn AgentCommand>>;
    fn execute(
        &self,
        ctx: &CommandContext,
        name: &str,
        params: Value,
    ) -> Result<CommandOutput, CommandError>;
    fn names(&self) -> Vec<&'static str>;
}

/// Default in-memory command registry with built-in commands.
#[derive(Default)]
pub struct DefaultCommandRegistry {
    commands: HashMap<&'static str, Arc<dyn AgentCommand>>,
}

impl DefaultCommandRegistry {
    pub fn with_builtins() -> Self {
        let mut registry = Self::default();
        registry.register(Arc::new(SystemInfoCommand));
        registry.register(Arc::new(ShellRunCommand));
        registry.register(Arc::new(AgentUpdateCommand));
        registry.register(Arc::new(HelperInstallCommand));
        registry.register(Arc::new(SystemRebootCommand));
        registry.register(Arc::new(FilePullCommand));
        registry.register(Arc::new(FilePushCommand));
        registry.register(Arc::new(RemoteDownloadCommand));
        registry.register(Arc::new(FileCopyCommand));
        registry.register(Arc::new(FileMoveCommand));
        registry.register(Arc::new(FileRenameCommand));
        registry.register(Arc::new(FileDeleteCommand));
        registry.register(Arc::new(FolderMkdirCommand));
        registry.register(Arc::new(FolderRmdirCommand));
        registry.register(Arc::new(FolderRenameCommand));
        registry.register(Arc::new(FolderMoveCommand));
        registry.register(Arc::new(FolderCopyCommand));
        desktop::register_desktop_commands(&mut registry);
        proxmox::register_proxmox_commands(&mut registry);
        registry
    }
}

impl CommandRegistry for DefaultCommandRegistry {
    fn register(&mut self, command: Arc<dyn AgentCommand>) {
        self.commands.insert(command.name(), command);
    }

    fn get(&self, name: &str) -> Option<Arc<dyn AgentCommand>> {
        self.commands.get(name).cloned()
    }

    fn execute(
        &self,
        ctx: &CommandContext,
        name: &str,
        params: Value,
    ) -> Result<CommandOutput, CommandError> {
        if !ctx.policy.allows_command(name) {
            return Err(CommandError::NotAllowed(name.to_string()));
        }
        let cmd = self
            .get(name)
            .ok_or_else(|| CommandError::NotFound(name.to_string()))?;
        cmd.execute(ctx, params)
    }

    fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self.commands.keys().copied().collect();
        names.sort_unstable();
        names
    }
}

/// Helper for platform wrappers: load keypair and run a command by name.
pub fn execute_command(
    registry: &dyn CommandRegistry,
    ctx: &CommandContext,
    command_name: &str,
    params: Value,
) -> Result<CommandOutput, CommandError> {
    registry.execute(ctx, command_name, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::permissions::ShellPolicy;

    fn test_context() -> CommandContext {
        CommandContext::new(
            Uuid::new_v4(),
            AgentPolicy::new(
                vec!["system.info".into(), "shell.run".into()],
                ShellPolicy {
                    allowed_binaries: vec!["/usr/bin/echo".into()],
                    allowed_cwd: vec![],
                    allowed_env: vec![],
                },
            ),
        )
    }

    #[test]
    fn registry_lists_builtins() {
        let registry = DefaultCommandRegistry::with_builtins();
        let names = registry.names();
        assert!(names.contains(&"system.info"));
        assert!(names.contains(&"shell.run"));
        assert!(names.contains(&"agent.update"));
        assert!(names.contains(&"helper.install"));
        assert!(names.contains(&"system.reboot"));
        assert!(names.contains(&"file.pull"));
        assert!(names.contains(&"file.push"));
        assert!(names.contains(&"remote.download"));
        assert!(names.contains(&"desktop.info"));
        assert!(names.contains(&"desktop.screenshot"));
        assert!(names.contains(&"desktop.session.open"));
    }

    #[test]
    fn rejects_disallowed_command() {
        let registry = DefaultCommandRegistry::with_builtins();
        let ctx = CommandContext::new(
            Uuid::new_v4(),
            AgentPolicy::new(vec!["system.info".into()], ShellPolicy::default()),
        );
        let err = registry
            .execute(&ctx, "shell.run", serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, CommandError::NotAllowed(_)));
    }

    #[test]
    fn system_info_succeeds() {
        let registry = DefaultCommandRegistry::with_builtins();
        let ctx = test_context();
        let out = registry
            .execute(&ctx, "system.info", serde_json::json!({}))
            .unwrap();
        assert!(out.exit_code == Some(0));
        assert!(out.stdout.contains("hostname"));
    }
}

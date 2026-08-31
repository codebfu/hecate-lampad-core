//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! system.reboot — reboot the host OS (must run through the pull loop).

use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use crate::elevation;
use hecate_protocol::command::CommandResultPayload;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

pub struct SystemRebootCommand;

impl AgentCommand for SystemRebootCommand {
    fn name(&self) -> &'static str {
        "system.reboot"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
        let _ = params;
        Err(CommandError::Execution(
            "system.reboot must run through the agent service pull loop".into(),
        ))
    }
}

/// Platform-specific elevated argv that triggers an OS reboot.
pub fn reboot_argv() -> Result<Vec<String>, String> {
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/usr/bin/systemctl").exists() {
            return Ok(vec!["/usr/bin/systemctl".into(), "reboot".into()]);
        }
        if std::path::Path::new("/sbin/shutdown").exists() {
            return Ok(vec![
                "/sbin/shutdown".into(),
                "-r".into(),
                "now".into(),
            ]);
        }
        if std::path::Path::new("/usr/sbin/reboot").exists() {
            return Ok(vec!["/usr/sbin/reboot".into()]);
        }
        return Err("no reboot binary found (systemctl/shutdown/reboot)".into());
    }
    #[cfg(target_os = "macos")]
    {
        if std::path::Path::new("/sbin/shutdown").exists() {
            return Ok(vec![
                "/sbin/shutdown".into(),
                "-r".into(),
                "now".into(),
            ]);
        }
        return Err("no reboot binary found (/sbin/shutdown)".into());
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(vec![
            "shutdown.exe".into(),
            "/r".into(),
            "/t".into(),
            "0".into(),
            "/f".into(),
        ]);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("system.reboot is not supported on this platform".into())
    }
}

/// Initiate an elevated OS reboot. On success the process should not submit a
/// terminal command result — the server completes after offline → online.
pub fn initiate_system_reboot() -> Result<(), String> {
    let argv = reboot_argv()?;
    let elevated = elevation::build_elevated_argv(&argv)?;
    let program = &elevated[0];
    let args: Vec<&str> = elevated.iter().skip(1).map(String::as_str).collect();

    let mut child = std::process::Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("exec {program}: {error}"))?;

    // Fail fast on immediate rejection (permissions, missing binary). If the
    // child is still running or exited 0, treat reboot as initiated — the host
    // may tear us down before a full wait completes.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                return Err(format!(
                    "reboot command exited with {:?}: {stderr}",
                    status.code()
                ));
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                // Still running — reboot is likely in progress.
                return Ok(());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(format!("wait for reboot command: {error}")),
        }
    }
}

/// Run system.reboot from the pull loop.
///
/// Returns `Some(failed_payload)` when the reboot could not be started or the
/// agent is still alive long after the request. Returns `None` only if this
/// process is about to die with the OS (not used today — we always return a
/// payload or block until timeout).
pub fn run_system_reboot_command(
    ctx: &CommandContext,
    command_id: Uuid,
) -> Option<CommandResultPayload> {
    if !ctx.policy.allows_command("system.reboot") {
        return Some(CommandResultPayload {
            command_id,
            stdout: String::new(),
            stderr: "command not allowed by execution policy".into(),
            exit_code: Some(1),
            truncated: false,
        });
    }

    if !ctx.policy.elevation_policy.enabled {
        return Some(CommandResultPayload {
            command_id,
            stdout: String::new(),
            stderr: "elevation is not enabled for this identity; system.reboot requires elevation"
                .into(),
            exit_code: Some(1),
            truncated: false,
        });
    }

    match initiate_system_reboot() {
        Ok(()) => {
            info!(command_id = %command_id, "system.reboot initiated; awaiting OS shutdown");
            // Stay alive briefly so the server can observe the offline transition
            // if the kernel takes a few seconds to halt. Do not submit success.
            std::thread::sleep(Duration::from_secs(120));
            warn!(command_id = %command_id, "still running 120s after reboot request");
            Some(CommandResultPayload {
                command_id,
                stdout: String::new(),
                stderr: "reboot was requested but the agent is still running after 120s".into(),
                exit_code: Some(1),
                truncated: false,
            })
        }
        Err(error) => {
            warn!(command_id = %command_id, error = %error, "system.reboot failed to start");
            Some(CommandResultPayload {
                command_id,
                stdout: String::new(),
                stderr: error,
                exit_code: Some(1),
                truncated: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AgentPolicy;
    use hecate_protocol::permissions::{ElevationPolicy, ShellPolicy};

    #[test]
    fn registry_handler_rejects_direct_execute() {
        let cmd = SystemRebootCommand;
        let ctx = CommandContext::new(
            Uuid::nil(),
            AgentPolicy::new(vec!["system.reboot".into()], ShellPolicy::default()),
        );
        let err = cmd.execute(&ctx, json!({})).unwrap_err();
        assert!(err.to_string().contains("pull loop"));
    }

    #[test]
    fn reboot_argv_is_non_empty() {
        // CI images (e.g. rust:bookworm) often lack systemctl/shutdown/reboot.
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            match reboot_argv() {
                Ok(argv) => assert!(!argv.is_empty()),
                Err(error) => assert!(
                    error.contains("no reboot binary found"),
                    "unexpected reboot_argv error: {error}"
                ),
            }
        }
    }

    #[test]
    fn rejects_without_elevation_policy() {
        let mut policy = AgentPolicy::new(
            vec!["system.reboot".into()],
            ShellPolicy::default(),
        );
        policy.elevation_policy = ElevationPolicy {
            enabled: false,
            allowed_binaries: vec![],
        };
        let ctx = CommandContext::new(Uuid::nil(), policy);
        let result = run_system_reboot_command(&ctx, Uuid::nil()).expect("payload");
        assert_eq!(result.exit_code, Some(1));
        assert!(result.stderr.contains("elevation"));
    }

    #[test]
    fn rejects_when_command_not_allowed() {
        let ctx = CommandContext::new(
            Uuid::nil(),
            AgentPolicy::new(vec!["system.info".into()], ShellPolicy::default()),
        );
        let result = run_system_reboot_command(&ctx, Uuid::nil()).expect("payload");
        assert_eq!(result.exit_code, Some(1));
        assert!(result.stderr.contains("not allowed"));
    }
}

//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use crate::elevation;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

pub struct ShellRunCommand;

#[derive(Debug, Deserialize)]
struct ShellRunParams {
    argv: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default = "default_timeout")]
    timeout_secs: u32,
    #[serde(default)]
    elevated: bool,
}

fn default_timeout() -> u32 {
    30
}

impl AgentCommand for ShellRunCommand {
    fn name(&self) -> &'static str {
        "shell.run"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["argv"],
            "properties": {
                "argv": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1
                },
                "cwd": { "type": "string" },
                "env": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 3600 },
                "elevated": {
                    "type": "boolean",
                    "description": "Run with root/admin privileges using the platform elevation backend (sudo on Linux/macOS, admin service token on Windows). Requires elevation_policy on the AI identity."
                }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
        let params: ShellRunParams = serde_json::from_value(params)
            .map_err(|e| CommandError::InvalidParams(e.to_string()))?;

        if params.argv.is_empty() {
            return Err(CommandError::InvalidParams("argv must not be empty".into()));
        }

        let cwd = params.cwd.unwrap_or_else(|| ".".into());

        ctx.policy.validate_shell_run(
            &params.argv,
            &cwd,
            &params.env,
            params.elevated,
        )?;

        let timeout = Duration::from_secs(
            params
                .timeout_secs
                .min(ctx.policy.timeout_secs)
                .max(1) as u64,
        );

        let exec_argv = if params.elevated {
            elevation::build_elevated_argv(&params.argv)
                .map_err(|error| CommandError::Execution(error))?
        } else {
            params.argv.clone()
        };

        run_execve(
            &exec_argv,
            &cwd,
            &params.env,
            timeout,
            ctx.max_output_bytes,
        )
    }
}

/// Run a process via explicit argv (no shell invocation).
fn run_execve(
    argv: &[String],
    cwd: &str,
    env: &HashMap<String, String>,
    timeout: Duration,
    max_output_bytes: u32,
) -> Result<CommandOutput, CommandError> {
    let program = &argv[0];
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();

    let mut cmd = std::process::Command::new(program);
    cmd.args(&args[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in env {
        cmd.env(key, value);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| CommandError::Execution(format!("exec {program}: {e}")))?;

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(CommandError::Execution(format!("wait {program}: {error}")));
            }
        }
    };

    let (stdout, stdout_trunc) = read_limited_stdout(&mut child, max_output_bytes)?;
    let (stderr, stderr_trunc) = read_limited_stderr(&mut child, max_output_bytes)?;

    let exit_code = if timed_out {
        Some(124)
    } else {
        status.and_then(|value| value.code())
    };

    if timed_out {
        return Ok(CommandOutput {
            stdout,
            stderr: if stderr.is_empty() {
                format!("process timed out after {}s", timeout.as_secs())
            } else {
                format!("{stderr}\nprocess timed out after {}s", timeout.as_secs())
            },
            exit_code,
            truncated: stdout_trunc || stderr_trunc,
        });
    }

    Ok(CommandOutput {
        stdout,
        stderr,
        exit_code,
        truncated: stdout_trunc || stderr_trunc,
    })
}

fn read_limited_stdout(child: &mut Child, max_output_bytes: u32) -> Result<(String, bool), CommandError> {
    match child.stdout.take() {
        Some(reader) => read_from_reader(reader, max_output_bytes as usize),
        None => Ok((String::new(), false)),
    }
}

fn read_limited_stderr(child: &mut Child, max_output_bytes: u32) -> Result<(String, bool), CommandError> {
    match child.stderr.take() {
        Some(reader) => read_from_reader(reader, max_output_bytes as usize),
        None => Ok((String::new(), false)),
    }
}

fn read_from_reader<R: Read>(mut reader: R, limit: usize) -> Result<(String, bool), CommandError> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut truncated = false;
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| CommandError::Execution(format!("read output: {error}")))?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(buffer.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        if read > remaining {
            buffer.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }

    Ok((String::from_utf8_lossy(&buffer).into_owned(), truncated))
}

#[cfg(test)]
fn truncate_string(s: String, max_bytes: u32) -> (String, bool) {
    if s.len() <= max_bytes as usize {
        return (s, false);
    }
    let mut end = max_bytes as usize;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AgentPolicy;
    use hecate_protocol::permissions::ShellPolicy;
    use uuid::Uuid;

    fn shell_context(policy: AgentPolicy) -> CommandContext {
        CommandContext::new(Uuid::new_v4(), policy)
    }

    #[test]
    fn rejects_metacharacters_in_argv() {
        let policy = AgentPolicy::new(
            vec!["shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec!["/usr/bin/echo".into()],
                allowed_cwd: vec![],
                allowed_env: vec![],
            },
        );
        let cmd = ShellRunCommand;
        let ctx = shell_context(policy);
        let err = cmd
            .execute(
                &ctx,
                json!({ "argv": ["/usr/bin/echo", "x; y"] }),
            )
            .unwrap_err();
        assert!(matches!(err, CommandError::Policy(_)));
    }

    #[test]
    fn rejects_disallowed_binary() {
        let policy = AgentPolicy::new(
            vec!["shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec!["/usr/bin/echo".into()],
                allowed_cwd: vec![],
                allowed_env: vec![],
            },
        );
        let cmd = ShellRunCommand;
        let ctx = shell_context(policy);
        let err = cmd
            .execute(
                &ctx,
                json!({ "argv": ["/bin/sh", "-c", "id"] }),
            )
            .unwrap_err();
        assert!(matches!(err, CommandError::Policy(_)));
    }

    #[test]
    fn rejects_sudo_in_argv() {
        let policy = AgentPolicy::new(
            vec!["shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec!["*".into()],
                allowed_cwd: vec![],
                allowed_env: vec![],
            },
        );
        let cmd = ShellRunCommand;
        let ctx = shell_context(policy);
        let err = cmd
            .execute(
                &ctx,
                json!({ "argv": ["/usr/bin/sudo", "/usr/bin/id"] }),
            )
            .unwrap_err();
        assert!(matches!(err, CommandError::Policy(_)));
    }

    #[test]
    fn runs_echo_without_shell() {
        let echo = which_echo();
        if echo.is_none() {
            return;
        }
        let echo = echo.unwrap();
        let policy = AgentPolicy::new(
            vec!["shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec![echo.clone()],
                allowed_cwd: vec![".".into()],
                allowed_env: vec![],
            },
        );
        let cmd = ShellRunCommand;
        let ctx = shell_context(policy);
        let out = cmd
            .execute(
                &ctx,
                json!({ "argv": [echo, "hello-hecate"], "cwd": "." }),
            )
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.contains("hello-hecate"));
    }

    fn which_echo() -> Option<String> {
        for candidate in ["/usr/bin/echo", "/bin/echo"] {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate.to_string());
            }
        }
        None
    }

    #[test]
    fn truncate_string_never_exceeds_limit() {
        let (out, truncated) = truncate_string("hello".into(), 10);
        assert_eq!(out, "hello");
        assert!(!truncated);
        let (out, truncated) = truncate_string("hello-world".into(), 5);
        assert!(out.len() <= 5);
        assert!(truncated);
    }
}

#[cfg(test)]
mod proptests {
    use super::truncate_string;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn truncate_respects_byte_limit(
            input in ".{0,256}",
            max_bytes in 1u32..128,
        ) {
            let (out, truncated) = truncate_string(input.clone(), max_bytes);
            prop_assert!(out.len() <= max_bytes as usize);
            if input.len() <= max_bytes as usize {
                prop_assert_eq!(out, input);
                prop_assert!(!truncated);
            } else {
                prop_assert!(truncated);
            }
        }
    }
}

//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::permissions::{command_allowed, ElevationPolicy, ShellPolicy};
use hecate_protocol::policy::{self, PolicyError};
use hecate_protocol::task::TaskExecutionPolicy;
use std::collections::{HashMap, HashSet};

/// Agent-side policy re-validation (defense in depth).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentPolicy {
    pub allowed_commands: HashSet<String>,
    pub shell_policy: ShellPolicy,
    pub elevation_policy: ElevationPolicy,
    pub max_output_bytes: u32,
    pub max_file_bytes: u32,
    pub timeout_secs: u32,
}

impl AgentPolicy {
    pub fn new(allowed_commands: Vec<String>, shell_policy: ShellPolicy) -> Self {
        Self {
            allowed_commands: allowed_commands.into_iter().collect(),
            shell_policy,
            elevation_policy: ElevationPolicy::default(),
            max_output_bytes: 65_536,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            timeout_secs: 30,
        }
    }

    pub fn new_with_elevation(
        allowed_commands: Vec<String>,
        shell_policy: ShellPolicy,
        elevation_policy: ElevationPolicy,
    ) -> Self {
        Self {
            allowed_commands: allowed_commands.into_iter().collect(),
            shell_policy,
            elevation_policy,
            max_output_bytes: 65_536,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            timeout_secs: 30,
        }
    }

    pub fn from_execution_policy(
        execution_policy: &TaskExecutionPolicy,
        timeout_secs: u32,
    ) -> Self {
        Self {
            allowed_commands: execution_policy
                .allowed_commands
                .iter()
                .cloned()
                .collect(),
            shell_policy: execution_policy.shell_policy.clone(),
            elevation_policy: execution_policy.elevation_policy.clone(),
            max_output_bytes: execution_policy.max_output_bytes,
            max_file_bytes: execution_policy.max_file_bytes,
            timeout_secs,
        }
    }

    pub fn allows_command(&self, name: &str) -> bool {
        command_allowed(
            &self.allowed_commands.iter().cloned().collect::<Vec<_>>(),
            name,
        )
    }

    pub fn validate_file_path(&self, path: &str) -> Result<(), PolicyError> {
        policy::check_cwd_policy(path, &self.shell_policy.allowed_cwd)
    }

    pub fn validate_remote_download_url(&self, url: &str) -> Result<(), String> {
        hecate_protocol::remote_download_policy::check_remote_download_url(url)
            .map_err(|error| error.to_string())
    }

    pub fn validate_shell_argv(&self, argv: &[String]) -> Result<(), PolicyError> {
        policy::check_shell_policy(argv, &self.shell_policy.allowed_binaries)
    }

    pub fn validate_cwd(&self, cwd: &str) -> Result<(), PolicyError> {
        policy::check_cwd_policy(cwd, &self.shell_policy.allowed_cwd)
    }

    pub fn validate_env(&self, env: &HashMap<String, String>) -> Result<(), PolicyError> {
        policy::check_env_policy(env, &self.shell_policy.allowed_env)
    }

    pub fn validate_shell_run(
        &self,
        argv: &[String],
        cwd: &str,
        env: &HashMap<String, String>,
        elevated: bool,
    ) -> Result<(), PolicyError> {
        if elevated {
            policy::check_elevation_policy(argv, &self.elevation_policy)?;
        } else {
            self.validate_shell_argv(argv)?;
        }
        self.validate_cwd(cwd)?;
        self.validate_env(env)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> AgentPolicy {
        AgentPolicy::new(
            vec!["system.info".into(), "shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec!["/usr/bin/uptime".into(), "/usr/bin/echo".into()],
                allowed_cwd: vec!["/tmp".into()],
                allowed_env: vec![],
            },
        )
    }

    #[test]
    fn allows_registered_command() {
        let p = test_policy();
        assert!(p.allows_command("system.info"));
        assert!(!p.allows_command("shell.exec"));
    }

    #[test]
    fn allows_any_command_when_wildcard_present() {
        let p = AgentPolicy::new(vec!["*".into()], ShellPolicy::default());
        assert!(p.allows_command("system.info"));
        assert!(p.allows_command("custom.command"));
    }

    #[test]
    fn rejects_shell_metacharacters() {
        let p = test_policy();
        let err = p
            .validate_shell_run(
                &["/usr/bin/echo".into(), "hello; rm".into()],
                "/tmp",
                &HashMap::new(),
                false,
            )
            .unwrap_err();
        assert!(matches!(err, PolicyError::Metacharacter { .. }));
    }

    #[test]
    fn rejects_disallowed_binary() {
        let p = test_policy();
        let err = p
            .validate_shell_run(&["/bin/sh".into(), "-c".into(), "id".into()], "/tmp", &HashMap::new(), false)
            .unwrap_err();
        assert!(matches!(err, PolicyError::BinaryNotAllowed { .. }));
    }

    #[test]
    fn rejects_disallowed_cwd() {
        let p = test_policy();
        let err = p
            .validate_shell_run(&["/usr/bin/uptime".into()], "/etc", &HashMap::new(), false)
            .unwrap_err();
        assert!(matches!(err, PolicyError::CwdNotAllowed { .. }));
    }

    #[test]
    fn allows_subdirectory_cwd() {
        let p = test_policy();
        p.validate_shell_run(&["/usr/bin/uptime".into()], "/tmp/nested", &HashMap::new(), false)
            .unwrap();
    }

    #[test]
    fn rejects_disallowed_env_vars() {
        let p = test_policy();
        let mut env = HashMap::new();
        env.insert("SECRET".into(), "x".into());
        let err = p
            .validate_shell_run(&["/usr/bin/uptime".into()], "/tmp", &env, false)
            .unwrap_err();
        assert!(matches!(err, PolicyError::EnvNotAllowed { .. }));
    }

    #[test]
    fn blocks_dangerous_env_even_with_wildcard() {
        let p = AgentPolicy::new(
            vec!["shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec!["/usr/bin/uptime".into()],
                allowed_cwd: vec!["/tmp".into()],
                allowed_env: vec!["*".into()],
            },
        );
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".into(), "/tmp/evil.so".into());
        let err = p
            .validate_shell_run(&["/usr/bin/uptime".into()], "/tmp", &env, false)
            .unwrap_err();
        assert!(matches!(err, PolicyError::DangerousEnv { .. }));
    }

    #[test]
    fn accepts_valid_shell_run() {
        let mut p = test_policy();
        p.shell_policy.allowed_env = vec!["LANG".into()];
        let mut env = HashMap::new();
        env.insert("LANG".into(), "C".into());
        p.validate_shell_run(&["/usr/bin/uptime".into()], "/tmp", &env, false).unwrap();
    }

    #[test]
    fn from_execution_policy_applies_wildcard_shell_policy() {
        let policy = AgentPolicy::from_execution_policy(
            &TaskExecutionPolicy {
                allowed_commands: vec!["*".into()],
                shell_policy: ShellPolicy {
                    allowed_binaries: vec!["*".into()],
                    allowed_cwd: vec!["/".into()],
                    allowed_env: vec![],
                },
                elevation_policy: ElevationPolicy::default(),
                max_output_bytes: 1_048_576,
                max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            },
            30,
        );
        policy
            .validate_shell_run(&["/usr/bin/uptime".into()], "/tmp", &HashMap::new(), false)
            .unwrap();
        assert!(policy.allows_command("shell.run"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use hecate_protocol::permissions::ShellPolicy;
    use proptest::prelude::*;

    fn shell_policy() -> AgentPolicy {
        AgentPolicy::new(
            vec!["shell.run".into()],
            ShellPolicy {
                allowed_binaries: vec!["/usr/bin/uptime".into(), "/usr/bin/echo".into()],
                allowed_cwd: vec!["/tmp".into()],
                allowed_env: vec![],
            },
        )
    }

    const METACHAR: [char; 9] = [';', '|', '&', '`', '$', '>', '<', '\n', '\r'];

    proptest! {
        #[test]
        fn agent_rejects_same_metacharacters_as_protocol(arg in ".+") {
            if arg.chars().any(|c| METACHAR.contains(&c)) {
                let policy = shell_policy();
                prop_assert!(policy
                    .validate_shell_run(&["/usr/bin/echo".into(), arg], "/tmp", &HashMap::new(), false)
                    .is_err());
            }
        }
    }
}

//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Local enrollment reset for lampad agents.

use std::path::PathBuf;

use crate::config::AgentConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetEnrollmentOptions {
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub runtime_status_path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForgetEnrollmentReport {
    pub removed_config: bool,
    pub removed_key: bool,
    pub removed_runtime_status: bool,
    pub had_agent_id: bool,
}

/// Remove local enrollment material (config, key, runtime status).
///
/// This does not contact the Hecate server. Revoke the machine in the UI when
/// the agent should no longer be trusted.
pub fn forget_agent_enrollment(
    options: ForgetEnrollmentOptions,
) -> anyhow::Result<ForgetEnrollmentReport> {
    let mut report = ForgetEnrollmentReport::default();

    if options.config_path.exists() {
        report.had_agent_id = AgentConfig::load(&options.config_path)
            .ok()
            .and_then(|config| config.agent_id)
            .is_some();
        std::fs::remove_file(&options.config_path)?;
        report.removed_config = true;
    }

    if options.key_path.exists() {
        std::fs::remove_file(&options.key_path)?;
        report.removed_key = true;
    }

    if options.runtime_status_path.exists() {
        std::fs::remove_file(&options.runtime_status_path)?;
        report.removed_runtime_status = true;
    }

    Ok(report)
}

pub fn print_forget_report(report: &ForgetEnrollmentReport) {
    if !report.removed_config && !report.removed_key && !report.removed_runtime_status {
        println!("No local enrollment material found; agent is already unenrolled on this host.");
        return;
    }

    println!("Local enrollment cleared.");
    if report.removed_config {
        println!("  - removed agent config");
    }
    if report.removed_key {
        println!("  - removed agent key");
    }
    if report.removed_runtime_status {
        println!("  - removed runtime status");
    }

    if report.had_agent_id {
        println!();
        println!(
            "The agent was forgotten locally. Revoke it in the Hecate UI if it should no longer access the fleet."
        );
    }

    println!();
    println!("Stop the agent service if it is still running, create a new enrollment token, then run:");
    println!("  hecate-lampad enroll --server-url <url> --token-file <path>");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn forget_removes_config_key_and_runtime_status() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let key_path = dir.path().join("agent.key");
        let runtime_path = dir.path().join("status.json");

        let config = AgentConfig {
            server_url: "https://hecate.example".into(),
            agent_id: Some(Uuid::new_v4()),
            config_path: config_path.clone(),
            key_path: key_path.clone(),
            ..AgentConfig::default()
        };
        config.save().unwrap();
        std::fs::write(&key_path, b"seed").unwrap();
        std::fs::write(&runtime_path, b"{}").unwrap();

        let report = forget_agent_enrollment(ForgetEnrollmentOptions {
            config_path,
            key_path: key_path.clone(),
            runtime_status_path: runtime_path.clone(),
        })
        .unwrap();

        assert!(report.removed_config);
        assert!(report.removed_key);
        assert!(report.removed_runtime_status);
        assert!(report.had_agent_id);
        assert!(!key_path.exists());
        assert!(!runtime_path.exists());
    }

    #[test]
    fn forget_is_idempotent_when_already_clean() {
        let dir = TempDir::new().unwrap();
        let report = forget_agent_enrollment(ForgetEnrollmentOptions {
            config_path: dir.path().join("config.toml"),
            key_path: dir.path().join("agent.key"),
            runtime_status_path: dir.path().join("status.json"),
        })
        .unwrap();

        assert_eq!(report, ForgetEnrollmentReport::default());
    }
}

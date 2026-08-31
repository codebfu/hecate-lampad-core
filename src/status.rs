//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Agent status collection and reporting.

use crate::agent_state_sync::sync_config_agent_state_from_server;
use crate::client::{AgentClient, ReachabilityResult};
use crate::host::local_hostname;
use crate::config::AgentConfig;
use crate::runtime::{format_runtime_mode, read_runtime_status, RuntimeStatusSnapshot};
use crate::signing::AgentKeypair;
use crate::AGENT_VERSION;
use hecate_protocol::agent::{AgentState, AgentStatusResponse};
use serde::Serialize;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Missing,
    Invalid,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Active,
    Inactive,
    Failed,
    NotFound,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LocalStatus {
    pub config: CheckStatus,
    pub config_path: PathBuf,
    pub config_error: Option<String>,
    pub key: CheckStatus,
    pub key_path: PathBuf,
    pub key_error: Option<String>,
    pub agent_id: Option<Uuid>,
    pub agent_state: Option<AgentState>,
    pub server_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ServiceReport {
    pub name: String,
    pub status: ServiceStatus,
    pub detail: Option<String>,
    pub runtime: Option<RuntimeStatusSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ServerStatus {
    pub url: Option<String>,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub reachability_error: Option<String>,
    pub state: Option<AgentState>,
    pub hostname: Option<String>,
    pub fetch_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentStatusReport {
    pub version: &'static str,
    pub service_version: Option<String>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub local: LocalStatus,
    pub service: ServiceReport,
    pub server: ServerStatus,
    pub next_steps: Vec<String>,
    pub exit_code: i32,
}

pub trait ServiceProbe: Send + Sync {
    fn probe(&self) -> ServiceReport;
}

pub struct NoServiceProbe;

impl ServiceProbe for NoServiceProbe {
    fn probe(&self) -> ServiceReport {
        ServiceReport {
            name: "agent-service".into(),
            status: ServiceStatus::NotApplicable,
            detail: Some("service probe not available on this platform".into()),
            runtime: None,
        }
    }
}

pub struct StatusOptions {
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub service_name: String,
    pub service_start_hint: String,
    pub enroll_hint: String,
    pub runtime_status_path: PathBuf,
}

pub async fn collect_status(
    options: StatusOptions,
    service_probe: &dyn ServiceProbe,
) -> AgentStatusReport {
    let hostname = local_hostname();

    let mut local = inspect_local(&options.config_path, &options.key_path);
    let mut service = service_probe.probe();
    if service.status == ServiceStatus::Active {
        service.runtime = read_runtime_status(&options.runtime_status_path);
    }
    let service_version = service.runtime.as_ref().map(|runtime| runtime.version.clone());
    let server = inspect_server(&local, &options.key_path).await;

    if local.config == CheckStatus::Ok {
        if let Some(server_state) = server.state {
            if local.agent_state != Some(server_state) {
                match sync_config_agent_state_from_server(&options.config_path, server_state) {
                    Ok(true) => local.agent_state = Some(server_state),
                    Ok(false) => {}
                    Err(error) => tracing::warn!(
                        error = %error,
                        "failed to sync cached agent state from server"
                    ),
                }
            }
        }
    }

    let mut next_steps = Vec::new();
    let exit_code = derive_next_steps(
        &local,
        &service,
        &server,
        &options.service_start_hint,
        &options.enroll_hint,
        &mut next_steps,
    );

    AgentStatusReport {
        version: AGENT_VERSION,
        service_version,
        hostname,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        local,
        service,
        server,
        next_steps,
        exit_code,
    }
}

fn inspect_local(config_path: &Path, key_path: &Path) -> LocalStatus {
    let mut local = LocalStatus {
        config: CheckStatus::Missing,
        config_path: config_path.to_path_buf(),
        config_error: None,
        key: CheckStatus::Missing,
        key_path: key_path.to_path_buf(),
        key_error: None,
        agent_id: None,
        agent_state: None,
        server_url: None,
    };

    if config_path.exists() {
        match AgentConfig::load(config_path) {
            Ok(config) => {
                local.config = CheckStatus::Ok;
                local.agent_id = config.agent_id;
                local.agent_state = config.agent_state;
                local.server_url = if config.server_url.is_empty() {
                    None
                } else {
                    Some(config.server_url)
                };
            }
            Err(error) => {
                local.config = CheckStatus::Invalid;
                local.config_error = Some(error.to_string());
            }
        }
    }

    if key_path.exists() {
        match inspect_key(key_path) {
            Ok(()) => local.key = CheckStatus::Ok,
            Err(error) => {
                local.key = CheckStatus::Invalid;
                local.key_error = Some(error);
            }
        }
    }

    local
}

fn inspect_key(key_path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(key_path).map_err(|error| error.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte seed, got {} bytes", bytes.len()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key_path)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(format!("expected mode 0600, got {mode:o}"));
        }
    }

    Ok(())
}

async fn inspect_server(local: &LocalStatus, key_path: &Path) -> ServerStatus {
    let Some(server_url) = local.server_url.clone() else {
        return ServerStatus {
            url: None,
            reachable: false,
            latency_ms: None,
            reachability_error: Some("server URL not configured".into()),
            state: None,
            hostname: None,
            fetch_error: None,
        };
    };

    let client = match AgentClient::new() {
        Ok(client) => client,
        Err(error) => {
            return ServerStatus {
                url: Some(server_url),
                reachable: false,
                latency_ms: None,
                reachability_error: Some(error.to_string()),
                state: None,
                hostname: None,
                fetch_error: None,
            };
        }
    };

    let ReachabilityResult {
        reachable,
        latency_ms,
        error,
    } = client.check_reachability(&server_url).await;

    let mut server = ServerStatus {
        url: Some(server_url.clone()),
        reachable,
        latency_ms,
        reachability_error: error,
        state: local.agent_state,
        hostname: None,
        fetch_error: None,
    };

    let Some(agent_id) = local.agent_id else {
        return server;
    };

    if local.key != CheckStatus::Ok {
        server.fetch_error = Some("agent key is missing or invalid".into());
        return server;
    }

    let keypair = match AgentKeypair::load(key_path) {
        Ok(keypair) => keypair,
        Err(error) => {
            server.fetch_error = Some(error.to_string());
            return server;
        }
    };

    match client
        .fetch_agent_status(&server_url, agent_id, &keypair)
        .await
    {
        Ok(AgentStatusResponse {
            state,
            hostname,
            ..
        }) => {
            server.state = Some(state);
            server.hostname = Some(hostname);
        }
        Err(error) => {
            server.fetch_error = Some(error.to_string());
        }
    }

    server
}

fn derive_next_steps(
    local: &LocalStatus,
    service: &ServiceReport,
    server: &ServerStatus,
    service_start_hint: &str,
    enroll_hint: &str,
    next_steps: &mut Vec<String>,
) -> i32 {
    if local.config == CheckStatus::Missing && local.key == CheckStatus::Missing {
        if service.status != ServiceStatus::Active {
            next_steps.push(format!("Run: {enroll_hint}"));
        } else {
            next_steps.push(format!("Run: {enroll_hint}"));
            next_steps.push(
                "The agent service is running and will pick up enrollment automatically".into(),
            );
        }
        return 1;
    }

    if local.config == CheckStatus::Invalid {
        next_steps.push(format!(
            "Fix config at {}: {}",
            local.config_path.display(),
            local.config_error.as_deref().unwrap_or("invalid")
        ));
        return 1;
    }

    if local.key == CheckStatus::Missing {
        next_steps.push(format!(
            "Re-run enrollment to create the agent key at {}",
            local.key_path.display()
        ));
        return 1;
    }

    if local.key == CheckStatus::Invalid {
        next_steps.push(format!(
            "Fix agent key at {}: {}",
            local.key_path.display(),
            local.key_error.as_deref().unwrap_or("invalid")
        ));
        return 1;
    }

    if local.agent_id.is_none() {
        next_steps.push(format!(
            "Agent ID is missing — create a re-enrollment token in Machines → agent detail, then run: {enroll_hint}"
        ));
        return 1;
    }

    let mut needs_action = false;

    if !server.reachable {
        needs_action = true;
        next_steps.push(format!(
            "Server is unreachable{} — check network and server URL",
            server
                .reachability_error
                .as_ref()
                .map(|error| format!(" ({error})"))
                .unwrap_or_default()
        ));
    }

    if let Some(error) = &server.fetch_error {
        needs_action = true;
        next_steps.push(format!("Could not fetch server agent state: {error}"));
    }

    let effective_state = server.state.or(local.agent_state);

    match effective_state {
        Some(AgentState::PendingApproval) => {
            needs_action = true;
            next_steps
                .push("Wait for admin approval in the Hecate UI (Machines page)".into());
            if service.status != ServiceStatus::Active {
                next_steps.push(format!("Then: {service_start_hint}"));
            }
        }
        Some(AgentState::Revoked) => {
            needs_action = true;
            next_steps.push("Agent is revoked on the server — contact an administrator".into());
        }
        Some(AgentState::Active) => {
            if service.status == ServiceStatus::Inactive
                || service.status == ServiceStatus::Failed
                || service.status == ServiceStatus::NotFound
            {
                needs_action = true;
                next_steps.push(format!("Start the agent service: {service_start_hint}"));
            }
        }
        None => {
            if server.reachable {
                needs_action = true;
                next_steps.push("Server agent state is unknown — verify enrollment on the server".into());
            }
        }
    }

    if needs_action {
        return 2;
    }

    if server.state == Some(AgentState::Active)
        && (service.status == ServiceStatus::Active
            || service.status == ServiceStatus::NotApplicable)
    {
        return 0;
    }

    if server.state == Some(AgentState::Active) && service.status == ServiceStatus::Unknown {
        return 2;
    }

    0
}

pub fn print_status_report(report: &AgentStatusReport) {
    println!("Agent version (binary): {}", report.version);
    if let Some(service_version) = &report.service_version {
        println!("Service version:        {service_version}");
    }
    println!(
        "Hostname:               {} ({}/{})",
        report.hostname, report.os, report.arch
    );
    println!();
    println!("Local");
    print_check(
        "  Config",
        report.local.config,
        &report.local.config_path.display().to_string(),
        report.local.config_error.as_deref(),
    );
    print_check(
        "  Key",
        report.local.key,
        &report.local.key_path.display().to_string(),
        report.local.key_error.as_deref(),
    );
    match report.local.agent_id {
        Some(agent_id) => println!("  Agent ID: set ({agent_id})"),
        None => println!("  Agent ID: not set"),
    }
    if let Some(state) = report.local.agent_state {
        println!("  Cached state: {}", format_agent_state(state));
    }
    println!();
    println!("Service");
    println!(
        "  {}: {}{}",
        report.service.name,
        format_service_status(report.service.status),
        report
            .service
            .detail
            .as_ref()
            .map(|detail| format!(" ({detail})"))
            .unwrap_or_default()
    );
    if let Some(runtime) = &report.service.runtime {
        println!("  Mode:    {}", format_runtime_mode(runtime.mode));
        println!("  Uptime:  {}s", runtime.uptime_secs);
        if let Some(detail) = &runtime.detail {
            println!("  Detail:  {detail}");
        }
    } else if report.service.status == ServiceStatus::Active {
        println!("  Runtime: status file not available yet");
    }
    println!();
    if let Some(url) = &report.server.url {
        println!("Server ({url})");
    } else {
        println!("Server");
    }
    if report.server.reachable {
        let latency = report
            .server
            .latency_ms
            .map(|ms| format!(" ({ms}ms)"))
            .unwrap_or_default();
        println!("  Reachable: yes{latency}");
    } else {
        println!(
            "  Reachable: no{}",
            report
                .server
                .reachability_error
                .as_ref()
                .map(|error| format!(" ({error})"))
                .unwrap_or_default()
        );
    }
    if let Some(state) = report.server.state {
        println!("  State:     {}", format_agent_state(state));
    } else if report.local.agent_id.is_some() {
        println!("  State:     unknown");
    }
    if let Some(error) = &report.server.fetch_error {
        println!("  Error:     {error}");
    }
    if !report.next_steps.is_empty() {
        println!();
        println!("Next steps:");
        for step in &report.next_steps {
            println!("  - {step}");
        }
    }
}

pub fn print_status_json(report: &AgentStatusReport) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

fn print_check(label: &str, status: CheckStatus, path: &str, detail: Option<&str>) {
    let status_label = match status {
        CheckStatus::Ok => "ok",
        CheckStatus::Missing => "missing",
        CheckStatus::Invalid => "invalid",
        CheckStatus::Warning => "warning",
    };
    let suffix = detail
        .map(|detail| format!(", {detail}"))
        .unwrap_or_default();
    println!("{label}:   {status_label} ({path}{suffix})");
}

fn format_agent_state(state: AgentState) -> &'static str {
    match state {
        AgentState::PendingApproval => "pending_approval",
        AgentState::Active => "active",
        AgentState::Revoked => "revoked",
    }
}

fn format_service_status(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Active => "active",
        ServiceStatus::Inactive => "inactive",
        ServiceStatus::Failed => "failed",
        ServiceStatus::NotFound => "not-found",
        ServiceStatus::Unknown => "unknown",
        ServiceStatus::NotApplicable => "n/a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::runtime::write_runtime_status;
    use crate::signing::AgentKeypair;
    use tempfile::TempDir;

    struct StaticServiceProbe {
        report: ServiceReport,
    }

    impl ServiceProbe for StaticServiceProbe {
        fn probe(&self) -> ServiceReport {
            self.report.clone()
        }
    }

    #[test]
    fn inspect_key_rejects_wrong_size() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("agent.key");
        std::fs::write(&key_path, b"short").unwrap();
        let error = inspect_key(&key_path).unwrap_err();
        assert!(error.contains("32-byte"));
    }

    #[test]
    fn inspect_local_missing_files() {
        let dir = TempDir::new().unwrap();
        let local = inspect_local(
            &dir.path().join("config.toml"),
            &dir.path().join("agent.key"),
        );
        assert_eq!(local.config, CheckStatus::Missing);
        assert_eq!(local.key, CheckStatus::Missing);
        assert!(local.agent_id.is_none());
    }

    #[test]
    fn inspect_local_reads_config_and_key() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let key_path = dir.path().join("agent.key");
        let agent_id = Uuid::new_v4();

        let config = AgentConfig {
            server_url: "https://hecate.example.com".into(),
            agent_id: Some(agent_id),
            agent_state: Some(AgentState::PendingApproval),
            config_path: config_path.clone(),
            key_path: key_path.clone(),
            ..Default::default()
        };
        config.save().unwrap();
        AgentKeypair::load_or_generate(&key_path).unwrap();

        let local = inspect_local(&config_path, &key_path);
        assert_eq!(local.config, CheckStatus::Ok);
        assert_eq!(local.key, CheckStatus::Ok);
        assert_eq!(local.agent_id, Some(agent_id));
        assert_eq!(local.agent_state, Some(AgentState::PendingApproval));
    }

    #[tokio::test]
    async fn collect_status_reads_service_runtime_version() {
        let dir = TempDir::new().unwrap();
        let runtime_path = dir.path().join("status.json");
        write_runtime_status(
            &runtime_path,
            crate::runtime::RuntimeMode::WaitingForEnrollment,
            std::time::Instant::now(),
            None,
        )
        .unwrap();

        let probe = StaticServiceProbe {
            report: ServiceReport {
                name: "hecate-lampad".into(),
                status: ServiceStatus::Active,
                detail: Some("active".into()),
                runtime: None,
            },
        };
        let report = collect_status(
            StatusOptions {
                config_path: dir.path().join("config.toml"),
                key_path: dir.path().join("agent.key"),
                service_name: "hecate-lampad".into(),
                service_start_hint: "systemctl enable --now hecate-lampad".into(),
                enroll_hint: "hecate-lampad enroll --server-url ...".into(),
                runtime_status_path: runtime_path,
            },
            &probe,
        )
        .await;

        assert_eq!(report.service_version.as_deref(), Some(AGENT_VERSION));
        assert!(report.service.runtime.is_some());
    }

    #[tokio::test]
    async fn collect_status_not_enrolled_exit_code() {
        let dir = TempDir::new().unwrap();
        let probe = StaticServiceProbe {
            report: ServiceReport {
                name: "hecate-lampad".into(),
                status: ServiceStatus::NotFound,
                detail: None,
                runtime: None,
            },
        };
        let report = collect_status(
            StatusOptions {
                config_path: dir.path().join("config.toml"),
                key_path: dir.path().join("agent.key"),
                service_name: "hecate-lampad".into(),
                service_start_hint: "systemctl enable --now hecate-lampad".into(),
                enroll_hint: "hecate-lampad enroll --server-url ...".into(),
                runtime_status_path: dir.path().join("status.json"),
            },
            &probe,
        )
        .await;
        assert_eq!(report.exit_code, 1);
        assert!(!report.next_steps.is_empty());
    }

    #[test]
    fn status_report_serializes_to_json() {
        let report = AgentStatusReport {
            version: "0.1.0",
            service_version: None,
            hostname: "test-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            local: LocalStatus {
                config: CheckStatus::Missing,
                config_path: PathBuf::from("/etc/hecate-lampad/config.toml"),
                config_error: None,
                key: CheckStatus::Missing,
                key_path: PathBuf::from("/etc/hecate-lampad/agent.key"),
                key_error: None,
                agent_id: None,
                agent_state: None,
                server_url: None,
            },
            service: ServiceReport {
                name: "hecate-lampad".into(),
                status: ServiceStatus::Inactive,
                detail: None,
                runtime: None,
            },
            server: ServerStatus {
                url: None,
                reachable: false,
                latency_ms: None,
                reachability_error: None,
                state: None,
                hostname: None,
                fetch_error: None,
            },
            next_steps: vec!["Run enroll".into()],
            exit_code: 1,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"exit_code\":1"));
        assert!(json.contains("\"hostname\":\"test-host\""));
    }
}

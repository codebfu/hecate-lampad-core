//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared agent logic for Hecate lampad agents.

pub mod agent_run;
pub mod agent_update;
pub mod cli;
pub mod client;
pub mod commands;
pub mod config;
pub mod desktop_ipc;
pub mod desktop_update;
pub mod proxmox_ipc;
pub mod proxmox_update;
pub mod enroll;
pub mod forget;
pub mod elevation;
pub mod host;
pub mod key_material;
pub mod paths;
pub mod package_update;
pub mod policy;
pub mod pull;
pub mod runtime;
pub mod signing;
pub mod self_update;
pub mod service_restart;
pub mod status;
pub mod tags;
pub mod task_verify;
pub mod updater;

/// Agent release version (aligned with platform package VERSION via `HECATE_AGENT_VERSION` at build time).
pub const AGENT_VERSION: &str = env!("HECATE_AGENT_VERSION");

pub use agent_run::{run_agent_service, AgentRunOptions};
pub use agent_update::{run_agent_update, AgentUpdateCliError, AgentUpdateOptions};
pub use cli::{
    command_with_defaults, generate_completion, generate_completions_to_dir, parse_with_defaults,
    Cli, Commands, PlatformDefaults, BIN_NAME,
};
pub use client::{AgentClient, HttpPullClient};
pub use host::local_hostname;
pub use commands::{
    AgentCommand, CommandContext, CommandError, CommandOutput, CommandRegistry,
    DefaultCommandRegistry,
};
pub use config::AgentConfig;
pub use enroll::{
    build_enroll_request, load_enrollment_keypair, prepare_agent_enrollment, print_enroll_success,
    read_enrollment_token, submit_enrollment,
};
pub use forget::{
    forget_agent_enrollment, print_forget_report, ForgetEnrollmentOptions, ForgetEnrollmentReport,
};
pub use paths::secure_agent_paths;
pub use policy::AgentPolicy;
pub use pull::{
    AgentHealthSnapshot, AgentSessionState, HeartbeatThread, PullClient, PullConfig, PullError,
    PullLoop, pull_stale_after,
};
pub use runtime::{
    default_runtime_status_path, format_runtime_mode, read_runtime_status, RuntimeMode,
    RuntimeStatusSnapshot,
};
pub use signing::{AgentKeypair, SignedRequestHeaders};
pub use status::{
    collect_status, print_status_json, print_status_report, AgentStatusReport, NoServiceProbe,
    ServiceProbe, ServiceReport, ServiceStatus, StatusOptions,
};
pub use tags::{collect_agent_tags, collect_default_tags};

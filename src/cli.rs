//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared CLI definition and shell completion generation for lampad agents.

use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use std::io;
use std::path::PathBuf;

pub const BIN_NAME: &str = "hecate-lampad";

/// Platform-specific default paths and CLI metadata.
#[derive(Clone, Copy, Debug)]
pub struct PlatformDefaults {
    pub about: &'static str,
    pub config: &'static str,
    pub key_path: &'static str,
}

#[derive(Parser, Debug)]
#[command(name = BIN_NAME, version = crate::AGENT_VERSION)]
struct CliArgs {
    /// Agent config file path.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Ed25519 private key file path.
    #[arg(long, global = true)]
    key_path: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

/// Parsed CLI with platform defaults applied to shared path flags.
#[derive(Debug)]
pub struct Cli {
    pub config: PathBuf,
    pub key_path: PathBuf,
    /// True when `--key-path` was passed on the command line.
    pub key_path_explicit: bool,
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Enroll this machine with the Hecate server (one-shot).
    Enroll {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Custom machine tags (namespace:value), comma-separated.
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Run the agent pull loop (long-running).
    Run,
    /// Download and apply the latest server release for this agent.
    Update {
        /// Check whether an update is available without applying it.
        #[arg(long)]
        check: bool,
    },
    /// Show enrollment and agent health status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completion scripts to stdout.
    #[command(hide = true)]
    Complete {
        shell: Shell,
    },
}

/// Build the CLI command with platform-specific defaults applied to flags.
pub fn command_with_defaults(defaults: PlatformDefaults) -> clap::Command {
    CliArgs::command()
        .about(defaults.about)
        .mut_arg("config", |arg| arg.default_value(defaults.config))
        .mut_arg("key_path", |arg| arg.default_value(defaults.key_path))
}

/// Parse CLI arguments using platform-specific defaults.
pub fn parse_with_defaults(defaults: PlatformDefaults) -> Cli {
    resolve_cli(defaults, &command_with_defaults(defaults).get_matches())
}

fn resolve_cli(defaults: PlatformDefaults, matches: &clap::ArgMatches) -> Cli {
    let args = CliArgs::from_arg_matches(matches).unwrap_or_else(|error| error.exit());
    let key_path_explicit = matches
        .value_source("key_path")
        .is_some_and(|source| source != ValueSource::DefaultValue);
    Cli {
        config: args
            .config
            .unwrap_or_else(|| PathBuf::from(defaults.config)),
        key_path: args
            .key_path
            .unwrap_or_else(|| PathBuf::from(defaults.key_path)),
        key_path_explicit,
        command: args.command,
    }
}

/// Write shell completion scripts for the given shell to stdout.
pub fn generate_completion(defaults: PlatformDefaults, shell: Shell) -> io::Result<()> {
    let mut cmd = command_with_defaults(defaults);
    clap_complete::generate(shell, &mut cmd, BIN_NAME, &mut io::stdout());
    Ok(())
}

/// Write shell completion scripts into `output_dir` (used from build scripts).
pub fn generate_completions_to_dir(
    defaults: PlatformDefaults,
    output_dir: &std::path::Path,
) -> io::Result<()> {
    use clap_complete::generate_to;

    std::fs::create_dir_all(output_dir.join("bash"))?;
    std::fs::create_dir_all(output_dir.join("zsh"))?;
    std::fs::create_dir_all(output_dir.join("fish"))?;
    std::fs::create_dir_all(output_dir.join("powershell"))?;

    let mut cmd = command_with_defaults(defaults);
    generate_to(
        Shell::Bash,
        &mut cmd,
        BIN_NAME,
        output_dir.join("bash"),
    )?;
    generate_to(
        Shell::Zsh,
        &mut cmd,
        BIN_NAME,
        output_dir.join("zsh"),
    )?;
    generate_to(
        Shell::Fish,
        &mut cmd,
        BIN_NAME,
        output_dir.join("fish"),
    )?;
    generate_to(
        Shell::PowerShell,
        &mut cmd,
        BIN_NAME,
        output_dir.join("powershell"),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULTS: PlatformDefaults = PlatformDefaults {
        about: "test",
        config: "/etc/hecate-lampad/config.toml",
        key_path: "/etc/hecate-lampad/agent.key",
    };

    #[test]
    fn status_uses_platform_defaults_without_explicit_flags() {
        let matches = command_with_defaults(DEFAULTS)
            .try_get_matches_from(["hecate-lampad", "status"])
            .expect("status should parse with default config and key paths");
        let cli = resolve_cli(DEFAULTS, &matches);
        assert_eq!(cli.config, PathBuf::from(DEFAULTS.config));
        assert_eq!(cli.key_path, PathBuf::from(DEFAULTS.key_path));
        assert!(!cli.key_path_explicit);
        assert!(matches!(cli.command, Commands::Status { json: false }));
    }

    #[test]
    fn key_path_explicit_when_provided_on_command_line() {
        let matches = command_with_defaults(DEFAULTS)
            .try_get_matches_from([
                "hecate-lampad",
                "status",
                "--key-path",
                "/custom/agent.key",
            ])
            .expect("status should accept explicit key path");
        let cli = resolve_cli(DEFAULTS, &matches);
        assert!(cli.key_path_explicit);
        assert_eq!(cli.key_path, PathBuf::from("/custom/agent.key"));
    }

    #[test]
    fn shared_flags_apply_to_enroll_without_explicit_paths() {
        let matches = command_with_defaults(DEFAULTS)
            .try_get_matches_from([
                "hecate-lampad",
                "enroll",
                "--server-url",
                "https://hecate.example.com",
                "--token",
                "secret",
            ])
            .expect("enroll should parse");
        let cli = resolve_cli(DEFAULTS, &matches);
        assert_eq!(cli.config, PathBuf::from(DEFAULTS.config));
        assert_eq!(cli.key_path, PathBuf::from(DEFAULTS.key_path));
        assert!(!cli.key_path_explicit);
    }

    #[test]
    fn update_command_parses_check_flag() {
        let matches = command_with_defaults(DEFAULTS)
            .try_get_matches_from(["hecate-lampad", "update", "--check"])
            .expect("update should parse");
        let cli = resolve_cli(DEFAULTS, &matches);
        assert!(matches!(cli.command, Commands::Update { check: true }));
    }
}

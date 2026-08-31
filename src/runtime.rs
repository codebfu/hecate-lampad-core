//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime status snapshot written by the long-running agent service.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long the service sleeps between readiness checks while waiting for enrollment.
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    WaitingForEnrollment,
    PendingApproval,
    Pulling,
    ConfigInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeStatusSnapshot {
    pub version: String,
    pub mode: RuntimeMode,
    pub pid: u32,
    pub uptime_secs: u64,
    pub updated_at_unix: u64,
    pub detail: Option<String>,
}

pub fn default_runtime_status_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        return PathBuf::from("/run/hecate-lampad/status.json");
    }
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/var/run/hecate-lampad/status.json");
    }
    #[cfg(windows)]
    {
        return PathBuf::from(r"C:\ProgramData\hecate-lampad\runtime\status.json");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        PathBuf::from("/tmp/hecate-lampad-status.json")
    }
}

pub fn read_runtime_status(path: &Path) -> Option<RuntimeStatusSnapshot> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn write_runtime_status(
    path: &Path,
    mode: RuntimeMode,
    started_at: Instant,
    detail: Option<String>,
) -> std::io::Result<()> {
    let snapshot = RuntimeStatusSnapshot {
        version: crate::AGENT_VERSION.to_string(),
        mode,
        pid: std::process::id(),
        uptime_secs: started_at.elapsed().as_secs(),
        updated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        detail,
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string(&snapshot)?;
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        let _ = std::fs::remove_file(path);
    }
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, content)?;
    }
    Ok(())
}

pub fn format_runtime_mode(mode: RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::WaitingForEnrollment => "waiting_for_enrollment",
        RuntimeMode::PendingApproval => "pending_approval",
        RuntimeMode::Pulling => "pulling",
        RuntimeMode::ConfigInvalid => "config_invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn runtime_status_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("status.json");
        write_runtime_status(
            &path,
            RuntimeMode::WaitingForEnrollment,
            Instant::now(),
            Some("config not found".into()),
        )
        .unwrap();

        let snapshot = read_runtime_status(&path).expect("status file");
        assert_eq!(snapshot.version, crate::AGENT_VERSION);
        assert_eq!(snapshot.mode, RuntimeMode::WaitingForEnrollment);
        assert_eq!(snapshot.detail.as_deref(), Some("config not found"));
    }
}

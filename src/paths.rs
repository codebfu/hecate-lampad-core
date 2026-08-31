//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Secure filesystem permissions for agent config and keys.

use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

/// Apply service-user ownership and permissions after enrollment.
///
/// Enrollment is typically run as root; the agent LaunchDaemon / systemd unit
/// runs as `hecate-lampad` and must own config + key afterward.
pub fn secure_agent_paths(config_path: &Path, key_path: &Path) {
    #[cfg(not(unix))]
    let _ = (config_path, key_path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = config_path.parent() {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
        }
        if config_path.exists() {
            let _ = std::fs::set_permissions(config_path, std::fs::Permissions::from_mode(0o640));
        }
        if key_path.exists() {
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    chown_service_user(config_path, key_path);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn service_owner_spec() -> &'static str {
    // Linux packages create a matching primary group; macOS sysadminctl users
    // typically use wheel/staff — match packaging postinstall (`hecate-lampad:wheel`).
    if cfg!(target_os = "macos") {
        "hecate-lampad:wheel"
    } else {
        "hecate-lampad:hecate-lampad"
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn chown_service_user(config_path: &Path, key_path: &Path) {
    let owner = service_owner_spec();

    for path in [config_path, key_path] {
        if !path.exists() {
            continue;
        }
        let _ = Command::new("chown").arg(owner).arg(path).status();
    }

    if let Some(parent) = config_path.parent() {
        let _ = Command::new("chown").arg(owner).arg(parent).status();
    }
}

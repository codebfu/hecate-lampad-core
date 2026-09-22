//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Local IPC between hecate-lampad (system service) and helpers.

pub use hecate_lampad_helper_base::*;

pub mod client;

/// Build gui/display tags from helper presence and optional live info.
pub fn collect_gui_tags(info: Option<&DesktopInfoResult>) -> Vec<String> {
    if !helper_package_installed() {
        return Vec::new();
    }
    match info {
        Some(info) => {
            let mut tags = vec!["gui:ready".into()];
            let backend = info.display_backend.to_ascii_lowercase();
            let display = match backend.as_str() {
                "x11" => "display:x11",
                "wayland" => "display:wayland",
                "windows" => "display:windows",
                "macos" | "quartz" | "cocoa" => "display:macos",
                other if !other.is_empty() => {
                    tags.push(format!("display:{}", other.replace('_', "-")));
                    return tags;
                }
                _ => "display:unknown",
            };
            tags.push(display.into());
            tags
        }
        None => vec!["gui:none".into()],
    }
}

/// Best-effort fix when the helper created sock/token without the shared
/// `hecate-ipc` group (common when `sg` is unavailable and the GUI session
/// token lacks the supplementary group). Uses non-interactive sudo.
#[cfg(target_os = "linux")]
pub fn repair_desktop_ipc_permissions() {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    let socket = default_socket_path();
    let token = ipc_token_path(&socket);
    if !path_present(&socket) && !path_present(&token) {
        return;
    }

    let Some(expected_gid) = hecate_ipc_gid() else {
        return;
    };

    let mut needs_fix = false;
    for path in [&socket, &token] {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.gid() != expected_gid {
                needs_fix = true;
                break;
            }
        } else if path_present(path) {
            // Unreadable metadata still warrants a repair attempt.
            needs_fix = true;
            break;
        }
    }
    if !needs_fix {
        return;
    }

    let mut shell = String::from("set -e;");
    if path_present(&socket) {
        let p = shell_escape(&socket.display().to_string());
        shell.push_str(&format!(
            " chgrp {group} {p}; chmod 0660 {p};",
            group = IPC_GROUP_NAME,
            p = p
        ));
    }
    if path_present(&token) {
        let p = shell_escape(&token.display().to_string());
        shell.push_str(&format!(
            " chgrp {group} {p}; chmod 0640 {p};",
            group = IPC_GROUP_NAME,
            p = p
        ));
    }

    let program_argv = vec!["sh".into(), "-c".into(), shell];
    let argv = if crate::elevation::is_privileged() {
        program_argv
    } else {
        match crate::elevation::build_elevated_argv(&program_argv) {
            Ok(argv) => argv,
            Err(_) => return,
        }
    };

    match Command::new(&argv[0]).args(&argv[1..]).status() {
        Ok(status) if status.success() => {
            tracing::info!(
                socket = %socket.display(),
                token = %token.display(),
                "repaired desktop IPC ownership to hecate-ipc"
            );
        }
        Ok(status) => {
            tracing::warn!(%status, "failed to repair desktop IPC ownership");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to run desktop IPC ownership repair");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn repair_desktop_ipc_permissions() {}

#[cfg(target_os = "linux")]
fn hecate_ipc_gid() -> Option<u32> {
    use std::ffi::CString;
    let name = CString::new(IPC_GROUP_NAME).ok()?;
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return None;
    }
    Some(unsafe { (*group).gr_gid })
}

#[cfg(target_os = "linux")]
fn path_present(path: &std::path::Path) -> bool {
    // Prefer metadata: Path::exists can be false on some EACCES cases.
    std::fs::metadata(path).is_ok() || path.exists()
}

#[cfg(target_os = "linux")]
fn shell_escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Local IPC between hecate-lampad (system service) and hecate-lampad-proxmox (system helper).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

pub mod client;

// Reuse the length-prefixed JSON frame codec from desktop IPC.
pub use crate::desktop_ipc::{encode_frame, read_frame, IpcErrorBody, IpcRequest, IpcResponse};

/// Default Unix socket path for the Proxmox console helper (Linux hosts only).
pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/hecate-lampad/proxmox.sock")
    }
    #[cfg(not(target_os = "linux"))]
    {
        PathBuf::from("/tmp/hecate-lampad-proxmox.sock")
    }
}

/// Path used to detect whether the Proxmox helper package is installed.
pub fn helper_binary_candidates() -> &'static [&'static str] {
    &[
        "/usr/bin/hecate-lampad-proxmox",
        "/usr/local/bin/hecate-lampad-proxmox",
    ]
}

pub fn helper_package_installed() -> bool {
    helper_binary_candidates()
        .iter()
        .any(|path| std::path::Path::new(path).exists())
}

#[derive(Debug, Error)]
pub enum ProxmoxIpcError {
    #[error("helper_unavailable: proxmox helper is not connected")]
    HelperUnavailable,
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("ipc io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc protocol error: {0}")]
    Protocol(String),
    #[error("{0}")]
    Remote(String),
}

/// Auth token path beside `proxmox.sock` (does not share desktop's `ipc.token`).
pub fn ipc_token_path(socket_path: &std::path::Path) -> PathBuf {
    socket_path.with_file_name("proxmox.ipc.token")
}

pub fn read_ipc_token(socket_path: &std::path::Path) -> Result<String, ProxmoxIpcError> {
    let path = ipc_token_path(socket_path);
    let token = std::fs::read_to_string(&path).map_err(|_| ProxmoxIpcError::HelperUnavailable)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(ProxmoxIpcError::HelperUnavailable);
    }
    Ok(token)
}

pub fn write_ipc_token(socket_path: &std::path::Path, token: &str) -> Result<(), std::io::Error> {
    let path = ipc_token_path(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() || std::fs::symlink_metadata(&path).is_ok() {
        let _ = std::fs::remove_file(&path);
    }
    {
        use std::io::Write;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            file.write_all(token.as_bytes())?;
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
                .open(&path)?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxmoxInfoResult {
    pub helper_version: String,
    pub node: String,
    pub pve_tools_present: bool,
    pub preferred_backend: String,
    pub fallback_backend: String,
    #[serde(default)]
    pub active_sessions: Vec<String>,
    #[serde(default)]
    pub mock_mode: bool,
}

#[derive(Debug, Clone)]
pub struct CaptureResult {
    pub meta: Value,
    pub bytes: Vec<u8>,
}

pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn map_remote_error(error: &IpcErrorBody) -> ProxmoxIpcError {
    match error.code.as_str() {
        "helper_unavailable" | "unauthorized" => ProxmoxIpcError::HelperUnavailable,
        _ => ProxmoxIpcError::Remote(format!("{}: {}", error.code, error.message)),
    }
}

/// Build proxmox:* tags from helper presence and optional live info.
pub fn collect_proxmox_tags(info: Option<&ProxmoxInfoResult>) -> Vec<String> {
    if !helper_package_installed() {
        return Vec::new();
    }
    match info {
        Some(_) => vec!["proxmox:console".into()],
        None => vec!["proxmox:none".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn token_sits_beside_proxmox_socket() {
        let socket = PathBuf::from("/run/hecate-lampad/proxmox.sock");
        assert_eq!(
            ipc_token_path(&socket),
            PathBuf::from("/run/hecate-lampad/proxmox.ipc.token")
        );
    }

    #[test]
    fn tags_absent_without_package() {
        // Without the binary installed, no tags.
        assert!(collect_proxmox_tags(None).is_empty() || !helper_package_installed());
        if !helper_package_installed() {
            assert!(collect_proxmox_tags(Some(&ProxmoxInfoResult {
                helper_version: "1.0.0".into(),
                node: "pve".into(),
                pve_tools_present: true,
                preferred_backend: "local_vnc".into(),
                fallback_backend: "pve_api".into(),
                active_sessions: vec![],
                mock_mode: false,
            }))
            .is_empty());
        }
    }
}

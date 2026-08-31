//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Locate and version the optional hecate-lampad-proxmox helper binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PROXMOX_VERSION_CACHE_TTL: Duration = Duration::from_secs(60);

struct ProxmoxVersionCache {
    checked_at: Instant,
    version: Option<String>,
}

static PROXMOX_VERSION_CACHE: Mutex<Option<ProxmoxVersionCache>> = Mutex::new(None);

pub fn proxmox_binary_candidates() -> Vec<PathBuf> {
    vec![PathBuf::from("/usr/bin/hecate-lampad-proxmox")]
}

pub fn find_proxmox_binary() -> Option<PathBuf> {
    for candidate in proxmox_binary_candidates() {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let output = Command::new("which")
        .arg("hecate-lampad-proxmox")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();
    if path.is_empty() {
        return None;
    }
    let path = PathBuf::from(path);
    path.is_file().then_some(path)
}

pub fn parse_proxmox_version_output(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?.trim();
    let version = line.split_whitespace().nth(1)?;
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

pub fn invalidate_proxmox_version_cache() {
    if let Ok(mut guard) = PROXMOX_VERSION_CACHE.lock() {
        *guard = None;
    }
}

pub fn installed_proxmox_version() -> Option<String> {
    if let Ok(guard) = PROXMOX_VERSION_CACHE.lock() {
        if let Some(cache) = guard.as_ref() {
            if cache.checked_at.elapsed() < PROXMOX_VERSION_CACHE_TTL {
                return cache.version.clone();
            }
        }
    }

    let version = find_proxmox_binary().and_then(|path| proxmox_version_at(&path));
    if let Ok(mut guard) = PROXMOX_VERSION_CACHE.lock() {
        *guard = Some(ProxmoxVersionCache {
            checked_at: Instant::now(),
            version: version.clone(),
        });
    }
    version
}

fn proxmox_version_at(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_proxmox_version_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::parse_proxmox_version_output;

    #[test]
    fn parses_version_line() {
        assert_eq!(
            parse_proxmox_version_output("hecate-lampad-proxmox 1.2.3\n"),
            Some("1.2.3".into())
        );
    }
}

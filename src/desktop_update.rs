//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Locate and version the optional hecate-lampad-desktop helper binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DESKTOP_VERSION_CACHE_TTL: Duration = Duration::from_secs(60);

struct DesktopVersionCache {
    checked_at: Instant,
    version: Option<String>,
}

static DESKTOP_VERSION_CACHE: Mutex<Option<DesktopVersionCache>> = Mutex::new(None);

/// Candidate install paths for the desktop helper (package defaults).
pub fn desktop_binary_candidates() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![PathBuf::from("/usr/bin/hecate-lampad-desktop")]
    }
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/usr/local/bin/hecate-lampad-desktop")]
    }
    #[cfg(target_os = "windows")]
    {
        vec![PathBuf::from(
            r"C:\Program Files\hecate-lampad-desktop\hecate-lampad-desktop.exe",
        )]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Return the installed desktop helper path, if present.
pub fn find_desktop_binary() -> Option<PathBuf> {
    for candidate in desktop_binary_candidates() {
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    // Fall back to PATH lookup.
    let output = Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg("hecate-lampad-desktop")
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

/// Parse `hecate-lampad-desktop --version` output (`hecate-lampad-desktop 1.3.0`).
pub fn parse_desktop_version_output(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?.trim();
    let version = line.split_whitespace().nth(1)?;
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

/// Drop the cached desktop helper version (e.g. after applying an update).
pub fn invalidate_desktop_version_cache() {
    if let Ok(mut guard) = DESKTOP_VERSION_CACHE.lock() {
        *guard = None;
    }
}

/// Read the installed desktop helper version, when available.
pub fn installed_desktop_version() -> Option<String> {
    if let Ok(guard) = DESKTOP_VERSION_CACHE.lock() {
        if let Some(cache) = guard.as_ref() {
            if cache.checked_at.elapsed() < DESKTOP_VERSION_CACHE_TTL {
                return cache.version.clone();
            }
        }
    }

    let version = find_desktop_binary().and_then(|path| desktop_version_at(&path));
    if let Ok(mut guard) = DESKTOP_VERSION_CACHE.lock() {
        *guard = Some(DesktopVersionCache {
            checked_at: Instant::now(),
            version: version.clone(),
        });
    }
    version
}

pub fn desktop_version_at(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_desktop_version_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_line() {
        assert_eq!(
            parse_desktop_version_output("hecate-lampad-desktop 1.2.3\n"),
            Some("1.2.3".into())
        );
    }
}

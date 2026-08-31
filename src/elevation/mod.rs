//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! OS-dependent privileged execution for shell.run when `elevated: true`.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
use std::process::Stdio;

/// How the agent elevates privileges on this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationMethod {
    Sudo,
    WindowsAdmin,
    Unsupported,
}

pub fn elevation_method() -> ElevationMethod {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if resolve_sudo_path().is_some() {
            ElevationMethod::Sudo
        } else {
            ElevationMethod::Unsupported
        }
    }
    #[cfg(target_os = "windows")]
    {
        ElevationMethod::WindowsAdmin
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        ElevationMethod::Unsupported
    }
}

pub fn elevation_method_name() -> &'static str {
    match elevation_method() {
        ElevationMethod::Sudo => "sudo",
        ElevationMethod::WindowsAdmin => "windows_admin",
        ElevationMethod::Unsupported => "none",
    }
}

pub fn elevation_supported() -> bool {
    !matches!(elevation_method(), ElevationMethod::Unsupported)
}

/// Build argv for privileged execution. Returns the argv passed to execve.
pub fn build_elevated_argv(program_argv: &[String]) -> Result<Vec<String>, String> {
    if program_argv.is_empty() {
        return Err("argv must not be empty".into());
    }

    match elevation_method() {
        ElevationMethod::Sudo => build_sudo_argv(program_argv),
        ElevationMethod::WindowsAdmin => build_windows_admin_argv(program_argv),
        ElevationMethod::Unsupported => {
            Err("elevated execution is not supported on this platform".into())
        }
    }
}

fn build_sudo_argv(program_argv: &[String]) -> Result<Vec<String>, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let sudo = resolve_sudo_path().ok_or_else(|| {
            "sudo not found; install the sudo package and reinstall hecate-lampad".to_string()
        })?;
        let mut argv = vec![sudo, "-n".into(), "--".into()];
        argv.extend(program_argv.iter().cloned());
        Ok(argv)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = program_argv;
        Err("sudo elevation is not available on this platform".into())
    }
}

fn build_windows_admin_argv(program_argv: &[String]) -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        if is_windows_admin()? {
            Ok(program_argv.to_vec())
        } else {
            Err(
                "elevated execution requires the agent service to run as Administrator or LocalSystem"
                    .into(),
            )
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = program_argv;
        Err("windows admin elevation is not available on this platform".into())
    }
}

/// Probe whether non-interactive elevation is currently available.
pub fn elevation_available() -> bool {
    match elevation_method() {
        ElevationMethod::Sudo => probe_sudo(),
        ElevationMethod::WindowsAdmin => is_windows_admin().unwrap_or(false),
        ElevationMethod::Unsupported => false,
    }
}

pub fn effective_user() -> String {
    for var in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    effective_uid()
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn effective_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        std::process::Command::new("id")
            .arg("-u")
            .stdin(Stdio::null())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|text| text.trim().parse().ok())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

pub fn is_privileged() -> bool {
    effective_uid() == Some(0) || is_windows_admin().unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_sudo_path() -> Option<String> {
    for candidate in ["/usr/bin/sudo", "/bin/sudo", "/usr/sbin/sudo"] {
        if Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn probe_sudo() -> bool {
    let Some(sudo) = resolve_sudo_path() else {
        return false;
    };
    let auth_ok = std::process::Command::new(&sudo)
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !auth_ok {
        return false;
    }
    probe_sudo_writable(&sudo)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_test_path() -> Option<String> {
    for candidate in ["/usr/bin/test", "/bin/test"] {
        if Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn probe_sudo_writable(sudo: &str) -> bool {
    let Some(test) = resolve_test_path() else {
        return false;
    };
    for path in ["/var/cache/apt", "/var/tmp", "/tmp"] {
        if !Path::new(path).exists() {
            continue;
        }
        let ok = std::process::Command::new(sudo)
            .args(["-n", "--", &test, "-w", path])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn probe_sudo_writable(sudo: &str) -> bool {
    let Some(test) = resolve_test_path() else {
        return false;
    };
    for path in ["/var/tmp", "/tmp"] {
        if !Path::new(path).exists() {
            continue;
        }
        let ok = std::process::Command::new(sudo)
            .args(["-n", "--", &test, "-w", path])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe_sudo() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn is_windows_admin() -> Result<bool, String> {
    std::process::Command::new("net")
        .arg("session")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "windows"))]
fn is_windows_admin() -> Result<bool, String> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_elevated_argv_rejects_empty() {
        assert!(build_elevated_argv(&[]).is_err());
    }

    #[test]
    fn effective_user_is_non_empty() {
        assert!(!effective_user().is_empty());
    }
}

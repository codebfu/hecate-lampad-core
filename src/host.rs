//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Local hostname resolution for agents and status reporting.

/// Returns the local machine hostname.
///
/// Environment variables (`HOSTNAME`, `COMPUTERNAME`) are checked first, then
/// platform-specific sources such as `/etc/hostname` or the `hostname` command.
pub fn local_hostname() -> String {
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() && trimmed != "unknown" {
                return trimmed.to_string();
            }
        }
    }

    read_system_hostname().unwrap_or_else(|| "unknown".into())
}

fn read_system_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/hostname") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if let Ok(output) = std::process::Command::new("hostname").output() {
            if output.status.success() {
                let trimmed = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_hostname_is_non_empty() {
        let hostname = local_hostname();
        assert!(!hostname.is_empty());
    }
}

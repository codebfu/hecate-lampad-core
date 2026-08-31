//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Helpers to bring the agent service back after a self-update.

/// Schedule a service restart when the current process will exit after replacing
/// its own binary. Linux/macOS supervisors restart clean exits via unit policy;
/// Windows SCM does not unless recovery is configured, so we kick `sc start`.
pub fn schedule_restart_after_self_update() {
    #[cfg(windows)]
    {
        schedule_windows_service_start("hecate-lampad", 3);
    }
}

/// Failsafe when a detached package installer should restart the service.
///
/// If `dpkg`/`msiexec` fails or never starts the unit, this delayed start brings
/// the previous binary back online.
pub fn schedule_install_failsafe() {
    #[cfg(target_os = "linux")]
    {
        schedule_linux_install_failsafe("hecate-lampad", 90);
    }
    #[cfg(target_os = "macos")]
    {
        schedule_macos_install_failsafe(90);
    }
    #[cfg(windows)]
    {
        // Primary failsafe lives inside the schtasks install script. This second
        // SYSTEM task covers the case where the install task never ran.
        schedule_windows_service_start("hecate-lampad", 120);
    }
}

#[cfg(target_os = "linux")]
fn schedule_linux_install_failsafe(service_name: &str, delay_secs: u64) {
    use std::process::{Command, Stdio};

    let script = format!(
        "sleep {delay_secs}; systemctl is-active --quiet {service_name} || systemctl start {service_name}"
    );
    match Command::new("nohup")
        .args(["bash", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => {
            std::mem::forget(child);
            tracing::info!(
                %service_name,
                delay_secs,
                "scheduled Linux service start failsafe after package install"
            );
        }
        Err(error) => tracing::warn!(
            %service_name,
            error = %error,
            "failed to schedule Linux install failsafe"
        ),
    }
}

#[cfg(target_os = "macos")]
fn schedule_macos_install_failsafe(delay_secs: u64) {
    use std::process::{Command, Stdio};

    let script = format!(
        "sleep {delay_secs}; \
launchctl print system/com.hecate.lampad >/dev/null 2>&1 || \
launchctl bootstrap system /Library/LaunchDaemons/com.hecate.lampad.plist >/dev/null 2>&1 || true; \
launchctl kickstart -k system/com.hecate.lampad >/dev/null 2>&1 || true"
    );
    match Command::new("/usr/bin/sudo")
        .args(["-n", "--", "/usr/bin/nohup", "/bin/bash", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => {
            std::mem::forget(child);
            tracing::info!(
                delay_secs,
                "scheduled macOS LaunchDaemon start failsafe after PKG install"
            );
        }
        Err(error) => tracing::warn!(
            error = %error,
            "failed to schedule macOS install failsafe"
        ),
    }
}

#[cfg(windows)]
fn schedule_windows_service_start(service_name: &str, delay_secs: u64) {
    use std::process::{Command, Stdio};

    // Child processes of the Windows service are killed with the service (job
    // object). Schedule a SYSTEM task so `sc start` survives service stop.
    let dir = if let Ok(program_data) = std::env::var("ProgramData") {
        std::path::PathBuf::from(program_data).join("hecate-lampad")
    } else {
        std::path::PathBuf::from(r"C:\ProgramData\hecate-lampad")
    };
    let _ = std::fs::create_dir_all(&dir);
    let task_name = if delay_secs >= 60 {
        "hecate-lampad-start-failsafe"
    } else {
        "hecate-lampad-start-after-update"
    };
    let script_path = dir.join(format!("{task_name}.cmd"));
    let body = format!(
        "@echo off\r\n\
         timeout /t {delay_secs} /nobreak >nul\r\n\
         sc query {service_name} | find \"RUNNING\" >nul\r\n\
         if errorlevel 1 sc start {service_name}\r\n\
         schtasks /Delete /TN \"{task_name}\" /F >nul 2>&1\r\n\
         del /f /q \"%~f0\"\r\n"
    );
    if script_path.exists() || std::fs::symlink_metadata(&script_path).is_ok() {
        let _ = std::fs::remove_file(&script_path);
    }
    {
        use std::io::Write;
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let write_result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&script_path)?;
            file.write_all(body.as_bytes())?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            tracing::warn!(
                %service_name,
                error = %error,
                "failed to write Windows service start script"
            );
            return;
        }
    }

    let tr = format!("cmd.exe /c \"{}\"", script_path.display());
    let create = Command::new("schtasks")
        .args([
            "/Create",
            "/TN",
            task_name,
            "/TR",
            &tr,
            "/SC",
            "ONCE",
            "/ST",
            "00:00",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match create {
        Ok(status) if status.success() => {}
        Ok(status) => {
            tracing::warn!(
                %service_name,
                %status,
                "schtasks create for service start failed"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                %service_name,
                error = %error,
                "schtasks create for service start failed to spawn"
            );
            return;
        }
    }

    match Command::new("schtasks")
        .args(["/Run", "/TN", task_name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => tracing::info!(
            %service_name,
            delay_secs,
            %task_name,
            "scheduled Windows SYSTEM task for service start"
        ),
        Ok(status) => tracing::warn!(
            %service_name,
            %status,
            "schtasks run for service start failed"
        ),
        Err(error) => tracing::warn!(
            %service_name,
            error = %error,
            "schtasks run for service start failed to spawn"
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn schedule_restart_is_callable() {
        // No-op on non-Windows; on Windows spawning sc is best-effort and safe.
        super::schedule_restart_after_self_update();
    }

    #[test]
    #[cfg(windows)]
    fn schedule_failsafe_is_callable() {
        super::schedule_install_failsafe();
    }

    #[test]
    #[cfg(not(windows))]
    fn schedule_failsafe_symbol_exists() {
        // Avoid spawning a long-lived sleep failsafe during unit tests on Linux.
        let _ = super::schedule_install_failsafe as fn();
    }
}

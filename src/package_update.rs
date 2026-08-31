//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Installer-package self-update for Linux (.deb), Windows (.msi), and macOS (.pkg).
//!
//! The agent downloads and verifies packages, launches the package manager in a
//! detached process, then lets the installer stop/restart the service. A
//! failsafe later starts the service if the installer never brings it back.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tracing::{info, warn};
use uuid::Uuid;

use crate::client::HttpPullClient;
use crate::elevation;
use crate::signing::AgentKeypair;
use crate::updater::{
    stage_artifact, staging_path_for, UpdateArtifact, Updater, UpdaterError, SelfUpdateParams,
};

fn write_private_file(path: &Path, bytes: &[u8], unix_mode: u32) -> Result<(), UpdaterError> {
    #[cfg(not(unix))]
    let _ = unix_mode;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(UpdaterError::from)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(parent).map_err(UpdaterError::from)?;
            if meta.permissions().mode() & 0o002 != 0 {
                return Err(UpdaterError::Aborted(format!(
                    "refusing to write install script under world-writable directory {}",
                    parent.display()
                )));
            }
        }
    }
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(unix_mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                UpdaterError::Aborted(format!(
                    "create {} (O_NOFOLLOW): {error}",
                    path.display()
                ))
            })?;
        file.write_all(bytes)?;
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
            .open(path)
            .map_err(|error| {
                UpdaterError::Aborted(format!("create {}: {error}", path.display()))
            })?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(UpdaterError::from)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

/// True when this platform applies updates via installer packages instead of
/// raw binary replacement.
pub fn uses_installer_packages() -> bool {
    cfg!(any(target_os = "linux", target_os = "windows", target_os = "macos"))
}

/// Package installs run as root via sudo (Linux/macOS) or a SYSTEM task (Windows).
/// Fail fast when the service user cannot elevate — otherwise we spawn a detached
/// installer that silently fails and agent.update reports a false success.
pub fn require_package_install_elevation() -> Result<(), UpdaterError> {
    if !uses_installer_packages() {
        return Ok(());
    }
    if elevation::is_privileged() || elevation::elevation_available() {
        return Ok(());
    }
    Err(UpdaterError::Aborted(package_install_elevation_hint()))
}

fn package_install_elevation_hint() -> String {
    #[cfg(target_os = "linux")]
    {
        return "package install requires root privileges but non-interactive elevation is unavailable; \
                reinstall the hecate-lampad deb package (or run install-elevation-policy.sh as root) \
                so /etc/sudoers.d/hecate-lampad is present, and ensure the systemd unit sets \
                ProtectSystem=no without ReadWritePaths= (that pair fails with exit 226/NAMESPACE)"
            .into();
    }
    #[cfg(target_os = "macos")]
    {
        return "package install requires root privileges but non-interactive sudo is unavailable; \
                reinstall the hecate-lampad pkg (or run install-elevation-policy.sh as root) \
                so /etc/sudoers.d/hecate-lampad is present"
            .into();
    }
    #[cfg(target_os = "windows")]
    {
        return "package install requires the hecate-lampad Windows service to run as LocalSystem \
                or another Administrator account (reinstall the MSI if the service account was changed)"
            .into();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "package install is not supported on this platform".into()
    }
}

/// Download, verify, and launch detached package installs (desktop then agent).
///
/// Returns after the installer process has been spawned. Does not wait for the
/// install to finish — the package manager stops the agent service when needed.
pub async fn launch_package_updates(
    packages: &[SelfUpdateParams],
    client: Option<&HttpPullClient>,
    agent_id: Uuid,
    keypair: &AgentKeypair,
) -> Result<(), UpdaterError> {
    if packages.is_empty() {
        return Err(UpdaterError::Aborted("no packages to install".into()));
    }
    require_package_install_elevation()?;

    let mut staged = Vec::with_capacity(packages.len());
    for params in packages {
        if params.release_public_key_b64.trim().is_empty() {
            return Err(UpdaterError::ReleaseKeyMissing);
        }
        let staging_path = package_staging_path(params);
        if let Err(error) = stage_artifact(
            &params.artifact_path,
            &staging_path,
            client,
            agent_id,
            keypair,
        )
        .await
        {
            cleanup_staged(&staged);
            let _ = std::fs::remove_file(&staging_path);
            return Err(error);
        }

        let updater = Updater::new(PathBuf::from("unused"));
        let artifact = UpdateArtifact {
            target_version: params.target_version.clone(),
            staging_path: staging_path.clone(),
            expected_sha256: params.sha256.clone(),
            signature: params.signature.clone(),
            release_public_key_b64: params.release_public_key_b64.clone(),
            release_public_key_previous_b64: params.release_public_key_previous_b64.clone(),
            kind: params.kind.clone(),
        };
        if let Err(error) = updater.verify_artifact(&artifact) {
            cleanup_staged(&staged);
            let _ = std::fs::remove_file(&staging_path);
            return Err(error);
        }
        // Re-verify immediately before handing paths to the detached installer.
        if let Err(error) = updater.verify_artifact(&artifact) {
            cleanup_staged(&staged);
            let _ = std::fs::remove_file(&staging_path);
            return Err(error);
        }

        staged.push(InstallPackage {
            path: staging_path,
            expected_sha256: params.sha256.to_lowercase(),
        });
    }

    let package_paths: Vec<PathBuf> = staged.iter().map(|pkg| pkg.path.clone()).collect();
    let includes_agent = packages.iter().any(|params| params.kind == "self_update");

    if let Err(error) = spawn_detached_installer(&staged) {
        cleanup_staged(&staged);
        return Err(error);
    }

    if includes_agent {
        crate::service_restart::schedule_install_failsafe();
    }

    info!(
        count = package_paths.len(),
        includes_agent,
        "detached package installer launched"
    );
    Ok(())
}

/// Download, verify, and run a single package install in-process (desktop-only).
pub async fn apply_package_update_blocking(
    params: &SelfUpdateParams,
    client: Option<&HttpPullClient>,
    agent_id: Uuid,
    keypair: &AgentKeypair,
) -> Result<(), UpdaterError> {
    if params.release_public_key_b64.trim().is_empty() {
        return Err(UpdaterError::ReleaseKeyMissing);
    }
    require_package_install_elevation()?;

    let staging_path = package_staging_path(params);
    if let Err(error) = stage_artifact(
        &params.artifact_path,
        &staging_path,
        client,
        agent_id,
        keypair,
    )
    .await
    {
        let _ = std::fs::remove_file(&staging_path);
        return Err(error);
    }

    let updater = Updater::new(PathBuf::from("unused"));
    let artifact = UpdateArtifact {
        target_version: params.target_version.clone(),
        staging_path: staging_path.clone(),
        expected_sha256: params.sha256.clone(),
        signature: params.signature.clone(),
        release_public_key_b64: params.release_public_key_b64.clone(),
        release_public_key_previous_b64: params.release_public_key_previous_b64.clone(),
        kind: params.kind.clone(),
    };

    if let Err(error) = updater.verify_artifact(&artifact) {
        let _ = std::fs::remove_file(&staging_path);
        return Err(error);
    }

    let staged = [InstallPackage {
        path: staging_path.clone(),
        expected_sha256: params.sha256.to_lowercase(),
    }];
    let result = run_installer_blocking(&staged);
    // On Windows the SYSTEM task installs asynchronously from the staged MSI;
    // the install script deletes the package when finished.
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::fs::remove_file(&staging_path);
    }
    #[cfg(target_os = "windows")]
    {
        if result.is_err() {
            let _ = std::fs::remove_file(&staging_path);
        }
    }
    result?;

    // Detect false-success MSI runs that leave a missing/placeholder binary.
    if params.kind == "desktop_update" {
        crate::desktop_update::invalidate_desktop_version_cache();
        let Some(path) = crate::desktop_update::find_desktop_binary() else {
            return Err(UpdaterError::Aborted(
                "desktop package install reported success but helper binary is missing".into(),
            ));
        };
        let meta = std::fs::metadata(&path).map_err(|error| {
            UpdaterError::Aborted(format!(
                "desktop package install reported success but cannot stat {}: {error}",
                path.display()
            ))
        })?;
        // Real helper binaries are multi-MB; catch no-op installs that leave a stub.
        if meta.len() < 1_000_000 {
            return Err(UpdaterError::Aborted(format!(
                "desktop package install reported success but {} is only {} bytes",
                path.display(),
                meta.len()
            )));
        }
    }

    if params.kind == "proxmox_update" {
        crate::proxmox_update::invalidate_proxmox_version_cache();
        let Some(path) = crate::proxmox_update::find_proxmox_binary() else {
            return Err(UpdaterError::Aborted(
                "proxmox package install reported success but helper binary is missing".into(),
            ));
        };
        let meta = std::fs::metadata(&path).map_err(|error| {
            UpdaterError::Aborted(format!(
                "proxmox package install reported success but cannot stat {}: {error}",
                path.display()
            ))
        })?;
        if meta.len() < 500_000 {
            return Err(UpdaterError::Aborted(format!(
                "proxmox package install reported success but {} is only {} bytes",
                path.display(),
                meta.len()
            )));
        }
    }

    Ok(())
}

/// After launching an installer that should stop this process, wait briefly so
/// we do not resume the pull loop before the package manager acts.
pub fn wait_for_installer_stop(max_wait: Duration) {
    let step = Duration::from_secs(1);
    let mut waited = Duration::ZERO;
    while waited < max_wait {
        std::thread::sleep(step);
        waited += step;
    }
    warn!(
        waited_secs = waited.as_secs(),
        "installer did not stop the agent process; continuing"
    );
}

fn package_staging_path(params: &SelfUpdateParams) -> PathBuf {
    let base = match &params.install_path {
        Some(path) => staging_path_for(path, &params.kind, &params.target_version),
        None => {
            let dummy = PathBuf::from(default_package_stem());
            staging_path_for(&dummy, &params.kind, &params.target_version)
        }
    };
    with_package_extension(base)
}

fn default_package_stem() -> &'static str {
    "hecate-lampad"
}

fn with_package_extension(path: PathBuf) -> PathBuf {
    let ext = package_extension();
    let as_str = path.to_string_lossy();
    if as_str.ends_with(ext) {
        return path;
    }
    PathBuf::from(format!("{as_str}{ext}"))
}

fn package_extension() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        ".msi"
    }
    #[cfg(target_os = "macos")]
    {
        ".pkg"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        ".deb"
    }
}

fn cleanup_staged(staged: &[InstallPackage]) {
    for package in staged {
        let _ = std::fs::remove_file(&package.path);
    }
}

#[derive(Clone)]
struct InstallPackage {
    path: PathBuf,
    expected_sha256: String,
}

fn spawn_detached_installer(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    #[cfg(target_os = "linux")]
    {
        spawn_linux_detached(packages)
    }
    #[cfg(target_os = "windows")]
    {
        spawn_windows_detached(packages)
    }
    #[cfg(target_os = "macos")]
    {
        spawn_macos_detached(packages)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = packages;
        Err(UpdaterError::Aborted(
            "installer packages are not supported on this platform".into(),
        ))
    }
}

fn run_installer_blocking(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    #[cfg(target_os = "linux")]
    {
        run_linux_dpkg(packages)
    }
    #[cfg(target_os = "windows")]
    {
        // Same SYSTEM-task path as agent updates: force-replace + durable logs.
        let log_path = windows_agent_data_dir().join("package-update.log");
        let _ = std::fs::remove_file(&log_path);
        let script_path = write_windows_install_script(packages)?;
        run_windows_system_task(
            "hecate-lampad-pkg-update",
            &script_path,
            "desktop package installer",
        )?;
        wait_for_windows_install_log(&log_path, Duration::from_secs(300))
    }
    #[cfg(target_os = "macos")]
    {
        run_macos_pkg_install(packages)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = packages;
        Err(UpdaterError::Aborted(
            "installer packages are not supported on this platform".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn spawn_linux_detached(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    let script = write_linux_install_script(packages)?;
    let log_path = install_log_path();
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // nohup keeps the shell alive after the agent service is stopped.
    let child = Command::new("nohup")
        .arg("bash")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| UpdaterError::Aborted(format!("failed to spawn installer: {error}")))?;

    // Detach: drop Child without waiting.
    std::mem::forget(child);
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_linux_install_script(packages: &[InstallPackage]) -> Result<PathBuf, UpdaterError> {
    let dir = agent_writable_dir().ok_or_else(|| {
        UpdaterError::Aborted(
            "no private agent runtime directory for install scripts (refusing world-writable temp)"
                .into(),
        )
    })?;
    let _ = std::fs::create_dir_all(&dir);
    let script_path = dir.join(format!(
        "hecate-lampad-install-{}-{:016x}.sh",
        std::process::id(),
        rand::random::<u64>()
    ));
    let log_path = install_log_path();

    let mut body = String::from("#!/bin/bash\nset -eu\n");
    body.push_str(&format!(
        "exec >>'{}' 2>&1\n",
        log_path.display()
    ));
    body.push_str("echo \"$(date -Is) hecate-lampad package install starting\"\n");
    // Let the agent submit the command result before dpkg stops the service.
    body.push_str("sleep 3\n");
    if elevation::is_privileged() {
        body.push_str("echo \"$(date -Is) running package install as root\"\n");
    } else {
        body.push_str(
            "if ! sudo -n true 2>/dev/null; then\n  \
             echo \"$(date -Is) package install failed: sudo NOPASSWD is not configured for hecate-lampad (missing /etc/sudoers.d/hecate-lampad?)\"\n  \
             exit 1\nfi\n",
        );
    }
    for package in packages {
        let path = package.path.display().to_string();
        let expected = package.expected_sha256.to_lowercase();
        // Re-hash immediately before dpkg to close the staging TOCTOU window.
        body.push_str(&format!(
            "echo '{expected}  {path}' | sha256sum -c -\n"
        ));
        // Prefer non-interactive sudo (service user); fall back to plain dpkg as root.
        if elevation::is_privileged() {
            body.push_str(&format!("dpkg -i '{path}'\n"));
        } else {
            body.push_str(&format!("sudo -n -- dpkg -i '{path}'\n"));
        }
    }
    body.push_str("echo \"$(date -Is) hecate-lampad package install finished\"\n");
    // Best-effort start; failsafe also covers this.
    body.push_str("systemctl start hecate-lampad >/dev/null 2>&1 || true\n");
    body.push_str("systemctl restart hecate-lampad-proxmox >/dev/null 2>&1 || true\n");
    for package in packages {
        body.push_str(&format!("rm -f '{}'\n", package.path.display()));
    }
    body.push_str(&format!("rm -f '{}'\n", script_path.display()));

    write_private_file(&script_path, body.as_bytes(), 0o700)?;
    Ok(script_path)
}

#[cfg(target_os = "linux")]
fn run_linux_dpkg(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    let dpkg = resolve_bin(&["/usr/bin/dpkg", "/bin/dpkg"])
        .ok_or_else(|| UpdaterError::Aborted("dpkg not found".into()))?;
    for package in packages {
        let actual = Updater::sha256_nofollow(&package.path)?;
        if actual != package.expected_sha256.to_lowercase() {
            return Err(UpdaterError::HashMismatch {
                expected: package.expected_sha256.clone(),
                actual,
            });
        }
        let argv = if elevation::is_privileged() {
            vec![
                dpkg.clone(),
                "-i".into(),
                package.path.to_string_lossy().into_owned(),
            ]
        } else {
            elevation::build_elevated_argv(&[
                dpkg.clone(),
                "-i".into(),
                package.path.to_string_lossy().into_owned(),
            ])
            .map_err(UpdaterError::Aborted)?
        };

        let program = &argv[0];
        let output = Command::new(program)
            .args(&argv[1..])
            .stdin(Stdio::null())
            .output()
            .map_err(|error| {
                UpdaterError::Aborted(format!("failed to run {program}: {error}"))
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(UpdaterError::Aborted(if stderr.is_empty() {
                format!("{program} exited with {}", output.status)
            } else {
                format!("{program} failed: {stderr}")
            }));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}

#[cfg(target_os = "linux")]
fn write_dir_probe(dir: &Path) -> bool {
    let probe = dir.join(".hecate-update-write-probe");
    if probe.exists() || std::fs::symlink_metadata(&probe).is_ok() {
        let _ = std::fs::remove_file(&probe);
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&probe)
    else {
        return false;
    };
    if file.write_all(b"ok").is_err() {
        let _ = std::fs::remove_file(&probe);
        return false;
    }
    let _ = std::fs::remove_file(&probe);
    true
}

#[cfg(target_os = "linux")]
fn agent_writable_dir() -> Option<PathBuf> {
    for dir in [
        PathBuf::from("/run/hecate-lampad"),
        PathBuf::from("/var/run/hecate-lampad"),
        PathBuf::from("/var/lib/hecate-lampad"),
    ] {
        if dir.is_dir() && write_dir_probe(&dir) {
            return Some(dir);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn install_log_path() -> PathBuf {
    agent_writable_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib/hecate-lampad"))
        .join("package-update.log")
}

#[cfg(target_os = "macos")]
fn spawn_macos_detached(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    let script = write_macos_install_script(packages)?;
    let agent_log = macos_install_log_path();
    if let Some(parent) = agent_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // launchd opens StandardOut/Err before exec; keep these under /var/log so the
    // system domain job is not rejected with EX_CONFIG on a 0750 agent data dir.
    let launchd_log = PathBuf::from("/var/log/hecate-lampad-pkg-update.log");

    let label = "com.hecate.lampad-pkg-update";
    let plist_path = PathBuf::from("/Library/LaunchDaemons").join(format!("{label}.plist"));
    let staging_plist = macos_agent_writable_dir()
        .ok_or_else(|| {
            UpdaterError::Aborted(
                "no private agent data directory for LaunchDaemon staging plist".into(),
            )
        })?
        .join(format!("{label}-{}.plist", rand::random::<u64>()));
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
        script.display(),
        launchd_log.display(),
        launchd_log.display()
    );
    write_private_file(&staging_plist, plist.as_bytes(), 0o600)?;

    let launchd_log_s = launchd_log.to_string_lossy().into_owned();
    let staging_plist_s = staging_plist.to_string_lossy().into_owned();
    let plist_path_s = plist_path.to_string_lossy().into_owned();
    let bootout_label = format!("system/{label}");

    run_macos_root(&["/usr/bin/touch", &launchd_log_s])?;
    run_macos_root(&["/bin/chmod", "644", &launchd_log_s])?;
    run_macos_root(&["/bin/cp", "-f", &staging_plist_s, &plist_path_s])?;
    run_macos_root(&["/bin/chmod", "644", &plist_path_s])?;
    let _ = run_macos_root(&["/bin/launchctl", "bootout", &bootout_label]);
    run_macos_root(&["/bin/launchctl", "bootstrap", "system", &plist_path_s])?;

    info!(
        script = %script.display(),
        plist = %plist_path.display(),
        "scheduled macOS package update via LaunchDaemon"
    );
    let _ = std::fs::remove_file(&staging_plist);
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_macos_root(argv: &[&str]) -> Result<(), UpdaterError> {
    let output = if elevation::is_privileged() {
        Command::new(argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    } else {
        let mut cmd = Command::new("/usr/bin/sudo");
        cmd.arg("-n").arg("--");
        for arg in argv {
            cmd.arg(arg);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    }
    .map_err(|error| UpdaterError::Aborted(format!("failed to spawn {}: {error}", argv[0])))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Err(UpdaterError::Aborted(format!(
        "{} failed: {} {}",
        argv.join(" "),
        stdout,
        stderr
    )))
}

#[cfg(target_os = "macos")]
fn write_macos_install_script(packages: &[InstallPackage]) -> Result<PathBuf, UpdaterError> {
    let dir = macos_agent_writable_dir().ok_or_else(|| {
        UpdaterError::Aborted(
            "no private agent data directory for install scripts (refusing world-writable temp)"
                .into(),
        )
    })?;
    let _ = std::fs::create_dir_all(&dir);
    let script_path = dir.join(format!(
        "hecate-lampad-install-{}-{:016x}.sh",
        std::process::id(),
        rand::random::<u64>()
    ));
    let log_path = macos_install_log_path();

    // Do not use `set -e`: a desktop package failure must not block the agent package.
    let mut body = String::from("#!/bin/bash\nset -u\n");
    body.push_str(&format!("exec >>'{}' 2>&1\n", log_path.display()));
    body.push_str("echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) hecate-lampad PKG install starting\"\n");
    // Let the agent finish submitting the command result before installer stops us.
    body.push_str("sleep 5\n");
    body.push_str("DESKTOP_FAILED=0\n");
    body.push_str("HAS_AGENT=0\n");
    body.push_str(
        r#"
hecate_verify_pkg() {
  local pkg="$1"
  local expected="$2"
  echo "${expected}  ${pkg}" | /usr/bin/shasum -a 256 -c -
}
hecate_install_pkg() {
  local pkg="$1"
  if [ "$(id -u)" -eq 0 ]; then
    /usr/sbin/installer -pkg "$pkg" -target /
  else
    if ! sudo -n true 2>/dev/null; then
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) package install failed: sudo NOPASSWD is not configured for hecate-lampad (missing /etc/sudoers.d/hecate-lampad?)"
      return 1
    fi
    sudo -n -- /usr/sbin/installer -pkg "$pkg" -target /
  fi
}
"#,
    );
    for package in packages {
        let name = package
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_desktop = name.contains("desktop");
        let path = package.path.display().to_string();
        let expected = package.expected_sha256.to_lowercase();
        if is_desktop {
            body.push_str(&format!(
                "if ! hecate_verify_pkg '{path}' '{expected}'; then\n  echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) desktop package hash mismatch: {path}\"\n  DESKTOP_FAILED=1\nelif ! hecate_install_pkg '{path}'; then\n  echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) desktop package install failed: {path}\"\n  DESKTOP_FAILED=1\nfi\n"
            ));
        } else {
            body.push_str("HAS_AGENT=1\n");
            body.push_str(&format!(
                "if ! hecate_verify_pkg '{path}' '{expected}'; then\n  echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) agent package hash mismatch: {path}\"\n  echo package install failed\n  exit 1\nfi\n"
            ));
            body.push_str(&format!(
                "if ! hecate_install_pkg '{path}'; then\n  echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) agent package install failed: {path}\"\n  echo package install failed\n  exit 1\nfi\n"
            ));
        }
    }
    body.push_str(
        "launchctl kickstart -k system/com.hecate.lampad >/dev/null 2>&1 || \
launchctl bootstrap system /Library/LaunchDaemons/com.hecate.lampad.plist >/dev/null 2>&1 || true\n",
    );
    body.push_str(
        "launchctl bootout system/com.hecate.lampad-pkg-update >/dev/null 2>&1 || true\n\
rm -f /Library/LaunchDaemons/com.hecate.lampad-pkg-update.plist\n",
    );
    for package in packages {
        body.push_str(&format!("rm -f '{}'\n", package.path.display()));
    }
    body.push_str(
        "if [ \"${DESKTOP_FAILED}\" = \"1\" ] && [ \"${HAS_AGENT}\" != \"1\" ]; then\n  echo package install failed\n  echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) hecate-lampad PKG install finished with desktop failure\"\n",
    );
    body.push_str(&format!("  rm -f '{}'\n  exit 1\nfi\n", script_path.display()));
    body.push_str(
        "if [ \"${DESKTOP_FAILED}\" = \"1\" ]; then\n  echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) desktop package failed but agent package continued\"\nfi\n",
    );
    body.push_str("echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) hecate-lampad PKG install finished\"\n");
    body.push_str(&format!("rm -f '{}'\n", script_path.display()));

    write_private_file(&script_path, body.as_bytes(), 0o700)?;
    Ok(script_path)
}

#[cfg(target_os = "macos")]
fn run_macos_pkg_install(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    let script = write_macos_install_script(packages)?;
    let output = Command::new("/bin/bash")
        .arg(&script)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            UpdaterError::Aborted(format!("failed to run PKG installer script: {error}"))
        })?;
    let _ = std::fs::remove_file(&script);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(UpdaterError::Aborted(if !stderr.is_empty() {
            format!("PKG install failed: {stderr}")
        } else if !stdout.is_empty() {
            format!("PKG install failed: {stdout}")
        } else {
            format!("PKG install exited with {}", output.status)
        }));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_macos_dir_probe(dir: &Path) -> bool {
    let probe = dir.join(".hecate-update-write-probe");
    if probe.exists() || std::fs::symlink_metadata(&probe).is_ok() {
        let _ = std::fs::remove_file(&probe);
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&probe)
    else {
        return false;
    };
    if file.write_all(b"ok").is_err() {
        let _ = std::fs::remove_file(&probe);
        return false;
    }
    let _ = std::fs::remove_file(&probe);
    true
}

#[cfg(target_os = "macos")]
fn macos_agent_writable_dir() -> Option<PathBuf> {
    for dir in [
        PathBuf::from("/var/lib/hecate-lampad"),
        PathBuf::from("/var/run/hecate-lampad"),
    ] {
        if dir.is_dir() && write_macos_dir_probe(&dir) {
            return Some(dir);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_install_log_path() -> PathBuf {
    macos_agent_writable_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib/hecate-lampad"))
        .join("package-update.log")
}

#[cfg(target_os = "windows")]
fn spawn_windows_detached(packages: &[InstallPackage]) -> Result<(), UpdaterError> {
    // Must not stay in the service process job: when msiexec's ServiceControl
    // stops hecate-lampad, Windows kills job members and aborts the install.
    // Schedule a SYSTEM task so msiexec runs outside the service tree.
    let script_path = write_windows_install_script(packages)?;
    run_windows_system_task(
        "hecate-lampad-pkg-update",
        &script_path,
        "package installer",
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_windows_install_script(packages: &[InstallPackage]) -> Result<PathBuf, UpdaterError> {
    let dir = windows_agent_data_dir();
    let _ = std::fs::create_dir_all(&dir);
    let script_path = dir.join("hecate-lampad-pkg-update.cmd");
    let log_path = dir.join("package-update.log");

    let mut body = String::from("@echo off\r\nsetlocal EnableExtensions\r\n");
    body.push_str(&format!(
        "echo %DATE% %TIME% hecate-lampad package install starting>>\"{}\"\r\n",
        log_path.display()
    ));
    // Let the agent finish submitting the command result before MSI stops us.
    body.push_str("timeout /t 5 /nobreak >nul\r\n");
    body.push_str("whoami | findstr /I \"SYSTEM\" >nul\r\n");
    body.push_str("if errorlevel 1 (\r\n");
    body.push_str(&format!(
        "  echo %DATE% %TIME% package install failed: expected SYSTEM task context>>\"{}\"\r\n",
        log_path.display()
    ));
    body.push_str(&format!(
        "  echo package install failed>>\"{}\"\r\n",
        log_path.display()
    ));
    body.push_str("  exit /b 1\r\n");
    body.push_str(")\r\n");
    body.push_str("set DESKTOP_FAILED=0\r\n");
    body.push_str("set HAS_AGENT=0\r\n");
    for (index, package) in packages.iter().enumerate() {
        let name = package
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_desktop = name.contains("desktop");
        if is_desktop {
            // Unlock a running helper before MajorUpgrade replaces files.
            body.push_str("taskkill /IM hecate-lampad-desktop.exe /F >nul 2>&1\r\n");
            body.push_str(
                "if exist \"C:\\Program Files\\hecate-lampad-desktop\\hecate-lampad-desktop.prev\" del /f /q \"C:\\Program Files\\hecate-lampad-desktop\\hecate-lampad-desktop.prev\"\r\n",
            );
            // ARP without files makes upgrades enter a broken REMOVE path.
            // Uninstall the orphaned product first so the new MSI is a fresh install.
            body.push_str(
                "if not exist \"C:\\Program Files\\hecate-lampad-desktop\\hecate-lampad-desktop.exe\" (\r\n",
            );
            body.push_str(&format!(
                "  echo %DATE% %TIME% scrubbing broken desktop ARP>>\"{}\"\r\n",
                log_path.display()
            ));
            body.push_str(
                "  powershell -NoProfile -ExecutionPolicy Bypass -Command \"Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Hecate Lampad Desktop Helper' } | ForEach-Object { Start-Process -FilePath msiexec.exe -ArgumentList @('/x', $_.PSChildName, '/qn', '/norestart') -Wait -NoNewWindow | Out-Null }\"\r\n",
            );
            body.push_str(")\r\n");
        } else {
            body.push_str("set HAS_AGENT=1\r\n");
            // Clear stale binary-replace backup; MSI ServiceControl stops the service.
            body.push_str(
                "if exist \"C:\\Program Files\\hecate-lampad\\hecate-lampad.prev\" del /f /q \"C:\\Program Files\\hecate-lampad\\hecate-lampad.prev\"\r\n",
            );
        }

        let msi_log = dir.join(format!("msi-install-{index}.log"));
        let expected = package.expected_sha256.to_lowercase();
        let pkg_path = package.path.display();
        body.push_str(&format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"if ((Get-FileHash -LiteralPath '{pkg_path}' -Algorithm SHA256).Hash.ToLower() -ne '{expected}') {{ exit 1 }}\"\r\n"
        ));
        body.push_str("if errorlevel 1 (\r\n");
        body.push_str(&format!(
            "  echo %DATE% %TIME% package hash mismatch for {pkg_path}>>\"{}\"\r\n",
            log_path.display()
        ));
        if is_desktop {
            body.push_str("  set DESKTOP_FAILED=1\r\n");
        } else {
            body.push_str(&format!(
                "  echo package install failed>>\"{}\"\r\n",
                log_path.display()
            ));
            body.push_str("  exit /b 1\r\n");
        }
        body.push_str(") else (\r\n");
        // Do NOT pass REINSTALL=ALL: with an existing UpgradeCode product it forces
        // maintenance mode, skips RemoveExistingProducts, sets REMOVE=ALL, and
        // breaks desktop Unregister CAs (MSI 2753 → 1603). MajorUpgrade (including
        // AllowSameVersionUpgrades) replaces files without REINSTALL.
        body.push_str(&format!(
            "  msiexec /i \"{pkg_path}\" /qn /norestart ALLUSERS=1 /l*v \"{}\"\r\n",
            msi_log.display()
        ));
        body.push_str("  set MSI_EXIT=%ERRORLEVEL%\r\n");
        body.push_str(&format!(
            "  echo %DATE% %TIME% msiexec exit %MSI_EXIT% for {pkg_path}>>\"{}\"\r\n",
            log_path.display()
        ));
        // 0=success, 3010=reboot required, 1641=reboot initiated — all OK for us.
        body.push_str(
            "  if not \"%MSI_EXIT%\"==\"0\" if not \"%MSI_EXIT%\"==\"3010\" if not \"%MSI_EXIT%\"==\"1641\" (\r\n",
        );
        body.push_str(&format!(
            "    echo %DATE% %TIME% msiexec failed with %MSI_EXIT%>>\"{}\"\r\n",
            log_path.display()
        ));
        if is_desktop {
            // Desktop failure must not block the agent MSI in the same batch.
            body.push_str("    set DESKTOP_FAILED=1\r\n");
            body.push_str(&format!(
                "    echo %DATE% %TIME% continuing after desktop package failure>>\"{}\"\r\n",
                log_path.display()
            ));
        } else {
            body.push_str(&format!(
                "    echo package install failed>>\"{}\"\r\n",
                log_path.display()
            ));
            body.push_str("    exit /b %MSI_EXIT%\r\n");
        }
        body.push_str("  )\r\n");
        body.push_str(")\r\n");
    }
    body.push_str(&format!(
        "sc start hecate-lampad>>\"{}\" 2>&1\r\n",
        log_path.display()
    ));
    // Failsafe if ServiceControl did not leave the service running.
    body.push_str("timeout /t 15 /nobreak >nul\r\n");
    body.push_str("sc query hecate-lampad | find \"RUNNING\" >nul\r\n");
    body.push_str("if errorlevel 1 sc start hecate-lampad\r\n");
    for package in packages {
        body.push_str(&format!("del /f /q \"{}\"\r\n", package.path.display()));
    }
    body.push_str("schtasks /Delete /TN \"hecate-lampad-pkg-update\" /F >nul 2>&1\r\n");
    body.push_str("if \"%DESKTOP_FAILED%\"==\"1\" if not \"%HAS_AGENT%\"==\"1\" (\r\n");
    body.push_str(&format!(
        "  echo package install failed>>\"{}\"\r\n",
        log_path.display()
    ));
    body.push_str(&format!(
        "  echo %DATE% %TIME% hecate-lampad package install finished with desktop failure>>\"{}\"\r\n",
        log_path.display()
    ));
    body.push_str(&format!("  del /f /q \"{}\"\r\n", script_path.display()));
    body.push_str("  exit /b 1603\r\n");
    body.push_str(")\r\n");
    body.push_str("if \"%DESKTOP_FAILED%\"==\"1\" (\r\n");
    body.push_str(&format!(
        "  echo %DATE% %TIME% desktop package failed but agent package continued>>\"{}\"\r\n",
        log_path.display()
    ));
    body.push_str(")\r\n");
    body.push_str(&format!(
        "echo %DATE% %TIME% hecate-lampad package install finished>>\"{}\"\r\n",
        log_path.display()
    ));
    body.push_str(&format!("del /f /q \"{}\"\r\n", script_path.display()));

    write_private_file(&script_path, body.as_bytes(), 0o600)?;
    Ok(script_path)
}

#[cfg(target_os = "windows")]
fn windows_agent_data_dir() -> PathBuf {
    if let Ok(program_data) = std::env::var("ProgramData") {
        return PathBuf::from(program_data).join("hecate-lampad");
    }
    PathBuf::from(r"C:\ProgramData\hecate-lampad")
}

/// Create/run a one-shot SYSTEM scheduled task so work survives service stop.
#[cfg(target_os = "windows")]
pub(crate) fn run_windows_system_task(
    task_name: &str,
    script_path: &Path,
    purpose: &str,
) -> Result<(), UpdaterError> {
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            UpdaterError::Aborted(format!("schtasks create ({purpose}) failed to spawn: {error}"))
        })?;
    if !create.status.success() {
        let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&create.stdout).trim().to_string();
        return Err(UpdaterError::Aborted(format!(
            "schtasks create ({purpose}) failed: {} {}",
            stdout, stderr
        )));
    }

    let run = Command::new("schtasks")
        .args(["/Run", "/TN", task_name])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            UpdaterError::Aborted(format!("schtasks run ({purpose}) failed to spawn: {error}"))
        })?;
    if !run.status.success() {
        let stderr = String::from_utf8_lossy(&run.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&run.stdout).trim().to_string();
        let _ = Command::new("schtasks")
            .args(["/Delete", "/TN", task_name, "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return Err(UpdaterError::Aborted(format!(
            "schtasks run ({purpose}) failed: {} {}",
            stdout, stderr
        )));
    }

    info!(%task_name, %purpose, path = %script_path.display(), "scheduled Windows SYSTEM task");
    Ok(())
}

#[cfg(target_os = "windows")]
fn wait_for_windows_install_log(log_path: &Path, max_wait: Duration) -> Result<(), UpdaterError> {
    let start = std::time::Instant::now();
    while start.elapsed() < max_wait {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            if content.contains("package install failed") {
                return Err(UpdaterError::Aborted(format!(
                    "Windows package install failed; see {}",
                    log_path.display()
                )));
            }
            if content.contains("package install finished") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(UpdaterError::Aborted(format!(
        "timed out waiting for Windows package install; see {}",
        log_path.display()
    )))
}

#[cfg(target_os = "windows")]
#[allow(dead_code)] // direct msiexec fallback for tests/tools
fn run_windows_msiexec(package: &Path) -> Result<(), UpdaterError> {
    // Prefer the shared script path; keep a direct fallback for tests/tools.
    let log_path = windows_agent_data_dir().join(format!(
        "msi-direct-{}.log",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(windows_agent_data_dir());
    let output = Command::new("msiexec")
        .args([
            "/i",
            &package.to_string_lossy(),
            "/qn",
            "/norestart",
            "ALLUSERS=1",
            "/l*v",
            &log_path.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| UpdaterError::Aborted(format!("failed to run msiexec: {error}")))?;
    let code = output.status.code().unwrap_or(-1);
    // 0 success, 3010 reboot required, 1641 reboot initiated.
    if matches!(code, 0 | 3010 | 1641) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(UpdaterError::Aborted(if stderr.is_empty() {
        format!("msiexec exited with {code}; log {}", log_path.display())
    } else {
        format!("msiexec failed ({code}): {stderr}")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_extension_matches_platform() {
        let ext = package_extension();
        assert!(ext == ".deb" || ext == ".msi" || ext == ".pkg");
    }

    #[test]
    fn with_extension_appends_once() {
        let path = PathBuf::from("/tmp/hecate.staging");
        let with = with_package_extension(path);
        let as_str = with.to_string_lossy();
        assert!(as_str.ends_with(package_extension()));
        let again = with_package_extension(with.clone());
        assert_eq!(again, with);
    }

    #[test]
    fn require_package_install_elevation_is_callable() {
        // Platform-dependent; must not panic. When elevation is unavailable, callers get a
        // descriptive Aborted error instead of reporting installer_launched success.
        let result = require_package_install_elevation();
        if elevation::is_privileged() || elevation::elevation_available() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
            let message = result.unwrap_err().to_string();
            assert!(message.contains("package install"));
        }
    }

    #[test]
    fn package_install_elevation_hint_is_non_empty() {
        let hint = super::package_install_elevation_hint();
        assert!(!hint.is_empty());
        assert!(hint.contains("package install"));
    }
}

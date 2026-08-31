//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::client::HttpPullClient;
use crate::elevation;
use crate::signing::{AgentKeypair, SigningError};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("update aborted: {0}")]
    Aborted(String),
    #[error("download failed: {0}")]
    Download(String),
    #[error("release signing key not configured")]
    ReleaseKeyMissing,
}

/// Self-update artifact metadata from a signed server task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArtifact {
    pub target_version: String,
    pub staging_path: PathBuf,
    pub expected_sha256: String,
    pub signature: String,
    pub release_public_key_b64: String,
    /// Optional previous release pubkey for dual-key verification.
    pub release_public_key_previous_b64: Option<String>,
    /// Canonical kind: `self_update` (agent) or `desktop_update` (helper).
    pub kind: String,
}

/// Verify SHA-256 and Ed25519 release signature, then atomically replace the binary.
pub struct Updater {
    current_binary: PathBuf,
}

impl Updater {
    pub fn new(current_binary: impl Into<PathBuf>) -> Self {
        Self {
            current_binary: current_binary.into(),
        }
    }

    pub fn verify_artifact(&self, artifact: &UpdateArtifact) -> Result<(), UpdaterError> {
        let bytes = read_nofollow(&artifact.staging_path)?;
        self.verify_bytes(&bytes, artifact)
    }

    /// Hash a staging file via a no-follow descriptor (held FD / FILE_SHARE_READ).
    pub fn sha256_nofollow(path: &Path) -> Result<String, UpdaterError> {
        let bytes = read_nofollow(path)?;
        Ok(hex_sha256(&bytes))
    }

    pub fn verify_bytes(&self, bytes: &[u8], artifact: &UpdateArtifact) -> Result<(), UpdaterError> {
        let actual = hex_sha256(bytes);
        if actual != artifact.expected_sha256.to_lowercase() {
            return Err(UpdaterError::HashMismatch {
                expected: artifact.expected_sha256.clone(),
                actual,
            });
        }

        let keys = release_verify_keys(artifact);
        if keys.is_empty() {
            return Err(UpdaterError::ReleaseKeyMissing);
        }

        // Prefer content Ed25519 (.sig / feature-repo) when signature verifies over raw bytes.
        if verify_content_signature(&keys, bytes, &artifact.signature).is_ok() {
            return Ok(());
        }

        // Legacy GitLab Package Registry manifests: canonical v1 message.
        let canonical = format!(
            "v1\n{}\n{}\n{}\n{}",
            artifact.kind, artifact.target_version, artifact.expected_sha256, actual
        );
        let mut last_error = SigningError::VerificationFailed;
        let mut ok = false;
        for key in &keys {
            match AgentKeypair::verify_canonical(key, &canonical, &artifact.signature) {
                Ok(()) => {
                    ok = true;
                    break;
                }
                Err(error) => last_error = error,
            }
        }
        if !ok {
            return Err(UpdaterError::Signature(last_error.to_string()));
        }

        Ok(())
    }

    /// Replace the running binary after verification.
    ///
    /// Root/CLI path: same-FS rename with EXDEV copy fallback.
    /// Service path (`hecate-lampad` user): elevated `mv`/`install` via sudo.
    pub fn apply(&self, artifact: &UpdateArtifact) -> Result<PathBuf, UpdaterError> {
        let bytes = read_nofollow(&artifact.staging_path)?;
        self.verify_bytes(&bytes, artifact)?;
        // Re-materialize verified bytes under a new exclusive name so install does
        // not consume a path the attacker could swap after the first open().
        let verified_path = artifact.staging_path.with_extension(format!(
            "verified-{}",
            random_suffix()
        ));
        if let Err(error) = write_staging_exclusive(&verified_path, &bytes) {
            let _ = std::fs::remove_file(&verified_path);
            return Err(error);
        }

        let backup = self.current_binary.with_extension("prev");
        // Windows rename cannot overwrite an existing destination; drop a stale
        // backup from a previous update before moving the running binary aside.
        if backup.exists() {
            std::fs::remove_file(&backup).map_err(|error| {
                UpdaterError::Aborted(format!(
                    "remove previous backup {}: {error}",
                    backup.display()
                ))
            })?;
        }
        if self.current_binary.exists() {
            replace_file(&self.current_binary, &backup)?;
        }

        match replace_file(&verified_path, &self.current_binary) {
            Ok(()) => {
                let _ = std::fs::remove_file(&verified_path);
                Ok(backup)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&verified_path);
                if backup.exists() {
                    let _ = replace_file(&backup, &self.current_binary);
                }
                Err(e)
            }
        }
    }
}

/// Stage beside the install path when privileged; otherwise use an agent-writable dir
/// (service user cannot write under `/usr/bin`).
pub fn staging_path_for(install_path: &Path, kind: &str, version: &str) -> PathBuf {
    staging_path_for_with_privilege(install_path, kind, version, elevation::is_privileged())
}

fn staging_path_for_with_privilege(
    install_path: &Path,
    kind: &str,
    version: &str,
    privileged: bool,
) -> PathBuf {
    let file_stem = install_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("hecate-lampad");
    let staging_name = format!(
        "{file_stem}.{kind}-{version}.{}.staging",
        random_suffix()
    );

    if !privileged {
        for dir in agent_writable_dirs() {
            if dir_is_usable(&dir) {
                let _ = ensure_private_dir(&dir);
                return dir.join(&staging_name);
            }
        }
        return std::env::temp_dir().join(staging_name);
    }

    let hidden = format!(".{staging_name}");
    match install_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(hidden),
        _ => std::env::temp_dir().join(hidden),
    }
}

fn agent_writable_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut dirs = Vec::new();
        if let Ok(program_data) = std::env::var("ProgramData") {
            dirs.push(PathBuf::from(program_data).join("hecate-lampad"));
        }
        dirs.push(PathBuf::from(r"C:\ProgramData\hecate-lampad"));
        dirs
    }
    #[cfg(not(windows))]
    {
        vec![
            PathBuf::from("/var/lib/hecate-lampad"),
            PathBuf::from("/run/hecate-lampad"),
            PathBuf::from("/var/run/hecate-lampad"),
        ]
    }
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ensure_private_dir(path: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_nofollow(path: &Path) -> Result<Vec<u8>, UpdaterError> {
    let mut file = open_nofollow(path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open_nofollow(path: &Path, create_new: bool) -> Result<std::fs::File, UpdaterError> {
    let mut opts = std::fs::OpenOptions::new();
    if create_new {
        opts.write(true).create_new(true);
    } else {
        opts.read(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if create_new {
            opts.mode(0o600);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        if !create_new {
            let meta = std::fs::symlink_metadata(path).map_err(UpdaterError::from)?;
            if meta.file_type().is_symlink() {
                return Err(UpdaterError::Download(format!(
                    "refusing to follow symlink staging path {}",
                    path.display()
                )));
            }
        }
        opts.share_mode(FILE_SHARE_READ);
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path).map_err(UpdaterError::from)
}

fn copy_regular_nofollow(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            std::fs::remove_file(dest).map_err(|error| {
                UpdaterError::Aborted(format!(
                    "remove symlink {} before copy: {error}",
                    dest.display()
                ))
            })?;
        }
    }
    let mut source = open_nofollow(src, false)?;
    let mut target = open_overwrite_nofollow(dest)?;
    std::io::copy(&mut source, &mut target).map_err(|error| {
        UpdaterError::Aborted(format!(
            "cross-device copy {} -> {}: {error}",
            src.display(),
            dest.display()
        ))
    })?;
    target.sync_all().map_err(UpdaterError::from)?;
    Ok(())
}

fn open_overwrite_nofollow(path: &Path) -> Result<std::fs::File, UpdaterError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        opts.mode(0o755);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(UpdaterError::Aborted(format!(
                    "refusing to follow symlink install path {}",
                    path.display()
                )));
            }
        }
        opts.share_mode(FILE_SHARE_READ);
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path).map_err(UpdaterError::from)
}

fn write_staging_exclusive(path: &Path, bytes: &[u8]) -> Result<(), UpdaterError> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    use std::io::Write;
    let mut file = open_nofollow(path, true)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn dir_is_usable(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    let probe = path.join(".hecate-update-write-probe");
    if probe.exists() || std::fs::symlink_metadata(&probe).is_ok() {
        let _ = std::fs::remove_file(&probe);
    }
    use std::io::Write;
    #[cfg(unix)]
    {
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
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let Ok(mut file) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&probe)
        else {
            return false;
        };
        if file.write_all(b"ok").is_err() {
            let _ = std::fs::remove_file(&probe);
            return false;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        if std::fs::write(&probe, b"ok").is_err() {
            return false;
        }
    }
    let _ = std::fs::remove_file(&probe);
    true
}

fn is_cross_device(err: &std::io::Error) -> bool {
    if err.kind() == ErrorKind::CrossesDevices {
        return true;
    }
    // EXDEV on Unix; ERROR_NOT_SAME_DEVICE on Windows.
    matches!(err.raw_os_error(), Some(18) | Some(17))
}

#[cfg(test)]
fn is_permission_denied(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::PermissionDenied || err.raw_os_error() == Some(13)
}

/// Prefer rename; on cross-device links, copy then remove the source.
/// When the agent service cannot write the install path, fall back to sudo.
fn replace_file(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    match replace_file_direct(src, dest) {
        Ok(()) => Ok(()),
        Err(direct_error) => {
            if elevation::is_privileged() || !elevation::elevation_available() {
                return Err(direct_error);
            }
            replace_file_elevated(src, dest).map_err(|elevated_error| {
                UpdaterError::Aborted(format!(
                    "{direct_error}; elevated fallback: {elevated_error}"
                ))
            })
        }
    }
}

fn replace_file_direct(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    // On Windows, rename fails if the destination already exists (unlike Unix).
    #[cfg(windows)]
    if dest.exists() {
        std::fs::remove_file(dest).map_err(|error| {
            UpdaterError::Aborted(format!(
                "remove existing {} before replace: {error}",
                dest.display()
            ))
        })?;
    }

    match std::fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(err) if is_cross_device(&err) => {
            copy_regular_nofollow(src, dest)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::symlink_metadata(src)
                    .map(|meta| meta.permissions().mode())
                    .unwrap_or(0o755);
                let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode));
            }
            let _ = std::fs::remove_file(src);
            Ok(())
        }
        Err(err) => Err(UpdaterError::Aborted(format!(
            "replace {} -> {}: {err}",
            src.display(),
            dest.display()
        ))),
    }
}

#[cfg(unix)]
fn replace_file_elevated(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    // Rename first (works for a running binary on Linux/macOS). Fall back to
    // install(1) when source and dest are on different filesystems.
    match elevated_mv(src, dest) {
        Ok(()) => Ok(()),
        Err(mv_error) => {
            elevated_install(src, dest).map_err(|install_error| {
                UpdaterError::Aborted(format!(
                    "elevated replace {} -> {} failed (mv: {mv_error}; install: {install_error})",
                    src.display(),
                    dest.display()
                ))
            })?;
            let _ = elevated_rm(src);
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn replace_file_elevated(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    Err(UpdaterError::Aborted(format!(
        "elevated replace is not supported on this platform ({} -> {})",
        src.display(),
        dest.display()
    )))
}

#[cfg(unix)]
fn elevated_mv(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    let mv = resolve_bin(&["/usr/bin/mv", "/bin/mv"])
        .ok_or_else(|| UpdaterError::Aborted("mv not found for elevated update".into()))?;
    let argv = elevation::build_elevated_argv(&[
        mv,
        "-f".into(),
        src.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .map_err(UpdaterError::Aborted)?;
    run_command(&argv)
}

#[cfg(unix)]
fn elevated_install(src: &Path, dest: &Path) -> Result<(), UpdaterError> {
    let install = resolve_bin(&["/usr/bin/install", "/bin/install"])
        .ok_or_else(|| UpdaterError::Aborted("install(1) not found for elevated update".into()))?;
    let argv = elevation::build_elevated_argv(&[
        install,
        "-m".into(),
        "755".into(),
        src.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .map_err(UpdaterError::Aborted)?;
    run_command(&argv)
}

#[cfg(unix)]
fn elevated_rm(path: &Path) -> Result<(), UpdaterError> {
    let rm = resolve_bin(&["/usr/bin/rm", "/bin/rm"])
        .ok_or_else(|| UpdaterError::Aborted("rm not found for elevated cleanup".into()))?;
    let argv = elevation::build_elevated_argv(&[
        rm,
        "-f".into(),
        path.to_string_lossy().into_owned(),
    ])
    .map_err(UpdaterError::Aborted)?;
    run_command(&argv)
}

#[cfg(unix)]
fn resolve_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}

#[cfg(unix)]
fn run_command(argv: &[String]) -> Result<(), UpdaterError> {
    use std::process::Stdio;
    let program = argv
        .first()
        .ok_or_else(|| UpdaterError::Aborted("empty elevated argv".into()))?;
    let output = std::process::Command::new(program)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            UpdaterError::Aborted(format!("failed to spawn {program}: {error}"))
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(UpdaterError::Aborted(if stderr.is_empty() {
        format!("{program} exited with {}", output.status)
    } else {
        format!("{program} failed: {stderr}")
    }))
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify Ed25519 detached signature over raw file bytes (feature-repo `.sig` style).
/// `signature_b64` is standard base64 of the 64-byte signature.
fn verify_content_signature(
    public_keys_b64: &[String],
    content: &[u8],
    signature_b64: &str,
) -> Result<(), SigningError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig_bytes = BASE64
        .decode(signature_b64.trim())
        .map_err(|_| SigningError::VerificationFailed)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SigningError::VerificationFailed)?;
    let signature = Signature::from_bytes(&sig_array);

    for key_b64 in public_keys_b64 {
        let pk = BASE64
            .decode(key_b64.trim())
            .map_err(|_| SigningError::InvalidKey("bad public key".into()))?;
        let pk_array: [u8; 32] = match pk.as_slice().try_into() {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_array) {
            if verifying_key.verify(content, &signature).is_ok() {
                return Ok(());
            }
        }
    }
    Err(SigningError::VerificationFailed)
}

fn release_verify_keys(artifact: &UpdateArtifact) -> Vec<String> {
    let mut keys = Vec::new();
    if !artifact.release_public_key_b64.trim().is_empty() {
        keys.push(artifact.release_public_key_b64.clone());
    }
    if let Some(prev) = artifact.release_public_key_previous_b64.as_ref() {
        if !prev.trim().is_empty() && !keys.iter().any(|k| k == prev) {
            keys.push(prev.clone());
        }
    }
    keys
}

/// Parameters for a server-issued self-update task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfUpdateParams {
    pub server_url: String,
    pub target_version: String,
    pub artifact_path: String,
    pub sha256: String,
    pub signature: String,
    pub release_public_key_b64: String,
    pub release_public_key_previous_b64: Option<String>,
    /// Install destination; defaults to current executable when None.
    pub install_path: Option<PathBuf>,
    /// Canonical signature kind (`self_update` or `desktop_update`).
    pub kind: String,
    /// Server task signature covering artifact_path + hash (C2 / H1c).
    pub server_task_sig: String,
}

pub fn validate_release_artifact_path(artifact_path: &str) -> Result<(), UpdaterError> {
    if !hecate_protocol::release_artifacts::is_release_artifact_path(artifact_path) {
        return Err(UpdaterError::Download(
            "artifact_path must be a canonical signed release artifact API path".into(),
        ));
    }
    Ok(())
}

pub async fn stage_artifact(
    artifact_path: &str,
    staging_path: &Path,
    client: Option<&HttpPullClient>,
    agent_id: uuid::Uuid,
    keypair: &AgentKeypair,
) -> Result<(), UpdaterError> {
    validate_release_artifact_path(artifact_path)?;
    let http_client = client.ok_or_else(|| {
        UpdaterError::Download("authenticated download client required".into())
    })?;
    let bytes = http_client
        .download_signed(agent_id, keypair, artifact_path)
        .await
        .map_err(|error| UpdaterError::Download(error.to_string()))?;

    write_staging_exclusive(staging_path, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Exec bit only for raw binaries; packages (.deb/.msi/.pkg) stay non-executable.
        let is_package = staging_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("deb")
                    || ext.eq_ignore_ascii_case("msi")
                    || ext.eq_ignore_ascii_case("pkg")
                    || ext.eq_ignore_ascii_case("staging")
            });
        if !is_package {
            std::fs::set_permissions(staging_path, std::fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(())
}

/// Download (or copy), verify, and apply an update.
///
/// On Linux/Windows/macOS this launches the installer package (`.deb` / `.msi` / `.pkg`) in a
/// detached process. On macOS it atomically replaces the binary.
pub async fn perform_self_update(
    params: &SelfUpdateParams,
    client: Option<&HttpPullClient>,
    agent_id: uuid::Uuid,
    keypair: &AgentKeypair,
) -> Result<(), UpdaterError> {
    if crate::package_update::uses_installer_packages() {
        return crate::package_update::launch_package_updates(
            &[params.clone()],
            client,
            agent_id,
            keypair,
        )
        .await;
    }
    perform_binary_self_update(params, client, agent_id, keypair).await
}

/// Download (or copy), verify, and atomically replace a component binary.
pub async fn perform_binary_self_update(
    params: &SelfUpdateParams,
    client: Option<&HttpPullClient>,
    agent_id: uuid::Uuid,
    keypair: &AgentKeypair,
) -> Result<(), UpdaterError> {
    if params.release_public_key_b64.trim().is_empty() {
        return Err(UpdaterError::ReleaseKeyMissing);
    }

    let current_binary = match &params.install_path {
        Some(path) => path.clone(),
        None => std::env::current_exe()?,
    };
    let staging_path = staging_path_for(&current_binary, &params.kind, &params.target_version);

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

    let updater = Updater::new(&current_binary);
    let artifact = UpdateArtifact {
        target_version: params.target_version.clone(),
        staging_path: staging_path.clone(),
        expected_sha256: params.sha256.clone(),
        signature: params.signature.clone(),
        release_public_key_b64: params.release_public_key_b64.clone(),
        release_public_key_previous_b64: params.release_public_key_previous_b64.clone(),
        kind: params.kind.clone(),
    };

    match updater.apply(&artifact) {
        Ok(_) => {
            let _ = std::fs::remove_file(&staging_path);
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_file(&staging_path);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::AgentKeypair;
    use tempfile::TempDir;

    #[test]
    fn rejects_hash_mismatch() {
        let dir = TempDir::new().unwrap();
        let staging = dir.path().join("agent.new");
        std::fs::write(&staging, b"binary").unwrap();

        let kp = AgentKeypair::generate();
        let hash = hex_sha256(b"wrong");
        let canonical = format!("v1\nself_update\n1.0.0\n{hash}\n{hash}");
        let sig = kp.sign_canonical(&canonical);

        let updater = Updater::new(dir.path().join("hecate-lampad"));
        let artifact = UpdateArtifact {
            target_version: "1.0.0".into(),
            staging_path: staging,
            expected_sha256: hash,
            signature: sig,
            release_public_key_b64: kp.public_key_base64(),
            release_public_key_previous_b64: None,
            kind: "self_update".into(),
        };

        assert!(matches!(
            updater.verify_artifact(&artifact),
            Err(UpdaterError::HashMismatch { .. })
        ));
    }

    #[test]
    fn verify_and_apply() {
        let dir = TempDir::new().unwrap();
        let current = dir.path().join("hecate-lampad");
        std::fs::write(&current, b"old").unwrap();

        let staging = dir.path().join("agent.new");
        std::fs::write(&staging, b"new-binary").unwrap();

        let kp = AgentKeypair::generate();
        let hash = hex_sha256(b"new-binary");
        let canonical = format!("v1\nself_update\n1.0.1\n{hash}\n{hash}");
        let sig = kp.sign_canonical(&canonical);

        let updater = Updater::new(&current);
        let artifact = UpdateArtifact {
            target_version: "1.0.1".into(),
            staging_path: staging,
            expected_sha256: hash,
            signature: sig,
            release_public_key_b64: kp.public_key_base64(),
            release_public_key_previous_b64: None,
            kind: "self_update".into(),
        };

        updater.apply(&artifact).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"new-binary");
    }

    #[test]
    fn verify_accepts_previous_release_key() {
        let dir = TempDir::new().unwrap();
        let staging = dir.path().join("agent.new");
        std::fs::write(&staging, b"payload").unwrap();

        let current = AgentKeypair::generate();
        let previous = AgentKeypair::generate();
        let hash = hex_sha256(b"payload");
        let canonical = format!("v1\nself_update\n2.0.0\n{hash}\n{hash}");
        let sig = previous.sign_canonical(&canonical);

        let updater = Updater::new(dir.path().join("hecate-lampad"));
        let artifact = UpdateArtifact {
            target_version: "2.0.0".into(),
            staging_path: staging,
            expected_sha256: hash,
            signature: sig,
            release_public_key_b64: current.public_key_base64(),
            release_public_key_previous_b64: Some(previous.public_key_base64()),
            kind: "self_update".into(),
        };
        updater.verify_artifact(&artifact).unwrap();
    }

    #[test]
    fn staging_path_beside_install_when_privileged() {
        let install = PathBuf::from("/usr/bin/hecate-lampad");
        let staging = staging_path_for_with_privilege(&install, "self_update", "1.2.9", true);
        let name = staging.file_name().and_then(|n| n.to_str()).unwrap();
        assert!(
            name.starts_with(".hecate-lampad.self_update-1.2.9.") && name.ends_with(".staging"),
            "unexpected staging path: {}",
            staging.display()
        );
        assert_eq!(staging.parent(), Some(Path::new("/usr/bin")));
    }

    #[test]
    fn staging_path_uses_temp_when_unprivileged_without_runtime_dir() {
        let install = PathBuf::from("/usr/bin/hecate-lampad");
        let staging = staging_path_for_with_privilege(&install, "self_update", "1.2.9", false);
        let name = staging.file_name().and_then(|n| n.to_str()).unwrap();
        assert!(
            name.starts_with("hecate-lampad.self_update-1.2.9.") && name.ends_with(".staging"),
            "unexpected staging path: {}",
            staging.display()
        );
        assert!(
            !staging.starts_with("/usr/bin"),
            "unprivileged staging must not target /usr/bin: {}",
            staging.display()
        );
    }

    #[test]
    fn replace_file_overwrites_destination() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        let dest = dir.path().join("dest");
        std::fs::write(&src, b"new").unwrap();
        std::fs::write(&dest, b"old").unwrap();
        replace_file_direct(&src, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert!(!src.exists());
    }

    #[test]
    fn permission_denied_detection() {
        let err = std::io::Error::from_raw_os_error(13);
        assert!(is_permission_denied(&err));
    }
}

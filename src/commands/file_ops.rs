//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

use hecate_protocol::policy::{self, PolicyError};

use super::CommandError;

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_file_path(path: &str, allowed_cwd: &[String]) -> Result<(), CommandError> {
    policy::reject_path_traversal(path).map_err(CommandError::Policy)?;
    policy::check_cwd_policy(path, allowed_cwd).map_err(CommandError::Policy)
}

pub fn resolve_read_path(path: &str, allowed_cwd: &[String]) -> Result<PathBuf, CommandError> {
    validate_file_path(path, allowed_cwd)?;
    let path = Path::new(path);
    if !path.exists() {
        return Err(CommandError::Execution(format!(
            "path does not exist: {}",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        CommandError::Execution(format!("canonicalize {}: {error}", path.display()))
    })?;
    ensure_path_allowed(&canonical, allowed_cwd)?;
    if !canonical.is_file() {
        return Err(CommandError::Execution(format!(
            "path is not a regular file: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

pub fn resolve_write_path(path: &str, allowed_cwd: &[String]) -> Result<PathBuf, CommandError> {
    validate_file_path(path, allowed_cwd)?;
    let path = Path::new(path);
    if path.exists() {
        let canonical = std::fs::canonicalize(path).map_err(|error| {
            CommandError::Execution(format!("canonicalize {}: {error}", path.display()))
        })?;
        ensure_path_allowed(&canonical, allowed_cwd)?;
        Ok(canonical)
    } else if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            return Err(CommandError::Execution(
                "destination path must include a parent directory".into(),
            ));
        }
        if !parent.exists() {
            return Err(CommandError::Execution(format!(
                "parent directory does not exist: {}",
                parent.display()
            )));
        }
        let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
            CommandError::Execution(format!("canonicalize {}: {error}", parent.display()))
        })?;
        ensure_path_allowed(&canonical_parent, allowed_cwd)?;
        let file_name = path.file_name().ok_or_else(|| {
            CommandError::Execution("destination path must include a file name".into())
        })?;
        Ok(canonical_parent.join(file_name))
    } else {
        Err(CommandError::Execution(
            "destination path must include a parent directory".into(),
        ))
    }
}

fn ensure_path_allowed(path: &Path, allowed_cwd: &[String]) -> Result<(), CommandError> {
    let path_str = path.to_string_lossy();
    policy::check_cwd_policy(path_str.trim(), allowed_cwd).map_err(|error| match error {
        PolicyError::CwdNotAllowed { cwd } => CommandError::Policy(PolicyError::CwdNotAllowed { cwd }),
        other => CommandError::Policy(other),
    })
}

pub fn read_file_limited(path: &Path, max_bytes: u32) -> Result<Vec<u8>, CommandError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        CommandError::Execution(format!("stat {}: {error}", path.display()))
    })?;
    if metadata.len() > max_bytes as u64 {
        return Err(CommandError::Execution(format!(
            "file exceeds max size of {max_bytes} bytes"
        )));
    }
    std::fs::read(path).map_err(|error| {
        CommandError::Execution(format!("read {}: {error}", path.display()))
    })
}

pub fn atomic_write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CommandError> {
    #[cfg(not(unix))]
    let _ = mode;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CommandError::Execution(format!("create parent {}: {error}", parent.display()))
        })?;
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(CommandError::Execution(format!(
                "refusing to overwrite symlink: {}",
                path.display()
            )));
        }
    }

    let nonce = rand::random::<u64>();
    let file_name = path.file_name().ok_or_else(|| {
        CommandError::Execution("destination path must include a file name".into())
    })?;
    let temp_path = path.with_file_name(format!(
        ".{}.hecate-tmp-{nonce:016x}",
        file_name.to_string_lossy()
    ));

    write_new_file_nofollow(&temp_path, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(mode)).map_err(
            |error| CommandError::Execution(format!("chmod {}: {error}", temp_path.display())),
        )?;
    }

    std::fs::rename(&temp_path, path).map_err(|error| {
        let _ = std::fs::remove_file(&temp_path);
        CommandError::Execution(format!(
            "rename {} -> {}: {error}",
            temp_path.display(),
            path.display()
        ))
    })
}

fn write_new_file_nofollow(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                CommandError::Execution(format!(
                    "create {} (O_NOFOLLOW): {error}",
                    path.display()
                ))
            })?;
        file.write_all(bytes).map_err(|error| {
            CommandError::Execution(format!("write {}: {error}", path.display()))
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| {
                CommandError::Execution(format!("create {}: {error}", path.display()))
            })?;
        file.write_all(bytes).map_err(|error| {
            CommandError::Execution(format!("write {}: {error}", path.display()))
        })?;
        Ok(())
    }
}

pub fn parse_file_mode(raw: Option<&str>) -> Result<u32, CommandError> {
    let mode = raw.unwrap_or("0644");
    parse_mode_octal(mode)
}

pub fn parse_dir_mode(raw: Option<&str>) -> Result<u32, CommandError> {
    let mode = raw.unwrap_or("0755");
    parse_mode_octal(mode)
}

fn parse_mode_octal(mode: &str) -> Result<u32, CommandError> {
    if mode.len() != 4 || !mode.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(CommandError::InvalidParams(
            "mode must be a 4-digit octal string".into(),
        ));
    }
    u32::from_str_radix(mode, 8)
        .map_err(|_| CommandError::InvalidParams("invalid mode".into()))
}

pub fn reject_path_traversal(path: &str) -> Result<(), CommandError> {
    if path
        .split(['/', '\\'])
        .any(|component| component == "..")
    {
        return Err(CommandError::InvalidParams(
            "path must not contain .. components".into(),
        ));
    }
    Ok(())
}

pub fn validate_name_component(name: &str) -> Result<(), CommandError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(CommandError::InvalidParams("name must not be empty".into()));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(CommandError::InvalidParams(
            "name must not contain path separators".into(),
        ));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(CommandError::InvalidParams("invalid name".into()));
    }
    Ok(())
}

pub fn resolve_existing_dir(path: &str, allowed_cwd: &[String]) -> Result<PathBuf, CommandError> {
    reject_path_traversal(path)?;
    validate_file_path(path, allowed_cwd)?;
    let path = Path::new(path);
    if !path.exists() {
        return Err(CommandError::Execution(format!(
            "path does not exist: {}",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        CommandError::Execution(format!("canonicalize {}: {error}", path.display()))
    })?;
    ensure_path_allowed(&canonical, allowed_cwd)?;
    if !canonical.is_dir() {
        return Err(CommandError::Execution(format!(
            "path is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

pub fn resolve_dir_create_path(path: &str, allowed_cwd: &[String]) -> Result<PathBuf, CommandError> {
    reject_path_traversal(path)?;
    validate_file_path(path, allowed_cwd)?;
    let path = Path::new(path);
    if path.exists() {
        return Err(CommandError::Execution(format!(
            "path already exists: {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        if parent.exists() {
            let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
                CommandError::Execution(format!("canonicalize {}: {error}", parent.display()))
            })?;
            ensure_path_allowed(&canonical_parent, allowed_cwd)?;
        }
    }
    Ok(path.to_path_buf())
}

pub fn resolve_rename_target(
    path: &str,
    new_name: &str,
    allowed_cwd: &[String],
    must_be_dir: bool,
) -> Result<(PathBuf, PathBuf), CommandError> {
    reject_path_traversal(path)?;
    validate_name_component(new_name)?;
    let source = if must_be_dir {
        resolve_existing_dir(path, allowed_cwd)?
    } else {
        resolve_read_path(path, allowed_cwd)?
    };
    let Some(parent) = source.parent() else {
        return Err(CommandError::Execution(
            "cannot rename path without parent directory".into(),
        ));
    };
    let target = parent.join(new_name.trim());
    validate_file_path(target.to_string_lossy().as_ref(), allowed_cwd)?;
    if target.exists() {
        return Err(CommandError::Execution(format!(
            "target already exists: {}",
            target.display()
        )));
    }
    Ok((source, target))
}

pub fn copy_file_path(src: &Path, dest: &Path) -> Result<(), CommandError> {
    if dest.exists() {
        return Err(CommandError::Execution(format!(
            "destination already exists: {}",
            dest.display()
        )));
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CommandError::Execution(format!("create parent {}: {error}", parent.display()))
        })?;
    }

    let copy_result = copy_file_nofollow(src, dest);
    if copy_result.is_err() && dest.exists() {
        let _ = std::fs::remove_file(dest);
    }
    copy_result
}

fn copy_file_nofollow(src: &Path, dest: &Path) -> Result<(), CommandError> {
    let meta = std::fs::symlink_metadata(src).map_err(|error| {
        CommandError::Execution(format!("stat {}: {error}", src.display()))
    })?;
    if meta.file_type().is_symlink() {
        return Err(CommandError::Execution(format!(
            "refusing to copy symlink (folder.copy does not follow or copy symlinks): {}",
            src.display()
        )));
    }
    if !meta.is_file() {
        return Err(CommandError::Execution(format!(
            "path is not a regular file: {}",
            src.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::io::{Read, Write};
        use std::os::unix::fs::OpenOptionsExt;

        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(src)
            .map_err(|error| {
                CommandError::Execution(format!(
                    "open {} (O_NOFOLLOW): {error}",
                    src.display()
                ))
            })?;
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .map_err(|error| {
                CommandError::Execution(format!("create {}: {error}", dest.display()))
            })?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = source.read(&mut buf).map_err(|error| {
                CommandError::Execution(format!("read {}: {error}", src.display()))
            })?;
            if n == 0 {
                break;
            }
            target.write_all(&buf[..n]).map_err(|error| {
                CommandError::Execution(format!("write {}: {error}", dest.display()))
            })?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        use std::io::{Read, Write};
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CommandError::Execution(format!(
                "refusing to copy reparse point: {}",
                src.display()
            )));
        }

        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(src)
            .map_err(|error| {
                CommandError::Execution(format!("open {}: {error}", src.display()))
            })?;
        let opened = source.metadata().map_err(|error| {
            CommandError::Execution(format!("stat {}: {error}", src.display()))
        })?;
        if opened.file_type().is_symlink()
            || opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(CommandError::Execution(format!(
                "refusing to copy reparse point: {}",
                src.display()
            )));
        }
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .map_err(|error| {
                CommandError::Execution(format!("create {}: {error}", dest.display()))
            })?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = source.read(&mut buf).map_err(|error| {
                CommandError::Execution(format!("read {}: {error}", src.display()))
            })?;
            if n == 0 {
                break;
            }
            target.write_all(&buf[..n]).map_err(|error| {
                CommandError::Execution(format!("write {}: {error}", dest.display()))
            })?;
        }
        Ok(())
    }
}

pub fn move_path(src: &Path, dest: &Path) -> Result<(), CommandError> {
    if dest.exists() {
        return Err(CommandError::Execution(format!(
            "destination already exists: {}",
            dest.display()
        )));
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CommandError::Execution(format!("create parent {}: {error}", parent.display()))
        })?;
    }
    std::fs::rename(src, dest).map_err(|error| {
        CommandError::Execution(format!(
            "move {} -> {}: {error}",
            src.display(),
            dest.display()
        ))
    })
}

pub fn delete_file_path(path: &Path) -> Result<(), CommandError> {
    std::fs::remove_file(path).map_err(|error| {
        CommandError::Execution(format!("delete {}: {error}", path.display()))
    })
}

pub fn remove_empty_dir(path: &Path) -> Result<(), CommandError> {
    std::fs::remove_dir(path).map_err(|error| {
        CommandError::Execution(format!("rmdir {}: {error}", path.display()))
    })
}

pub fn create_dir_path(path: &Path, mode: u32) -> Result<(), CommandError> {
    #[cfg(not(unix))]
    let _ = mode;

    std::fs::DirBuilder::new()
        .recursive(false)
        .create(path)
        .map_err(|error| CommandError::Execution(format!("mkdir {}: {error}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
            CommandError::Execution(format!("chmod {}: {error}", path.display()))
        })?;
    }
    Ok(())
}

pub fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<(), CommandError> {
    if dest.exists() {
        return Err(CommandError::Execution(format!(
            "destination already exists: {}",
            dest.display()
        )));
    }
    let result = copy_dir_recursive_inner(src, dest);
    if result.is_err() && dest.exists() {
        let _ = std::fs::remove_dir_all(dest);
    }
    result
}

fn copy_dir_recursive_inner(src: &Path, dest: &Path) -> Result<(), CommandError> {
    std::fs::create_dir_all(dest).map_err(|error| {
        CommandError::Execution(format!("mkdir {}: {error}", dest.display()))
    })?;
    for entry in std::fs::read_dir(src).map_err(|error| {
        CommandError::Execution(format!("read dir {}: {error}", src.display()))
    })? {
        let entry = entry.map_err(|error| {
            CommandError::Execution(format!("read dir entry in {}: {error}", src.display()))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            CommandError::Execution(format!(
                "stat {}: {error}",
                entry.path().display()
            ))
        })?;
        let target = dest.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(CommandError::Execution(format!(
                "refusing to copy symlink (folder.copy does not follow or copy symlinks): {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            copy_dir_recursive_inner(&entry.path(), &target)?;
        } else if file_type.is_file() {
            copy_file_nofollow(&entry.path(), &target)?;
        } else {
            return Err(CommandError::Execution(format!(
                "unsupported entry type: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

pub fn success_output(value: serde_json::Value) -> super::CommandOutput {
    super::CommandOutput {
        stdout: value.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolve_read_path_rejects_outside_allowed_cwd() {
        let dir = TempDir::new().unwrap();
        let allowed = vec![dir.path().to_string_lossy().into_owned()];
        let outside = "/etc/passwd";
        assert!(resolve_read_path(outside, &allowed).is_err());
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("output.txt");
        atomic_write_file(&target, b"hello", 0o644).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    }
}

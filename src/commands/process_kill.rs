//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Cross-platform helpers to terminate spawned command processes (and children).

use std::process::{Child, Command};

/// Configure the child so it can be killed as a process group on Unix.
pub fn configure_command_process_group(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // New process group leader so we can kill(-pid) for the whole tree.
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let _ = cmd;
}

/// Kill the spawned process. On Unix, also SIGKILL the process group so shell
/// grandchildren (e.g. `docker logs -f` under an elevated wrapper) do not keep
/// stdout/stderr pipes open after cancel/timeout.
pub fn kill_child_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(child.id()) {
            unsafe {
                let _ = libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

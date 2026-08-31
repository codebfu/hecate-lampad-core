//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use crate::elevation;
use crate::host::local_hostname;
use crate::AGENT_VERSION;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env::consts::{ARCH, OS};

pub struct SystemInfoCommand;

#[derive(Debug, Deserialize)]
struct SystemInfoParams {}

impl AgentCommand for SystemInfoCommand {
    fn name(&self) -> &'static str {
        "system.info"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
        let _: SystemInfoParams = serde_json::from_value(params)
            .map_err(|e| CommandError::InvalidParams(e.to_string()))?;

        let hostname = local_hostname();

        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let total_memory_bytes = read_total_memory_bytes();

        let info = json!({
            "hostname": hostname,
            "os": OS,
            "arch": ARCH,
            "cpu_count": cpu_count,
            "total_memory_bytes": total_memory_bytes,
            "agent_version": AGENT_VERSION,
            "agent_runtime": {
                "effective_user": elevation::effective_user(),
                "effective_uid": elevation::effective_uid(),
                "is_privileged": elevation::is_privileged(),
                "elevation": {
                    "supported": elevation::elevation_supported(),
                    "method": elevation::elevation_method_name(),
                    "available": elevation::elevation_available(),
                    "constraints": ["non_interactive", "allowlist_only", "use_elevated_flag"]
                }
            }
        });

        Ok(CommandOutput {
            stdout: serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".into()),
            stderr: String::new(),
            exit_code: Some(0),
            truncated: false,
        })
    }
}

fn read_total_memory_bytes() -> u64 {
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if let Some(kb) = line.strip_prefix("MemTotal:") {
                    if let Ok(kb_val) = kb.trim().trim_end_matches(" kB").parse::<u64>() {
                        return kb_val * 1024;
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        #[repr(C)]
        struct MemoryStatusEx {
            length: u32,
            memory_load: u32,
            total_phys: u64,
            avail_phys: u64,
            total_page_file: u64,
            avail_page_file: u64,
            total_virtual: u64,
            avail_virtual: u64,
            avail_extended_virtual: u64,
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
        }

        let mut status = MemoryStatusEx {
            length: std::mem::size_of::<MemoryStatusEx>() as u32,
            memory_load: 0,
            total_phys: 0,
            avail_phys: 0,
            total_page_file: 0,
            avail_page_file: 0,
            total_virtual: 0,
            avail_virtual: 0,
            avail_extended_virtual: 0,
        };
        // SAFETY: status is a valid MEMORYSTATUSEX buffer with dwLength set.
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
            return status.total_phys;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AgentPolicy;
    use hecate_protocol::permissions::ShellPolicy;
    use uuid::Uuid;

    #[test]
    fn returns_json_with_required_fields() {
        let cmd = SystemInfoCommand;
        let ctx = CommandContext::new(
            Uuid::new_v4(),
            AgentPolicy::new(vec!["system.info".into()], ShellPolicy::default()),
        );
        let out = cmd.execute(&ctx, json!({})).unwrap();
        let parsed: Value = serde_json::from_str(&out.stdout).unwrap();
        assert!(parsed.get("hostname").is_some());
        assert!(parsed.get("os").is_some());
        assert!(parsed.get("arch").is_some());
        assert!(parsed.get("cpu_count").is_some());
        assert!(parsed.get("agent_version").is_some());
        assert!(parsed.get("agent_runtime").is_some());
    }
}

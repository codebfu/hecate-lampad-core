//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::sync_stub;
use crate::commands::{AgentCommand, CommandContext, CommandError, CommandOutput};
use serde_json::{json, Value};

pub struct ProxmoxConsoleOpenCommand;

impl AgentCommand for ProxmoxConsoleOpenCommand {
    fn name(&self) -> &'static str {
        "proxmox.console.open"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["vmid"],
            "properties": {
                "vmid": { "type": "integer" },
                "fps": { "type": "integer" },
                "format": { "type": "string" },
                "max_duration_secs": { "type": "integer" },
                "session_id": { "type": "string" }
            }
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct ProxmoxConsoleFrameCommand;

impl AgentCommand for ProxmoxConsoleFrameCommand {
    fn name(&self) -> &'static str {
        "proxmox.console.frame"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": { "type": "string" }
            }
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct ProxmoxConsoleInputCommand;

impl AgentCommand for ProxmoxConsoleInputCommand {
    fn name(&self) -> &'static str {
        "proxmox.console.input"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": { "type": "string" },
                "events": { "type": "array" }
            }
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct ProxmoxConsoleCloseCommand;

impl AgentCommand for ProxmoxConsoleCloseCommand {
    fn name(&self) -> &'static str {
        "proxmox.console.close"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": { "type": "string" }
            }
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

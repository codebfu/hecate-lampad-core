//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

pub struct DesktopWindowListCommand;
pub struct DesktopWindowFocusCommand;
pub struct DesktopWindowWaitCommand;

impl AgentCommand for DesktopWindowListCommand {
    fn name(&self) -> &'static str {
        "desktop.window.list"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "include_hidden": { "type": "boolean" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

impl AgentCommand for DesktopWindowFocusCommand {
    fn name(&self) -> &'static str {
        "desktop.window.focus"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "title": { "type": "string" },
                "app": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

impl AgentCommand for DesktopWindowWaitCommand {
    fn name(&self) -> &'static str {
        "desktop.window.wait"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "title": { "type": "string" },
                "app": { "type": "string" },
                "timeout_ms": { "type": "integer" },
                "state": { "type": "string", "enum": ["visible", "focused"] }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

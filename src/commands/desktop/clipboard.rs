//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

pub struct DesktopClipboardGetCommand;

impl AgentCommand for DesktopClipboardGetCommand {
    fn name(&self) -> &'static str {
        "desktop.clipboard.get"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "format": { "type": "string", "enum": ["text", "image"] }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct DesktopClipboardSetCommand;

impl AgentCommand for DesktopClipboardSetCommand {
    fn name(&self) -> &'static str {
        "desktop.clipboard.set"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" },
                "artifact_id": { "type": "string", "format": "uuid" },
                "sha256": { "type": "string" },
                "format": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

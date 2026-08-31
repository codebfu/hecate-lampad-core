//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

pub struct DesktopSessionOpenCommand;

impl AgentCommand for DesktopSessionOpenCommand {
    fn name(&self) -> &'static str {
        "desktop.session.open"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "session_id": { "type": "string", "format": "uuid" },
                "fps": { "type": "integer", "minimum": 1, "maximum": 10 },
                "max_duration_secs": { "type": "integer", "minimum": 30, "maximum": 3600 },
                "display": { "type": "integer", "minimum": 0 },
                "format": { "type": "string", "enum": ["png", "jpeg"] }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct DesktopSessionFrameCommand;

impl AgentCommand for DesktopSessionFrameCommand {
    fn name(&self) -> &'static str {
        "desktop.session.frame"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": { "type": "string", "format": "uuid" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct DesktopSessionInputCommand;

impl AgentCommand for DesktopSessionInputCommand {
    fn name(&self) -> &'static str {
        "desktop.session.input"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["session_id", "events"],
            "properties": {
                "session_id": { "type": "string", "format": "uuid" },
                "events": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 64,
                    "items": { "type": "object" }
                }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

pub struct DesktopSessionCloseCommand;

impl AgentCommand for DesktopSessionCloseCommand {
    fn name(&self) -> &'static str {
        "desktop.session.close"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": { "type": "string", "format": "uuid" }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

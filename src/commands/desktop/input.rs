//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

macro_rules! desktop_input_command {
    ($struct:ident, $name:expr, $schema:expr) => {
        pub struct $struct;

        impl AgentCommand for $struct {
            fn name(&self) -> &'static str {
                $name
            }

            fn input_schema(&self) -> Value {
                $schema
            }

            fn execute(
                &self,
                _ctx: &CommandContext,
                _params: Value,
            ) -> Result<CommandOutput, CommandError> {
                sync_stub(self.name())
            }
        }
    };
}

desktop_input_command!(
    DesktopMoveCommand,
    "desktop.move",
    json!({
        "type": "object",
        "required": ["x", "y"],
        "properties": {
            "x": { "type": "number" },
            "y": { "type": "number" },
            "relative": { "type": "boolean" },
            "display": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
);

desktop_input_command!(
    DesktopClickCommand,
    "desktop.click",
    json!({
        "type": "object",
        "required": ["x", "y"],
        "properties": {
            "x": { "type": "number" },
            "y": { "type": "number" },
            "button": { "type": "string", "enum": ["left", "right", "middle"] },
            "count": { "type": "integer", "minimum": 1, "maximum": 3 },
            "display": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
);

desktop_input_command!(
    DesktopScrollCommand,
    "desktop.scroll",
    json!({
        "type": "object",
        "required": ["x", "y"],
        "properties": {
            "x": { "type": "number" },
            "y": { "type": "number" },
            "dx": { "type": "integer" },
            "dy": { "type": "integer" },
            "delta": { "type": "integer" },
            "display": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
);

desktop_input_command!(
    DesktopDragCommand,
    "desktop.drag",
    json!({
        "type": "object",
        "required": ["from", "to"],
        "properties": {
            "from": {
                "type": "object",
                "required": ["x", "y"],
                "properties": { "x": { "type": "number" }, "y": { "type": "number" } }
            },
            "to": {
                "type": "object",
                "required": ["x", "y"],
                "properties": { "x": { "type": "number" }, "y": { "type": "number" } }
            },
            "button": { "type": "string", "enum": ["left", "right", "middle"] },
            "duration_ms": { "type": "integer", "minimum": 0 },
            "display": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
);

desktop_input_command!(
    DesktopTypeCommand,
    "desktop.type",
    json!({
        "type": "object",
        "required": ["text"],
        "properties": {
            "text": { "type": "string", "minLength": 1 },
            "delay_ms": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
);

desktop_input_command!(
    DesktopKeyCommand,
    "desktop.key",
    json!({
        "type": "object",
        "required": ["key"],
        "properties": {
            "key": { "type": "string", "minLength": 1 },
            "modifiers": { "type": "array", "items": { "type": "string" } },
            "action": { "type": "string", "enum": ["press", "release", "tap"] }
        },
        "additionalProperties": false
    })
);

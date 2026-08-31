//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

pub struct DesktopScreenshotCommand;

impl AgentCommand for DesktopScreenshotCommand {
    fn name(&self) -> &'static str {
        "desktop.screenshot"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "display": { "type": "integer", "minimum": 0 },
                "region": {
                    "type": "object",
                    "required": ["x", "y", "width", "height"],
                    "properties": {
                        "x": { "type": "number" },
                        "y": { "type": "number" },
                        "width": { "type": "number" },
                        "height": { "type": "number" }
                    },
                    "additionalProperties": false
                }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

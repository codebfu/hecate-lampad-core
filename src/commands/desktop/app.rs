//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

pub struct DesktopAppLaunchCommand;

impl AgentCommand for DesktopAppLaunchCommand {
    fn name(&self) -> &'static str {
        "desktop.app.launch"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "app": { "type": "string" },
                "args": { "type": "array", "items": { "type": "string" } },
                "cwd": { "type": "string" },
                "wait_window_ms": { "type": "integer" }
            },
            "required": ["app"],
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

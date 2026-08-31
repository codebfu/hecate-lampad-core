//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use super::sync_stub;
use serde_json::{json, Value};

pub struct DesktopShellRunCommand;

impl AgentCommand for DesktopShellRunCommand {
    fn name(&self) -> &'static str {
        "desktop.shell.run"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "argv": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1
                },
                "cwd": { "type": "string" },
                "env": { "type": "object", "additionalProperties": { "type": "string" } },
                "timeout_secs": { "type": "integer" }
            },
            "required": ["argv"],
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

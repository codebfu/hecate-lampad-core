//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use serde_json::{json, Value};

pub struct HelperInstallCommand;

impl AgentCommand for HelperInstallCommand {
    fn name(&self) -> &'static str {
        "helper.install"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "component": {
                    "type": "string",
                    "enum": ["desktop", "proxmox"]
                }
            },
            "required": ["component"],
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
        let _ = params;
        Err(CommandError::Execution(
            "helper.install must run through the agent service pull loop".into(),
        ))
    }
}

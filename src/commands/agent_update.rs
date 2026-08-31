//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use serde_json::{json, Value};

pub struct AgentUpdateCommand;

impl AgentCommand for AgentUpdateCommand {
    fn name(&self) -> &'static str {
        "agent.update"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, params: Value) -> Result<CommandOutput, CommandError> {
        let _ = params;
        Err(CommandError::Execution(
            "agent.update must run through the agent service pull loop".into(),
        ))
    }
}

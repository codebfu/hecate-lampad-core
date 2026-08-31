//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use super::sync_stub;
use crate::commands::{AgentCommand, CommandContext, CommandError, CommandOutput};
use serde_json::{json, Value};

pub struct ProxmoxVmListCommand;

impl AgentCommand for ProxmoxVmListCommand {
    fn name(&self) -> &'static str {
        "proxmox.vm.list"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object", "properties": {} })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        sync_stub(self.name())
    }
}

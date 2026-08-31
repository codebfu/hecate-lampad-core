//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Keep the locally cached `agent_state` aligned with the Hecate server.

use crate::client::{AgentClient, ClientError};
use crate::config::AgentConfig;
use crate::runtime::RuntimeMode;
use crate::signing::AgentKeypair;
use hecate_protocol::agent::AgentState;
use std::path::Path;
use tracing::info;
use uuid::Uuid;

pub fn runtime_mode_for_agent_state(state: Option<AgentState>) -> RuntimeMode {
    match state {
        Some(AgentState::PendingApproval) => RuntimeMode::PendingApproval,
        Some(AgentState::Active) | Some(AgentState::Revoked) | None => RuntimeMode::Pulling,
    }
}

/// Fetch the authoritative agent state from the server and persist it locally when it changed.
pub async fn refresh_local_agent_state(
    config: &mut AgentConfig,
    agent_id: Uuid,
    keypair: &AgentKeypair,
) -> Result<Option<AgentState>, ClientError> {
    let client = AgentClient::new()?;
    let response = client
        .fetch_agent_status(&config.server_url, agent_id, keypair)
        .await?;
    persist_agent_state(config, response.state)
}

/// Update an in-memory config and write it to disk when the state differs.
pub fn persist_agent_state(
    config: &mut AgentConfig,
    server_state: AgentState,
) -> Result<Option<AgentState>, ClientError> {
    if config.agent_state == Some(server_state) {
        return Ok(None);
    }

    let previous = config.agent_state;
    config.agent_state = Some(server_state);
    if let Err(error) = config.save() {
        config.agent_state = previous;
        return Err(ClientError::InvalidResponse(format!(
            "failed to persist agent state: {error}"
        )));
    }

    info!(
        previous = ?previous,
        current = ?server_state,
        "synced local agent state from server"
    );
    Ok(Some(server_state))
}

/// Best-effort sync used by the CLI status command after a successful server fetch.
pub fn sync_config_agent_state_from_server(
    config_path: &Path,
    server_state: AgentState,
) -> Result<bool, ClientError> {
    let mut config = AgentConfig::load(config_path).map_err(|error| {
        ClientError::InvalidResponse(format!("failed to load config: {error}"))
    })?;
    Ok(persist_agent_state(&mut config, server_state)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn runtime_mode_maps_pending_approval() {
        assert_eq!(
            runtime_mode_for_agent_state(Some(AgentState::PendingApproval)),
            RuntimeMode::PendingApproval
        );
        assert_eq!(
            runtime_mode_for_agent_state(Some(AgentState::Active)),
            RuntimeMode::Pulling
        );
    }

    #[test]
    fn persist_agent_state_writes_active() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut config = AgentConfig {
            server_url: "https://hecate.example.com".into(),
            agent_id: Some(Uuid::new_v4()),
            agent_state: Some(AgentState::PendingApproval),
            config_path: config_path.clone(),
            key_path: dir.path().join("agent.key"),
            ..Default::default()
        };
        config.save().unwrap();

        let changed = persist_agent_state(&mut config, AgentState::Active)
            .unwrap()
            .expect("state changed");
        assert_eq!(changed, AgentState::Active);

        let loaded = AgentConfig::load(&config_path).unwrap();
        assert_eq!(loaded.agent_state, Some(AgentState::Active));
    }

    #[test]
    fn persist_agent_state_noop_when_unchanged() {
        let dir = TempDir::new().unwrap();
        let mut config = AgentConfig {
            server_url: "https://hecate.example.com".into(),
            agent_state: Some(AgentState::Active),
            config_path: dir.path().join("config.toml"),
            ..Default::default()
        };
        assert!(persist_agent_state(&mut config, AgentState::Active)
            .unwrap()
            .is_none());
    }
}

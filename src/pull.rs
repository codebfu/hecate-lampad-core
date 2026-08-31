//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::config::AgentConfig;
use crate::desktop_update::installed_desktop_version;
use crate::host::local_hostname;
use crate::proxmox_update::installed_proxmox_version;
use crate::signing::{AgentKeypair, SignedRequestHeaders};
use crate::tags::collect_agent_tags;
use crate::AGENT_VERSION;
use hecate_protocol::agent::HeartbeatRequest;
use hecate_protocol::task::{AgentTask, PullResponse};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Cap on remembered command IDs used to skip duplicate re-execution.
const RECENT_COMMAND_ID_CAPACITY: usize = 512;

/// Consecutive heartbeat failures before requesting a pull-session reset.
const MAX_CONSECUTIVE_HEARTBEAT_FAILURES: u32 = 6;

/// LRU-ish set of recently executed command IDs (HashSet + insertion order).
#[derive(Debug, Default)]
pub struct RecentCommandIds {
    order: VecDeque<Uuid>,
    set: HashSet<Uuid>,
}

impl RecentCommandIds {
    pub fn with_capacity_hint(capacity: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            set: HashSet::with_capacity(capacity),
        }
    }

    /// Returns `true` if `id` was newly recorded; `false` if it was already seen.
    pub fn insert_if_new(&mut self, id: Uuid) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > RECENT_COMMAND_ID_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct PullConfig {
    pub interval: Duration,
    pub backoff_max: Duration,
}

impl Default for PullConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            backoff_max: Duration::from_secs(300),
        }
    }
}

impl PullConfig {
    pub fn from_agent_config(config: &AgentConfig) -> Self {
        Self {
            interval: Duration::from_secs(config.pull_interval_secs),
            backoff_max: Duration::from_secs(config.backoff_max_secs),
        }
    }
}

#[derive(Debug, Error)]
pub enum PullError {
    #[error("agent not configured: {0}")]
    NotConfigured(&'static str),
    #[error("pull request failed: {0}")]
    Request(String),
    #[error("agent revoked")]
    Revoked,
}

/// Abstraction for pull HTTP transport (enables testing without network).
#[async_trait::async_trait]
pub trait PullClient: Send + Sync {
    async fn pull(&self, headers: &SignedRequestHeaders) -> Result<PullResponse, PullError>;
    async fn submit_heartbeat(
        &self,
        headers: &SignedRequestHeaders,
        body: &[u8],
    ) -> Result<(), PullError>;
}

/// How long after the last successful pull (while idle) before the agent reports unhealthy.
/// Multiplying the pull interval covers transient network blips without masking a stuck loop.
pub fn pull_stale_after(pull_interval: Duration) -> Duration {
    (pull_interval * 3).max(Duration::from_secs(30))
}

/// Snapshot of pull-loop / command health included in every heartbeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHealthSnapshot {
    pub healthy: bool,
    pub busy: bool,
    pub secs_since_last_pull: Option<u64>,
    pub current_command_id: Option<Uuid>,
}

/// Shared signing key and heartbeat tag state between the pull loop and heartbeat thread.
pub struct AgentSessionState {
    keypair: Mutex<AgentKeypair>,
    /// Tags collected once at service start; sent on the first heartbeat only.
    startup_tags: Mutex<Option<Vec<String>>>,
    /// Tags queued for the next heartbeat when GUI helper state changes.
    pending_tags: Mutex<Option<Vec<String>>>,
    started_at: Instant,
    stop: AtomicBool,
    /// Last successful pull; None until the first pull succeeds.
    last_pull_ok_at: Mutex<Option<Instant>>,
    /// True while a command is being executed (pull loop may be blocked by design).
    busy: AtomicBool,
    current_command_id: Mutex<Option<Uuid>>,
    /// Max idle time since last pull before reporting unhealthy.
    pull_stale_after: Duration,
    /// Recently executed command IDs (dedup against server redelivery).
    recent_command_ids: Mutex<RecentCommandIds>,
    consecutive_heartbeat_failures: AtomicU32,
}

impl AgentSessionState {
    pub fn new(keypair: AgentKeypair, config_tags: &[String]) -> Arc<Self> {
        Self::with_pull_stale_after(keypair, config_tags, pull_stale_after(Duration::from_secs(5)))
    }

    pub fn with_pull_stale_after(
        keypair: AgentKeypair,
        config_tags: &[String],
        pull_stale_after: Duration,
    ) -> Arc<Self> {
        let mut startup_tags = collect_agent_tags(config_tags).ok();
        if let Some(tags) = startup_tags.as_mut() {
            if crate::desktop_ipc::helper_package_installed() {
                // Initial probe without blocking forever — best-effort sync connect is async-only,
                // so start with gui:none until the pull loop refreshes.
                for tag in crate::desktop_ipc::collect_gui_tags(None) {
                    if !tags.contains(&tag) {
                        tags.push(tag);
                    }
                }
                tags.sort();
                tags.dedup();
            }
        }
        Arc::new(Self {
            keypair: Mutex::new(keypair),
            startup_tags: Mutex::new(startup_tags),
            pending_tags: Mutex::new(None),
            started_at: Instant::now(),
            stop: AtomicBool::new(false),
            last_pull_ok_at: Mutex::new(None),
            busy: AtomicBool::new(false),
            current_command_id: Mutex::new(None),
            pull_stale_after,
            recent_command_ids: Mutex::new(RecentCommandIds::with_capacity_hint(
                RECENT_COMMAND_ID_CAPACITY,
            )),
            consecutive_heartbeat_failures: AtomicU32::new(0),
        })
    }

    /// Queue a full tag set to be sent on the next heartbeat.
    pub fn queue_tag_refresh(&self, tags: Vec<String>) {
        *self.pending_tags.lock().expect("pending_tags lock") = Some(tags);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn set_keypair(&self, keypair: AgentKeypair) {
        *self.keypair.lock().expect("keypair lock") = keypair;
    }

    pub fn keypair(&self) -> AgentKeypair {
        self.keypair.lock().expect("keypair lock").clone()
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn last_pull_ok_at(&self) -> Option<Instant> {
        *self.last_pull_ok_at.lock().expect("last_pull_ok_at lock")
    }

    pub fn record_heartbeat_success(&self) {
        self.consecutive_heartbeat_failures.store(0, Ordering::SeqCst);
    }

    /// Returns true when the heartbeat thread should stop and reset the pull session.
    pub fn record_heartbeat_failure(&self) -> bool {
        let failures = self.consecutive_heartbeat_failures.fetch_add(1, Ordering::SeqCst) + 1;
        failures >= MAX_CONSECUTIVE_HEARTBEAT_FAILURES
    }

    pub fn reset_transport_failures(&self) {
        self.consecutive_heartbeat_failures.store(0, Ordering::SeqCst);
    }

    /// Record a successful pull so heartbeats know the queue loop is alive.
    pub fn mark_pull_ok(&self) {
        *self.last_pull_ok_at.lock().expect("last_pull_ok_at lock") = Some(Instant::now());
    }

    /// Mark the agent as executing work (healthy even if pull is paused).
    pub fn begin_busy(&self, command_id: Option<Uuid>) {
        self.busy.store(true, Ordering::SeqCst);
        *self.current_command_id.lock().expect("current_command_id lock") = command_id;
    }

    /// Mark the agent as executing a command (healthy even if pull is paused).
    pub fn begin_command(&self, command_id: Uuid) {
        self.begin_busy(Some(command_id));
    }

    /// Record `command_id` as seen. Returns `false` if it was already executed recently.
    pub fn remember_command_id(&self, command_id: Uuid) -> bool {
        self.recent_command_ids
            .lock()
            .expect("recent_command_ids lock")
            .insert_if_new(command_id)
    }

    /// Clear the in-flight work marker after completion or failure.
    pub fn end_command(&self) {
        self.busy.store(false, Ordering::SeqCst);
        *self.current_command_id.lock().expect("current_command_id lock") = None;
    }

    /// Global health: busy with a command, recent pull, or still within startup grace.
    pub fn health_snapshot(&self) -> AgentHealthSnapshot {
        let busy = self.busy.load(Ordering::SeqCst);
        let current_command_id = if busy {
            self.current_command_id
                .lock()
                .expect("current_command_id lock")
                .clone()
        } else {
            None
        };
        let last_pull = *self.last_pull_ok_at.lock().expect("last_pull_ok_at lock");
        let secs_since_last_pull = last_pull.map(|at| at.elapsed().as_secs());
        let healthy = if busy {
            true
        } else if let Some(at) = last_pull {
            at.elapsed() <= self.pull_stale_after
        } else {
            // Grace period before the first pull succeeds.
            self.started_at.elapsed() <= self.pull_stale_after
        };
        AgentHealthSnapshot {
            healthy,
            busy,
            secs_since_last_pull,
            current_command_id,
        }
    }

    fn take_heartbeat_tags(&self) -> Vec<String> {
        self.startup_tags
            .lock()
            .expect("startup_tags lock")
            .take()
            .or_else(|| self.pending_tags.lock().expect("pending_tags lock").take())
            .unwrap_or_default()
    }
}

async fn send_heartbeat_once<C: PullClient>(
    client: &C,
    agent_id: Uuid,
    state: &AgentSessionState,
) -> Result<(), PullError> {
    let tags = state.take_heartbeat_tags();
    let health = state.health_snapshot();
    let keypair = state.keypair();
    let body = HeartbeatRequest {
        agent_version: AGENT_VERSION.to_string(),
        uptime_secs: state.uptime_secs(),
        hostname: local_hostname(),
        tags,
        desktop_version: installed_desktop_version(),
        proxmox_version: installed_proxmox_version(),
        healthy: Some(health.healthy),
        busy: health.busy,
        secs_since_last_pull: health.secs_since_last_pull,
        current_command_id: health.current_command_id,
    };
    let body_bytes =
        serde_json::to_vec(&body).map_err(|error| PullError::Request(error.to_string()))?;
    let headers = SignedRequestHeaders::new(
        agent_id,
        &keypair,
        "POST",
        "/api/v1/agent/heartbeat",
        &body_bytes,
    );
    client.submit_heartbeat(&headers, &body_bytes).await
}

/// Dedicated OS thread that keeps heartbeats flowing while long commands run.
pub struct HeartbeatThread {
    state: Arc<AgentSessionState>,
    join: Option<JoinHandle<()>>,
}

impl HeartbeatThread {
    pub fn spawn<C>(client: C, agent_id: Uuid, state: Arc<AgentSessionState>, interval: Duration) -> Self
    where
        C: PullClient + Clone + 'static,
    {
        let thread_state = Arc::clone(&state);
        let join = std::thread::Builder::new()
            .name("hecate-heartbeat".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        error!(error = %error, "failed to create heartbeat runtime");
                        return;
                    }
                };
                runtime.block_on(async move {
                    info!(agent_id = %agent_id, interval_secs = interval.as_secs(), "heartbeat thread started");
                    loop {
                        if thread_state.should_stop() {
                            break;
                        }
                        if let Err(error) =
                            send_heartbeat_once(&client, agent_id, thread_state.as_ref()).await
                        {
                            warn!(error = %error, "heartbeat failed");
                            if thread_state.record_heartbeat_failure() {
                                warn!(
                                    failures = MAX_CONSECUTIVE_HEARTBEAT_FAILURES,
                                    "too many consecutive heartbeat failures; resetting pull session"
                                );
                                thread_state.request_stop();
                                break;
                            }
                        } else {
                            thread_state.record_heartbeat_success();
                        }
                        // Interruptible sleep so Drop can stop the thread promptly.
                        let mut remaining = interval;
                        while remaining > Duration::ZERO && !thread_state.should_stop() {
                            let slice = remaining.min(Duration::from_millis(200));
                            tokio::time::sleep(slice).await;
                            remaining = remaining.saturating_sub(slice);
                        }
                    }
                    info!(agent_id = %agent_id, "heartbeat thread stopping");
                });
            })
            .expect("failed to spawn heartbeat thread");

        Self {
            state,
            join: Some(join),
        }
    }
}

impl Drop for HeartbeatThread {
    fn drop(&mut self) {
        self.state.request_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Pull loop with exponential backoff on errors.
///
/// Heartbeats run on a separate [`HeartbeatThread`] so long-running commands do not
/// starve `last_seen_at` updates on the server.
pub struct PullLoop<C: PullClient> {
    client: C,
    agent_id: Uuid,
    state: Arc<AgentSessionState>,
    config: PullConfig,
    backoff: Duration,
}

impl<C: PullClient> PullLoop<C> {
    pub fn new(
        client: C,
        agent_id: Uuid,
        keypair: AgentKeypair,
        config: PullConfig,
        config_tags: &[String],
    ) -> Self {
        let interval = config.interval;
        Self {
            client,
            agent_id,
            state: AgentSessionState::with_pull_stale_after(
                keypair,
                config_tags,
                pull_stale_after(interval),
            ),
            config,
            backoff: interval,
        }
    }

    pub fn with_state(client: C, agent_id: Uuid, state: Arc<AgentSessionState>, config: PullConfig) -> Self {
        let interval = config.interval;
        Self {
            client,
            agent_id,
            state,
            config,
            backoff: interval,
        }
    }

    pub fn session_state(&self) -> Arc<AgentSessionState> {
        Arc::clone(&self.state)
    }

    /// Queue a full tag set to be sent on the next heartbeat.
    pub fn queue_tag_refresh(&self, tags: Vec<String>) {
        self.state.queue_tag_refresh(tags);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.state.uptime_secs()
    }

    pub async fn pull_once(&self) -> Result<PullResponse, PullError> {
        let body = b"";
        let keypair = self.state.keypair();
        let headers = SignedRequestHeaders::new(
            self.agent_id,
            &keypair,
            "GET",
            "/api/v1/agent/pull",
            body,
        );
        debug!(agent_id = %self.agent_id, "pulling tasks from server");
        self.client.pull(&headers).await
    }

    pub fn set_keypair(&self, keypair: AgentKeypair) {
        self.state.set_keypair(keypair);
    }

    pub fn keypair(&self) -> AgentKeypair {
        self.state.keypair()
    }

    pub async fn send_heartbeat(&self) -> Result<(), PullError> {
        send_heartbeat_once(&self.client, self.agent_id, self.state.as_ref()).await
    }

    pub async fn run_iteration<F, Fut>(&mut self, mut handle_task: F) -> Result<(), PullError>
    where
        F: FnMut(AgentTask) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        match self.pull_once().await {
            Ok(response) => {
                self.state.mark_pull_ok();
                self.backoff = self.config.interval;
                for task in response.tasks {
                    handle_task(task).await;
                }
                tokio::time::sleep(self.config.interval).await;
                Ok(())
            }
            Err(PullError::Revoked) => {
                error!("agent credential revoked; stopping pull loop");
                Err(PullError::Revoked)
            }
            Err(e) => {
                warn!(error = %e, backoff_secs = self.backoff.as_secs(), "pull failed");
                tokio::time::sleep(self.backoff).await;
                self.backoff = (self.backoff * 2).min(self.config.backoff_max);
                Err(e)
            }
        }
    }

    pub async fn run<F, Fut>(&mut self, mut handle_task: F) -> !
    where
        F: FnMut(AgentTask) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        info!(agent_id = %self.agent_id, "starting pull loop");
        loop {
            let _ = self.run_iteration(&mut handle_task).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hecate_protocol::agent::HeartbeatRequest;
    use hecate_protocol::task::AgentTask;
    use std::sync::atomic::AtomicUsize;

    struct MockClient {
        tasks: PullResponse,
    }

    struct CapturingMockClient {
        tasks: PullResponse,
        bodies: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    #[derive(Clone)]
    struct CountingMockClient {
        heartbeats: Arc<AtomicUsize>,
        block_pull: Arc<AtomicBool>,
    }

    #[async_trait]
    impl PullClient for MockClient {
        async fn pull(&self, _headers: &SignedRequestHeaders) -> Result<PullResponse, PullError> {
            Ok(self.tasks.clone())
        }

        async fn submit_heartbeat(
            &self,
            _headers: &SignedRequestHeaders,
            _body: &[u8],
        ) -> Result<(), PullError> {
            Ok(())
        }
    }

    #[async_trait]
    impl PullClient for CapturingMockClient {
        async fn pull(&self, _headers: &SignedRequestHeaders) -> Result<PullResponse, PullError> {
            Ok(self.tasks.clone())
        }

        async fn submit_heartbeat(
            &self,
            _headers: &SignedRequestHeaders,
            body: &[u8],
        ) -> Result<(), PullError> {
            self.bodies.lock().unwrap().push(body.to_vec());
            Ok(())
        }
    }

    #[async_trait]
    impl PullClient for CountingMockClient {
        async fn pull(&self, _headers: &SignedRequestHeaders) -> Result<PullResponse, PullError> {
            while self.block_pull.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(PullResponse {
                tasks: vec![],
                key_material: None,
            })
        }

        async fn submit_heartbeat(
            &self,
            _headers: &SignedRequestHeaders,
            _body: &[u8],
        ) -> Result<(), PullError> {
            self.heartbeats.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn pull_once_returns_tasks() {
        let kp = AgentKeypair::generate();
        let client = MockClient {
            tasks: PullResponse {
                tasks: vec![AgentTask::NoOp],
                key_material: None,
            },
        };
        let config = PullConfig::default();
        let pull_loop = PullLoop::new(client, Uuid::new_v4(), kp, config, &[]);
        let response = pull_loop.pull_once().await.unwrap();
        assert_eq!(response.tasks.len(), 1);
    }

    #[tokio::test]
    async fn send_heartbeat_includes_tags_only_on_first_call() {
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let client = CapturingMockClient {
            tasks: PullResponse {
                tasks: vec![],
                key_material: None,
            },
            bodies: std::sync::Arc::clone(&bodies),
        };
        let pull_loop = PullLoop::new(
            client,
            Uuid::new_v4(),
            AgentKeypair::generate(),
            PullConfig::default(),
            &[],
        );

        pull_loop.send_heartbeat().await.expect("first heartbeat");
        pull_loop.send_heartbeat().await.expect("second heartbeat");

        let locked = bodies.lock().unwrap();
        let first: HeartbeatRequest =
            serde_json::from_slice(&locked[0]).expect("first heartbeat json");
        let second: HeartbeatRequest =
            serde_json::from_slice(&locked[1]).expect("second heartbeat json");

        assert!(first.tags.iter().any(|tag| tag.starts_with("os:")));
        assert!(first.tags.iter().any(|tag| tag.starts_with("arch:")));
        assert!(second.tags.is_empty());
    }

    #[test]
    fn heartbeat_thread_keeps_sending_while_caller_blocks() {
        let heartbeats = Arc::new(AtomicUsize::new(0));
        let block_pull = Arc::new(AtomicBool::new(true));
        let client = CountingMockClient {
            heartbeats: Arc::clone(&heartbeats),
            block_pull: Arc::clone(&block_pull),
        };
        let state = AgentSessionState::new(AgentKeypair::generate(), &[]);
        let _heartbeat = HeartbeatThread::spawn(
            client,
            Uuid::new_v4(),
            Arc::clone(&state),
            Duration::from_millis(40),
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while heartbeats.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            heartbeats.load(Ordering::SeqCst) >= 2,
            "expected heartbeats while blocked, got {}",
            heartbeats.load(Ordering::SeqCst)
        );
        block_pull.store(false, Ordering::SeqCst);
    }

    #[test]
    fn health_stays_healthy_while_busy_even_if_pull_is_stale() {
        let state = AgentSessionState::with_pull_stale_after(
            AgentKeypair::generate(),
            &[],
            Duration::from_millis(30),
        );
        state.mark_pull_ok();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!state.health_snapshot().healthy, "stale pull must be unhealthy when idle");

        let command_id = Uuid::new_v4();
        state.begin_command(command_id);
        let health = state.health_snapshot();
        assert!(health.healthy, "busy agent remains healthy during long commands");
        assert!(health.busy);
        assert_eq!(health.current_command_id, Some(command_id));

        state.end_command();
        assert!(!state.health_snapshot().healthy);
    }

    #[test]
    fn recent_command_ids_dedup_and_evict() {
        let mut recent = RecentCommandIds::with_capacity_hint(4);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        assert!(recent.insert_if_new(first));
        assert!(!recent.insert_if_new(first));
        assert!(recent.insert_if_new(second));

        for i in 3u128..=(RECENT_COMMAND_ID_CAPACITY as u128 + 2) {
            assert!(recent.insert_if_new(Uuid::from_u128(i)));
        }
        assert!(recent.insert_if_new(first));
    }

    #[test]
    fn health_reports_healthy_after_recent_pull() {
        let state = AgentSessionState::with_pull_stale_after(
            AgentKeypair::generate(),
            &[],
            Duration::from_secs(30),
        );
        state.mark_pull_ok();
        let health = state.health_snapshot();
        assert!(health.healthy);
        assert!(!health.busy);
        assert_eq!(health.secs_since_last_pull, Some(0));
    }

    #[tokio::test]
    async fn send_heartbeat_includes_health_fields() {
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let client = CapturingMockClient {
            tasks: PullResponse {
                tasks: vec![],
                key_material: None,
            },
            bodies: std::sync::Arc::clone(&bodies),
        };
        let pull_loop = PullLoop::new(
            client,
            Uuid::new_v4(),
            AgentKeypair::generate(),
            PullConfig::default(),
            &[],
        );
        pull_loop.session_state().mark_pull_ok();
        pull_loop.send_heartbeat().await.expect("heartbeat");

        let locked = bodies.lock().unwrap();
        let body: HeartbeatRequest =
            serde_json::from_slice(&locked[0]).expect("heartbeat json");
        assert_eq!(body.healthy, Some(true));
        assert!(!body.busy);
        assert!(body.secs_since_last_pull.is_some());
    }
}

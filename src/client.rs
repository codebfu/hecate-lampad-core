//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! HTTP client for agent ↔ server communication.

use crate::pull::{PullClient, PullError};
use crate::signing::{AgentKeypair, SignedRequestHeaders};
use async_trait::async_trait;
use hecate_protocol::agent::{AgentStatusResponse, EnrollRequest, EnrollResponse};
use hecate_protocol::command::CommandResultPayload;
use hecate_protocol::task::PullResponse;
use reqwest::StatusCode;
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;

pub const ENROLL_PATH: &str = "/api/v1/agent/enroll";
pub const STATUS_PATH: &str = "/api/v1/agent/status";
pub const PULL_PATH: &str = "/api/v1/agent/pull";
pub const UPDATE_OFFER_PATH: &str = "/api/v1/agent/update-offer";
pub const HEARTBEAT_PATH: &str = "/api/v1/agent/heartbeat";
pub const RESULTS_PATH: &str = "/api/v1/agent/results";
pub const COMMAND_ARTIFACT_PATH_PREFIX: &str = "/api/v1/agent/commands";

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct UploadedArtifact {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub size_bytes: i64,
}

pub fn command_artifact_path(command_id: Uuid) -> String {
    format!("{COMMAND_ARTIFACT_PATH_PREFIX}/{command_id}/artifact")
}

pub(crate) fn agent_download_url(server_url: &str, path: &str) -> Result<String, ClientError> {
    if !path.starts_with("/api/v1/agent/") {
        return Err(ClientError::InvalidResponse(
            "download path is not an agent API path".into(),
        ));
    }
    if path.contains("://")
        || path.starts_with("//")
        || path.contains("..")
        || path.contains('\\')
        || path.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r' || b == b' ')
    {
        return Err(ClientError::InvalidResponse(
            "download path is not a safe relative agent path".into(),
        ));
    }
    let base = reqwest::Url::parse(&format!(
        "{}/",
        AgentClient::normalize_base_url(server_url)
    ))
    .map_err(|error| ClientError::InvalidResponse(format!("invalid server URL: {error}")))?;
    let joined = base
        .join(path)
        .map_err(|error| ClientError::InvalidResponse(format!("invalid download path: {error}")))?;
    if joined.scheme() != base.scheme()
        || joined.host() != base.host()
        || joined.port_or_known_default() != base.port_or_known_default()
    {
        return Err(ClientError::InvalidResponse(
            "download path escaped the configured server origin".into(),
        ));
    }
    Ok(joined.to_string())
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("server returned {status}: {body}")]
    Server { status: StatusCode, body: String },
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityResult {
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct AgentClient {
    http: reqwest::Client,
}

impl AgentClient {
    pub fn new() -> Result<Self, ClientError> {
        Ok(Self {
            http: build_strict_http_client(Duration::from_secs(15))?,
        })
    }

    pub(crate) fn normalize_base_url(server_url: &str) -> String {
        server_url.trim_end_matches('/').to_string()
    }

    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    pub async fn enroll(
        &self,
        server_url: &str,
        request: &EnrollRequest,
    ) -> Result<EnrollResponse, ClientError> {
        let url = format!("{}{}", Self::normalize_base_url(server_url), ENROLL_PATH);
        let response = self.http.post(url).json(request).send().await?;
        Self::decode_json(response).await
    }

    pub async fn fetch_agent_status(
        &self,
        server_url: &str,
        agent_id: Uuid,
        keypair: &AgentKeypair,
    ) -> Result<AgentStatusResponse, ClientError> {
        let signed = SignedRequestHeaders::new(agent_id, keypair, "GET", STATUS_PATH, b"");
        let url = format!("{}{}", Self::normalize_base_url(server_url), STATUS_PATH);
        let response = signed
            .apply_to_request(self.http.get(url))
            .send()
            .await?;
        Self::decode_json(response).await
    }

    pub async fn check_reachability(&self, server_url: &str) -> ReachabilityResult {
        let url = format!("{}{}", Self::normalize_base_url(server_url), PULL_PATH);
        let started = Instant::now();
        match self.http.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() || status == StatusCode::UNAUTHORIZED {
                    ReachabilityResult {
                        reachable: true,
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                        error: None,
                    }
                } else {
                    ReachabilityResult {
                        reachable: false,
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                        error: Some(format!("HTTP {status}")),
                    }
                }
            }
            Err(error) => ReachabilityResult {
                reachable: false,
                latency_ms: None,
                error: Some(error.to_string()),
            },
        }
    }

    async fn decode_json<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, ClientError> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(ClientError::Server { status, body });
        }
        serde_json::from_str(&body).map_err(|error| ClientError::InvalidResponse(error.to_string()))
    }
}

impl Default for AgentClient {
    fn default() -> Self {
        Self::new().expect("failed to build HTTP client")
    }
}

/// HTTP transport for the agent pull loop.
#[derive(Clone)]
pub struct HttpPullClient {
    client: AgentClient,
    server_url: String,
}

impl HttpPullClient {
    pub fn new(server_url: String) -> Result<Self, ClientError> {
        Ok(Self {
            client: AgentClient::new()?,
            server_url,
        })
    }

    fn pull_url(&self) -> String {
        format!(
            "{}{}",
            AgentClient::normalize_base_url(&self.server_url),
            PULL_PATH
        )
    }

    fn heartbeat_url(&self) -> String {
        format!(
            "{}{}",
            AgentClient::normalize_base_url(&self.server_url),
            HEARTBEAT_PATH
        )
    }

    fn results_url(&self) -> String {
        format!(
            "{}{}",
            AgentClient::normalize_base_url(&self.server_url),
            RESULTS_PATH
        )
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn http_client(&self) -> &reqwest::Client {
        self.client.http_client()
    }

    pub async fn download_signed(
        &self,
        agent_id: Uuid,
        keypair: &AgentKeypair,
        path: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let url = agent_download_url(&self.server_url, path)?;
        let headers = SignedRequestHeaders::new(agent_id, keypair, "GET", path, b"");
        let response = headers
            .apply_to_request(self.client.http_client().get(url))
            .send()
            .await?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            return Err(ClientError::Server {
                status,
                body: "agent credential revoked".into(),
            });
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ClientError::Server { status, body });
        }

        Ok(response.bytes().await?.to_vec())
    }

    pub async fn upload_artifact(
        &self,
        agent_id: Uuid,
        keypair: &AgentKeypair,
        command_id: Uuid,
        body: &[u8],
        sha256: &str,
        filename: &str,
    ) -> Result<UploadedArtifact, ClientError> {
        let path = command_artifact_path(command_id);
        let url = format!(
            "{}{}",
            AgentClient::normalize_base_url(&self.server_url),
            path
        );
        let headers = SignedRequestHeaders::new(agent_id, keypair, "PUT", &path, body);
        let response = headers
            .apply_to_request(
                self.client
                    .http_client()
                    .put(url)
                    .header("content-type", "application/octet-stream")
                    .header("x-sha256", sha256)
                    .header("x-filename", filename)
                    .body(body.to_vec()),
            )
            .send()
            .await?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            return Err(ClientError::Server {
                status,
                body: "agent credential revoked".into(),
            });
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ClientError::Server { status, body });
        }

        response
            .json()
            .await
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))
    }

    pub async fn submit_result(
        &self,
        agent_id: Uuid,
        keypair: &AgentKeypair,
        result: &CommandResultPayload,
    ) -> Result<(), PullError> {
        let body_bytes =
            serde_json::to_vec(result).map_err(|error| PullError::Request(error.to_string()))?;
        let headers = SignedRequestHeaders::new(
            agent_id,
            keypair,
            "POST",
            RESULTS_PATH,
            &body_bytes,
        );
        let response = headers
            .apply_to_request(
                self.client
                    .http_client()
                    .post(self.results_url())
                    .header("content-type", "application/json")
                    .body(body_bytes),
            )
            .send()
            .await
            .map_err(|error| PullError::Request(error.to_string()))?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            return Err(PullError::Revoked);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PullError::Request(format!("HTTP {status}: {body}")));
        }
        Ok(())
    }

    pub async fn rotate_credentials(
        &self,
        agent_id: Uuid,
        keypair: &AgentKeypair,
        body: &hecate_protocol::agent::RotateCredentialRequest,
    ) -> Result<hecate_protocol::agent::RotateCredentialResponse, ClientError> {
        const PATH: &str = "/api/v1/agent/credentials/rotate";
        let body_bytes = serde_json::to_vec(body)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        let headers = SignedRequestHeaders::new(agent_id, keypair, "POST", PATH, &body_bytes);
        let url = format!(
            "{}{}",
            AgentClient::normalize_base_url(&self.server_url),
            PATH
        );
        let response = headers
            .apply_to_request(
                self.client
                    .http_client()
                    .post(url)
                    .header("content-type", "application/json")
                    .body(body_bytes),
            )
            .send()
            .await?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            return Err(ClientError::Server {
                status,
                body: "agent credential revoked".into(),
            });
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ClientError::Server { status, body });
        }
        response
            .json()
            .await
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))
    }
}

#[async_trait]
impl PullClient for HttpPullClient {
    async fn pull(&self, headers: &SignedRequestHeaders) -> Result<PullResponse, PullError> {
        let response = headers
            .apply_to_request(self.client.http_client().get(self.pull_url()))
            .send()
            .await
            .map_err(|error| PullError::Request(error.to_string()))?;

        map_pull_response(response).await
    }

    async fn submit_heartbeat(
        &self,
        headers: &SignedRequestHeaders,
        body: &[u8],
    ) -> Result<(), PullError> {
        let response = headers
            .apply_to_request(
                self.client
                    .http_client()
                    .post(self.heartbeat_url())
                    .body(body.to_vec()),
            )
            .header("content-type", "application/json")
            .send()
            .await
            .map_err(|error| PullError::Request(error.to_string()))?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            return Err(PullError::Revoked);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PullError::Request(format!("HTTP {status}: {body}")));
        }
        Ok(())
    }
}

/// Strict rustls client: webpki-roots, TLS 1.2+, never `danger_accept_invalid_certs`.
pub fn build_strict_http_client(timeout: Duration) -> Result<reqwest::Client, ClientError> {
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

async fn map_pull_response(response: reqwest::Response) -> Result<PullResponse, PullError> {
    let status = response.status();
    if status == StatusCode::FORBIDDEN {
        return Err(PullError::Revoked);
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(PullError::Request(format!("HTTP {status}: {body}")));
    }
    response
        .json()
        .await
        .map_err(|error| PullError::Request(error.to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_sources_never_disable_tls_verification() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let needle = ["danger_accept_invalid_", "certs(true)"].concat();
        let mut hits = Vec::new();
        walk_rs(&root, &mut hits, &needle);
        assert!(
            hits.is_empty(),
            "danger_accept_invalid_certs must not appear in the agent: {hits:?}"
        );
    }

    fn walk_rs(dir: &std::path::Path, hits: &mut Vec<String>, needle: &str) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs(&path, hits, needle);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if text.contains(needle) {
                        hits.push(path.display().to_string());
                    }
                }
            }
        }
    }

    #[test]
    fn agent_download_url_stays_on_origin() {
        let url = super::agent_download_url(
            "https://hecate.example",
            "/api/v1/agent/releases/linux/amd64/hecate-lampad",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://hecate.example/api/v1/agent/releases/linux/amd64/hecate-lampad"
        );
        assert!(super::agent_download_url("https://hecate.example", "//evil.example/x").is_err());
        assert!(super::agent_download_url(
            "https://hecate.example",
            "https://evil.example/api/v1/agent/x"
        )
        .is_err());
        assert!(super::agent_download_url("https://hecate.example", "/internal/x").is_err());
    }

    #[test]
    fn agent_http_client_disables_redirects() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/client.rs");
        let text = std::fs::read_to_string(path).unwrap();
        assert!(
            text.contains("redirect(reqwest::redirect::Policy::none())"),
            "agent HTTP client must disable automatic redirects"
        );
    }
}

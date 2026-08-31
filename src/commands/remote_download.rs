//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use hecate_protocol::remote_download_policy;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::file_ops::{atomic_write_file, resolve_write_path, sha256_hex};
use super::{AgentCommand, CommandContext, CommandError, CommandOutput};
use crate::client::HttpPullClient;
use crate::signing::AgentKeypair;

pub struct RemoteDownloadCommand;

#[derive(Debug, Deserialize)]
struct RemoteDownloadParams {
    url: String,
    #[serde(default)]
    dest_path: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    /// Server-resolved IP; required for hostname URLs so the agent does not re-resolve DNS.
    #[serde(default)]
    connect_ip: Option<String>,
}

pub async fn run_remote_download_command(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> CommandOutput {
    match execute_remote_download(ctx, client, agent_id, keypair, command_id, params).await {
        Ok(output) => output,
        Err(error) => CommandOutput {
            stdout: String::new(),
            stderr: error.to_string(),
            exit_code: Some(1),
            truncated: false,
        },
    }
}

async fn execute_remote_download(
    ctx: &CommandContext,
    client: &HttpPullClient,
    agent_id: Uuid,
    keypair: &AgentKeypair,
    command_id: Uuid,
    params: Value,
) -> Result<CommandOutput, CommandError> {
    let params: RemoteDownloadParams = serde_json::from_value(params)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;

    remote_download_policy::check_remote_download_url(&params.url)
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;

    if let Some(dest_path) = params.dest_path.as_deref().filter(|value| !value.trim().is_empty()) {
        validate_dest_path(dest_path, &ctx.policy.shell_policy.allowed_cwd)?;
    }

    let timeout = Duration::from_secs(ctx.policy.timeout_secs.min(120) as u64);
    let mut current_url = params.url.clone();
    let mut response = None;
    for hop in 0..5 {
        let parsed = Url::parse(&current_url)
            .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
        let pinned_ip = if hop == 0 {
            params.connect_ip.as_deref()
        } else {
            None
        };
        let pinned = resolve_and_pin_host(&parsed, pinned_ip, hop > 0).await?;
        // Disable automatic redirects: each hop must be re-validated (SSRF defense).
        // Pin DNS via ClientBuilder::resolve so TLS SNI stays on the original hostname.
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10));
        if pinned.host.parse::<std::net::IpAddr>().is_err() {
            builder = builder.resolve(&pinned.host, pinned.addr);
        }
        let http = builder
            .build()
            .map_err(|error| CommandError::Execution(format!("http client: {error}")))?;

        let mut request = http.get(parsed.as_str());
        for (key, value) in &params.headers {
            let name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
                CommandError::InvalidParams(format!("invalid header name {key}: {error}"))
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|error| {
                CommandError::InvalidParams(format!("invalid header value for {key}: {error}"))
            })?;
            request = request.header(name, header_value);
        }

        let resp = request
            .send()
            .await
            .map_err(|error| CommandError::Execution(format!("download request failed: {error}")))?;

        if resp.status().is_redirection() {
            let next = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    CommandError::Execution("redirect without Location header".into())
                })?;
            current_url = parsed
                .join(next)
                .map_err(|error| CommandError::Execution(format!("invalid redirect: {error}")))?
                .to_string();
            remote_download_policy::check_remote_download_url(&current_url)
                .map_err(|error| CommandError::InvalidParams(error.to_string()))?;
            continue;
        }
        response = Some(resp);
        break;
    }
    let response = response.ok_or_else(|| {
        CommandError::Execution("too many redirects while downloading".into())
    })?;
    if !response.status().is_success() {
        return Err(CommandError::Execution(format!(
            "download failed with HTTP {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|error| CommandError::Execution(format!("read response body: {error}")))?
        .to_vec();

    if bytes.len() > ctx.policy.max_file_bytes as usize {
        return Err(CommandError::Execution(format!(
            "download exceeds max size of {} bytes",
            ctx.policy.max_file_bytes
        )));
    }

    if let Some(dest_path) = params.dest_path.as_deref().filter(|value| !value.trim().is_empty()) {
        let resolved = resolve_write_path(dest_path, &ctx.policy.shell_policy.allowed_cwd)?;
        atomic_write_file(&resolved, &bytes, 0o644)?;
        let sha256 = sha256_hex(&bytes);
        return Ok(CommandOutput {
            stdout: json!({
                "url": params.url,
                "dest_path": dest_path,
                "bytes_written": bytes.len(),
                "sha256": sha256,
            })
            .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            truncated: false,
        });
    }

    let sha256 = sha256_hex(&bytes);
    let stored = client
        .upload_artifact(agent_id, keypair, command_id, &bytes, &sha256, "download.bin")
        .await
        .map_err(|error| CommandError::Execution(error.to_string()))?;

    Ok(CommandOutput {
        stdout: json!({
            "artifact_id": stored.artifact_id,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "url": params.url,
        })
        .to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    })
}

#[derive(Debug)]
struct PinnedHost {
    host: String,
    addr: SocketAddr,
}

async fn resolve_and_pin_host(
    url: &Url,
    pinned_ip: Option<&str>,
    allow_agent_dns: bool,
) -> Result<PinnedHost, CommandError> {
    let host = url
        .host_str()
        .ok_or_else(|| CommandError::InvalidParams("url missing host".into()))?
        .to_string();
    remote_download_policy::check_remote_download_url(url.as_str())
        .map_err(|error| CommandError::InvalidParams(error.to_string()))?;

    let port = url.port_or_known_default().unwrap_or(443);
    let addr: SocketAddr = if let Some(pinned) = pinned_ip {
        let ip: std::net::IpAddr = pinned.parse().map_err(|_| {
            CommandError::InvalidParams(format!("invalid connect_ip: {pinned}"))
        })?;
        if remote_download_policy::is_blocked_ip(ip) {
            return Err(CommandError::InvalidParams(format!(
                "connect_ip is not allowed: {ip}"
            )));
        }
        SocketAddr::new(ip, port)
    } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if remote_download_policy::is_blocked_ip(ip) {
            return Err(CommandError::InvalidParams(format!(
                "url host is not allowed: {host}"
            )));
        }
        SocketAddr::new(ip, port)
    } else if allow_agent_dns {
        let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| {
                CommandError::Execution(format!("cannot resolve download host: {error}"))
            })?
            .collect();
        if addresses.is_empty() {
            return Err(CommandError::Execution(
                "download host resolved to no addresses".into(),
            ));
        }
        let mut chosen = None;
        for address in addresses {
            if remote_download_policy::is_blocked_ip(address.ip()) {
                return Err(CommandError::InvalidParams(format!(
                    "download URL resolves to a private or reserved address: {}",
                    address.ip()
                )));
            }
            chosen.get_or_insert(address);
        }
        chosen.ok_or_else(|| {
            CommandError::Execution("download host resolved to no addresses".into())
        })?
    } else {
        return Err(CommandError::InvalidParams(
            "connect_ip is required for hostname download URLs (server must pin DNS)".into(),
        ));
    };

    Ok(PinnedHost { host, addr })
}

fn validate_dest_path(dest_path: &str, allowed_cwd: &[String]) -> Result<(), CommandError> {
    if dest_path.contains("..") {
        return Err(CommandError::InvalidParams(
            "dest_path must not contain ..".into(),
        ));
    }
    super::file_ops::validate_file_path(dest_path, allowed_cwd)
}

impl AgentCommand for RemoteDownloadCommand {
    fn name(&self) -> &'static str {
        "remote.download"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string" },
                "dest_path": { "type": "string" },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "connect_ip": {
                    "type": "string",
                    "description": "Server-injected DNS pin; clients must omit this field"
                }
            },
            "additionalProperties": false
        })
    }

    fn execute(&self, _ctx: &CommandContext, _params: Value) -> Result<CommandOutput, CommandError> {
        Err(CommandError::Execution(
            "remote.download requires async execution".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_in_dest_path() {
        assert!(validate_dest_path("/tmp/../etc/passwd", &["/tmp".into()]).is_err());
    }

    #[tokio::test]
    async fn hostname_without_connect_ip_is_rejected() {
        let url = Url::parse("https://example.com/file").unwrap();
        let err = resolve_and_pin_host(&url, None, false).await.unwrap_err();
        assert!(err.to_string().contains("connect_ip"));
    }

    #[tokio::test]
    async fn uses_server_pinned_connect_ip() {
        let url = Url::parse("https://example.com/file").unwrap();
        let pinned = resolve_and_pin_host(&url, Some("93.184.216.34"), false)
            .await
            .unwrap();
        assert_eq!(pinned.addr.ip().to_string(), "93.184.216.34");
        assert_eq!(pinned.host, "example.com");
    }
}

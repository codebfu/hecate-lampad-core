//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Proxmox helper IPC client used by the agent service.

use super::{
    default_socket_path, encode_frame, new_request_id, read_ipc_token, CaptureResult, IpcRequest,
    IpcResponse, ProxmoxInfoResult, ProxmoxIpcError,
};
#[cfg(unix)]
use super::{map_remote_error, read_frame};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::time::timeout;

pub struct ProxmoxIpcClient {
    socket_path: PathBuf,
    #[cfg_attr(not(unix), allow(dead_code))]
    connect_timeout: Duration,
    #[cfg_attr(not(unix), allow(dead_code))]
    request_timeout: Duration,
}

impl Default for ProxmoxIpcClient {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(60),
        }
    }
}

impl ProxmoxIpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            ..Self::default()
        }
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    pub async fn ping(&self) -> Result<(), ProxmoxIpcError> {
        let _ = self.call("ping", json!({}), false).await?;
        Ok(())
    }

    pub async fn info(&self) -> Result<ProxmoxInfoResult, ProxmoxIpcError> {
        let (response, _) = self.call("info", json!({}), false).await?;
        serde_json::from_value(response.result)
            .map_err(|e| ProxmoxIpcError::InvalidResponse(e.to_string()))
    }

    pub async fn try_info(&self) -> Option<ProxmoxInfoResult> {
        self.info().await.ok()
    }

    pub async fn console_frame(&self, params: Value) -> Result<CaptureResult, ProxmoxIpcError> {
        let (response, bytes) = self.call("console.frame", params, true).await?;
        Ok(CaptureResult {
            meta: response.result,
            bytes,
        })
    }

    pub async fn call_json(&self, method: &str, params: Value) -> Result<Value, ProxmoxIpcError> {
        let (response, _) = self.call(method, params, false).await?;
        Ok(response.result)
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        expect_payload: bool,
    ) -> Result<(IpcResponse, Vec<u8>), ProxmoxIpcError> {
        let auth_token = read_ipc_token(&self.socket_path).ok();
        let request = IpcRequest {
            id: new_request_id(),
            method: method.to_string(),
            params,
            auth_token,
        };
        let frame = encode_frame(&request, &[])
            .map_err(|e| ProxmoxIpcError::Protocol(e.to_string()))?;

        #[cfg(unix)]
        let mut stream = {
            use tokio::net::UnixStream;
            let connect = UnixStream::connect(&self.socket_path);
            match timeout(self.connect_timeout, connect).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => return Err(ProxmoxIpcError::HelperUnavailable),
            }
        };

        #[cfg(not(unix))]
        {
            let _ = (&frame, expect_payload, &request);
            return Err(ProxmoxIpcError::HelperUnavailable);
        }

        #[cfg(unix)]
        {
            exchange(
                &mut stream,
                &request,
                &frame,
                expect_payload,
                self.request_timeout,
            )
            .await
        }
    }
}

#[cfg(unix)]
async fn exchange<S>(
    stream: &mut S,
    request: &IpcRequest,
    frame: &[u8],
    expect_payload: bool,
    request_timeout: Duration,
) -> Result<(IpcResponse, Vec<u8>), ProxmoxIpcError>
where
    S: tokio::io::AsyncReadExt + AsyncWriteExt + Unpin,
{
    let work = async {
        stream.write_all(frame).await?;
        stream.flush().await?;
        let (header, payload) = read_frame(stream)
            .await
            .map_err(|e| ProxmoxIpcError::Protocol(e.to_string()))?;
        let response: IpcResponse = serde_json::from_slice(&header)
            .map_err(|e| ProxmoxIpcError::InvalidResponse(e.to_string()))?;
        if response.id != request.id {
            return Err(ProxmoxIpcError::InvalidResponse("response id mismatch".into()));
        }
        if !response.ok {
            let err = response
                .error
                .as_ref()
                .map(map_remote_error)
                .unwrap_or_else(|| ProxmoxIpcError::Remote("unknown remote error".into()));
            return Err(err);
        }
        if expect_payload && payload.is_empty() {
            return Err(ProxmoxIpcError::InvalidResponse("empty capture payload".into()));
        }
        Ok((response, payload))
    };
    match timeout(request_timeout, work).await {
        Ok(result) => result,
        Err(_) => Err(ProxmoxIpcError::HelperUnavailable),
    }
}

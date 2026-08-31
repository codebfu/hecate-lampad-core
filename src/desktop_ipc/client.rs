//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Desktop helper IPC client used by the agent service.

use hecate_lampad_helper_base::{
    default_socket_path, encode_frame, map_remote_error, new_request_id, read_frame, read_ipc_token,
    CaptureResult, DesktopInfoResult, DesktopIpcError, IpcRequest, IpcResponse,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

pub struct DesktopIpcClient {
    socket_path: PathBuf,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl Default for DesktopIpcClient {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(60),
        }
    }
}

impl DesktopIpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            ..Self::default()
        }
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    pub async fn ping(&self) -> Result<(), DesktopIpcError> {
        let _ = self.call("ping", json!({}), false).await?;
        Ok(())
    }

    pub async fn info(&self) -> Result<DesktopInfoResult, DesktopIpcError> {
        let (response, _) = self.call("info", json!({}), false).await?;
        serde_json::from_value(response.result)
            .map_err(|e| DesktopIpcError::InvalidResponse(e.to_string()))
    }

    pub async fn try_info(&self) -> Option<DesktopInfoResult> {
        self.info().await.ok()
    }

    pub async fn screenshot(&self, params: Value) -> Result<CaptureResult, DesktopIpcError> {
        let (response, bytes) = self.call("screenshot", params, true).await?;
        Ok(CaptureResult {
            meta: response.result,
            bytes,
        })
    }

    pub async fn session_frame(&self, params: Value) -> Result<CaptureResult, DesktopIpcError> {
        let (response, bytes) = self.call("session.frame", params, true).await?;
        Ok(CaptureResult {
            meta: response.result,
            bytes,
        })
    }

    pub async fn clipboard_get_image(&self, params: Value) -> Result<CaptureResult, DesktopIpcError> {
        let (response, bytes) = self.call("clipboard.get", params, true).await?;
        Ok(CaptureResult {
            meta: response.result,
            bytes,
        })
    }

    pub async fn call_json(&self, method: &str, params: Value) -> Result<Value, DesktopIpcError> {
        let (response, _) = self.call(method, params, false).await?;
        Ok(response.result)
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        expect_payload: bool,
    ) -> Result<(IpcResponse, Vec<u8>), DesktopIpcError> {
        let auth_token = read_ipc_token(&self.socket_path).ok();
        let request = IpcRequest {
            id: new_request_id(),
            method: method.to_string(),
            params,
            auth_token,
        };
        let frame = encode_frame(&request, &[])?;

        #[cfg(unix)]
        let mut stream = {
            use tokio::net::UnixStream;
            let connect = UnixStream::connect(&self.socket_path);
            match timeout(self.connect_timeout, connect).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => return Err(DesktopIpcError::HelperUnavailable),
            }
        };

        #[cfg(windows)]
        let mut stream = {
            use tokio::net::windows::named_pipe::ClientOptions;
            let pipe_name = self.socket_path.to_string_lossy().to_string();
            let connect = async {
                // Retry briefly — pipe may not be ready yet.
                let mut last_err = None;
                for _ in 0..10 {
                    match ClientOptions::new().open(&pipe_name) {
                        Ok(client) => return Ok(client),
                        Err(error) => {
                            last_err = Some(error);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "named pipe unavailable")
                }))
            };
            match timeout(self.connect_timeout, connect).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => return Err(DesktopIpcError::HelperUnavailable),
            }
        };

        #[cfg(not(any(unix, windows)))]
        {
            let _ = frame;
            return Err(DesktopIpcError::HelperUnavailable);
        }

        #[cfg(any(unix, windows))]
        {
            exchange(&mut stream, &request, &frame, expect_payload, self.request_timeout).await
        }
    }
}

async fn exchange<S>(
    stream: &mut S,
    request: &IpcRequest,
    frame: &[u8],
    expect_payload: bool,
    request_timeout: Duration,
) -> Result<(IpcResponse, Vec<u8>), DesktopIpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(request_timeout, stream.write_all(frame))
        .await
        .map_err(|_| DesktopIpcError::Protocol("write timeout".into()))??;

    let (header, payload) = timeout(request_timeout, read_frame(stream))
        .await
        .map_err(|_| DesktopIpcError::Protocol("read timeout".into()))??;

    let response: IpcResponse = serde_json::from_slice(&header)
        .map_err(|e| DesktopIpcError::InvalidResponse(e.to_string()))?;
    if response.id != request.id {
        return Err(DesktopIpcError::InvalidResponse(
            "response id mismatch".into(),
        ));
    }
    if !response.ok {
        let error = response.error.unwrap_or(super::IpcErrorBody {
            code: "remote".into(),
            message: "unknown helper error".into(),
        });
        return Err(map_remote_error(&error));
    }
    if expect_payload && payload.is_empty() && matches!(request.method.as_str(), "screenshot" | "session.frame")
    {
        return Err(DesktopIpcError::InvalidResponse(
            "expected image payload".into(),
        ));
    }
    Ok((response, payload))
}

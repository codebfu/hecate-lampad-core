//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Server task signature verification on the agent.

use hecate_protocol::task::TaskExecutionPolicy;
use hecate_protocol::task_signing::build_task_canonical_string;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use uuid::Uuid;

pub fn verify_server_task_sig(
    task_signing_pubkey_b64: &str,
    server_task_sig: &str,
    command_id: Uuid,
    command_name: &str,
    params: &Value,
    execution_policy: &TaskExecutionPolicy,
) -> Result<(), String> {
    verify_server_task_sig_any(
        &[task_signing_pubkey_b64],
        server_task_sig,
        command_id,
        command_name,
        params,
        execution_policy,
    )
}

/// Verify a task signature against any of the provided public keys (dual-key rotation).
pub fn verify_server_task_sig_any(
    task_signing_pubkeys_b64: &[&str],
    server_task_sig: &str,
    command_id: Uuid,
    command_name: &str,
    params: &Value,
    execution_policy: &TaskExecutionPolicy,
) -> Result<(), String> {
    let keys: Vec<&str> = task_signing_pubkeys_b64
        .iter()
        .copied()
        .filter(|k| !k.trim().is_empty())
        .collect();
    if keys.is_empty() {
        return Err("task signing public key is not configured; re-enroll required".into());
    }
    if server_task_sig.trim().is_empty() {
        return Err("missing server task signature".into());
    }

    let params_json = serde_json::to_string(params).unwrap_or_else(|_| "{}".into());
    let policy_json = serde_json::to_string(execution_policy).unwrap_or_else(|_| "{}".into());
    let canonical = build_task_canonical_string(
        &command_id.to_string(),
        command_name,
        &params_json,
        &policy_json,
    );

    let sig_bytes = BASE64
        .decode(server_task_sig)
        .map_err(|_| "invalid server task signature encoding".to_string())?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid server task signature length".to_string())?;
    let signature = Signature::from_bytes(&sig_array);

    let mut last_error = "invalid server task signature".to_string();
    for pubkey in keys {
        match verify_with_key(pubkey, &canonical, &signature) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

pub fn verify_self_update_task_sig(
    task_signing_pubkeys_b64: &[&str],
    server_task_sig: &str,
    machine_id: Uuid,
    kind: &str,
    artifact_path: &str,
    sha256: &str,
    target_version: &str,
) -> Result<(), String> {
    let params = hecate_protocol::task::self_update_sign_params(
        kind,
        artifact_path,
        sha256,
        target_version,
    );
    verify_server_task_sig_any(
        task_signing_pubkeys_b64,
        server_task_sig,
        machine_id,
        "self_update",
        &params,
        &TaskExecutionPolicy::default(),
    )
}

fn verify_with_key(
    task_signing_pubkey_b64: &str,
    canonical: &str,
    signature: &Signature,
) -> Result<(), String> {
    let pk_bytes = BASE64
        .decode(task_signing_pubkey_b64)
        .map_err(|_| "invalid task signing public key encoding".to_string())?;
    let pk_array: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid task signing public key length".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| "invalid task signing public key".to_string())?;
    verifying_key
        .verify(canonical.as_bytes(), signature)
        .map_err(|_| "invalid server task signature".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use hecate_protocol::task_signing::build_task_canonical_string;
    use rand::rngs::OsRng;

    #[test]
    fn verify_accepts_either_current_or_previous_key() {
        let current = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let previous = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let current_pub = BASE64.encode(current.verifying_key().to_bytes());
        let previous_pub = BASE64.encode(previous.verifying_key().to_bytes());
        let command_id = Uuid::from_u128(9);
        let params = serde_json::json!({ "argv": ["/bin/true"] });
        let policy = TaskExecutionPolicy::default();
        let params_json = serde_json::to_string(&params).unwrap();
        let policy_json = serde_json::to_string(&policy).unwrap();
        let canonical = build_task_canonical_string(
            &command_id.to_string(),
            "shell.run",
            &params_json,
            &policy_json,
        );
        let sig = BASE64.encode(previous.sign(canonical.as_bytes()).to_bytes());
        verify_server_task_sig_any(
            &[&current_pub, &previous_pub],
            &sig,
            command_id,
            "shell.run",
            &params,
            &policy,
        )
        .unwrap();
    }
}

//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

pub use hecate_protocol::agent_signing::{
    build_canonical_string, hex_sha256, HEADER_AGENT_ID, HEADER_NONCE, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, SIGNING_VERSION,
};

pub fn generate_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

fn read_seed_nofollow(path: &Path) -> Result<Vec<u8>, SigningError> {
    #[cfg(windows)]
    {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(SigningError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to follow symlink key path {}", path.display()),
            )));
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = opts.open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("agent key not found at {path}: provide --key-path or run enroll without --key-path to create the default key")]
    KeyNotFound { path: PathBuf },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Ed25519 keypair for agent authentication.
#[derive(Clone)]
pub struct AgentKeypair {
    signing_key: SigningKey,
}

impl AgentKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed_bytes(seed: &[u8; 32]) -> Result<Self, SigningError> {
        let signing_key = SigningKey::from_bytes(seed);
        Ok(Self { signing_key })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref();
        let bytes = read_seed_nofollow(path)?;
        if bytes.len() != 32 {
            return Err(SigningError::InvalidKey(format!(
                "expected 32-byte seed at {}",
                path.display()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Self::from_seed_bytes(&seed)
    }

    pub fn generate_at(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref();
        let kp = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.exists() {
            return Err(SigningError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("refusing to overwrite existing key at {}", path.display()),
            )));
        }
        use std::io::Write;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            file.write_all(&kp.signing_key.to_bytes())?;
            file.sync_all()?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            file.write_all(&kp.signing_key.to_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(&kp.signing_key.to_bytes())?;
            file.sync_all()?;
        }
        Ok(kp)
    }

    pub fn regenerate_at(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref();
        let kp = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            file.write_all(&kp.signing_key.to_bytes())?;
            file.sync_all()?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            file.write_all(&kp.signing_key.to_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            file.write_all(&kp.signing_key.to_bytes())?;
            file.sync_all()?;
        }
        Ok(kp)
    }

    /// Load an existing key, or create one at the platform default path when
    /// `--key-path` was not provided and the default file is missing.
    pub fn resolve(
        path: &Path,
        default_path: &Path,
        key_path_explicit: bool,
    ) -> Result<Self, SigningError> {
        if path.exists() {
            return Self::load(path);
        }
        if !key_path_explicit && path == default_path {
            return Self::generate_at(path);
        }
        Err(SigningError::KeyNotFound {
            path: path.to_path_buf(),
        })
    }

    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else {
            Self::generate_at(path)
        }
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign_canonical(&self, canonical: &str) -> String {
        let signature = self.signing_key.sign(canonical.as_bytes());
        BASE64.encode(signature.to_bytes())
    }

    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp_ms: i64,
        nonce: &str,
    ) -> String {
        let canonical = build_canonical_string(method, path, body, timestamp_ms, nonce);
        self.sign_canonical(&canonical)
    }

    pub fn verify_canonical(
        public_key_b64: &str,
        canonical: &str,
        signature_b64: &str,
    ) -> Result<(), SigningError> {
        let pk_bytes = BASE64
            .decode(public_key_b64)
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| SigningError::InvalidKey("public key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;

        let sig_bytes = BASE64
            .decode(signature_b64)
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SigningError::InvalidKey("signature must be 64 bytes".into()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        verifying_key
            .verify(canonical.as_bytes(), &signature)
            .map_err(|_| SigningError::VerificationFailed)
    }
}

/// HTTP headers for a signed agent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequestHeaders {
    pub agent_id: Uuid,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: String,
}

impl SignedRequestHeaders {
    pub fn new(agent_id: Uuid, keypair: &AgentKeypair, method: &str, path: &str, body: &[u8]) -> Self {
        let timestamp_ms = chrono::Utc::now().timestamp_millis();
        let nonce = generate_nonce();
        let signature = keypair.sign_request(method, path, body, timestamp_ms, &nonce);
        Self {
            agent_id,
            timestamp_ms,
            nonce,
            signature,
        }
    }

    pub fn apply_to_request(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header(HEADER_AGENT_ID, self.agent_id.to_string())
            .header(HEADER_TIMESTAMP, self.timestamp_ms.to_string())
            .header(HEADER_NONCE, &self.nonce)
            .header(HEADER_SIGNATURE, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_string_format() {
        let body = br#"{"agent_version":"0.1.0"}"#;
        let canonical = build_canonical_string("GET", "/api/v1/agent/pull", body, 1_700_000_000_000, "deadbeef");
        let expected_hash = hex_sha256(body);
        assert_eq!(
            canonical,
            format!("v1\nGET\n/api/v1/agent/pull\n{expected_hash}\n1700000000000\ndeadbeef")
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = AgentKeypair::generate();
        let body = b"{}";
        let canonical = build_canonical_string("POST", "/api/v1/agent/results", body, 123, "nonce1");
        let sig = kp.sign_canonical(&canonical);
        let pk = kp.public_key_base64();
        AgentKeypair::verify_canonical(&pk, &canonical, &sig).unwrap();
    }

    #[test]
    fn rejects_tampered_body() {
        let kp = AgentKeypair::generate();
        let canonical = build_canonical_string("GET", "/pull", b"{}", 123, "n");
        let sig = kp.sign_canonical(&canonical);
        let pk = kp.public_key_base64();
        let tampered = build_canonical_string("GET", "/pull", b"{\"x\":1}", 123, "n");
        assert!(AgentKeypair::verify_canonical(&pk, &tampered, &sig).is_err());
    }

    #[test]
    fn resolve_generates_default_key_when_not_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let default_path = dir.path().join("agent.key");
        let keypair =
            AgentKeypair::resolve(&default_path, &default_path, false).expect("default key");
        assert!(default_path.exists());
        let loaded = AgentKeypair::load(&default_path).unwrap();
        assert_eq!(
            keypair.public_key_base64(),
            loaded.public_key_base64()
        );
    }

    #[test]
    fn resolve_errors_when_explicit_path_missing() {
        let dir = tempfile::tempdir().unwrap();
        let default_path = dir.path().join("agent.key");
        let custom_path = dir.path().join("custom.key");
        assert!(matches!(
            AgentKeypair::resolve(&custom_path, &default_path, true),
            Err(SigningError::KeyNotFound { .. })
        ));
    }
}

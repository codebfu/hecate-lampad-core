//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Sign a self-update release manifest for GitLab Package Registry publishing.

use std::env;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "sign-release")]
struct Args {
  #[arg(long)]
  os: String,
  #[arg(long)]
  arch: String,
  #[arg(long)]
  version: String,
  #[arg(long)]
  binary: PathBuf,
  #[arg(long)]
  output: PathBuf,
  /// Signature domain: `self_update`, `desktop_update`, or `proxmox_update`.
  #[arg(long, default_value = "self_update")]
  kind: String,
}

#[derive(Debug, Serialize)]
struct ReleaseManifest {
  version: String,
  os: String,
  arch: String,
  sha256: String,
  signature: String,
  filename: String,
}

fn main() -> anyhow::Result<()> {
  let args = Args::parse();
  let signing_key_b64 = env::var("HECATE_RELEASE_SIGNING_KEY_B64")
    .map_err(|_| anyhow::anyhow!("HECATE_RELEASE_SIGNING_KEY_B64 is required"))?;
  let seed = BASE64.decode(signing_key_b64.trim())?;
  let seed: [u8; 32] = seed
    .as_slice()
    .try_into()
    .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
  let signing_key = SigningKey::from_bytes(&seed);

  let kind = args.kind.trim();
  if kind != "self_update" && kind != "desktop_update" && kind != "proxmox_update" {
    anyhow::bail!("--kind must be self_update, desktop_update, or proxmox_update");
  }

  let bytes = fs::read(&args.binary)?;
  let sha256 = hex_sha256(&bytes);
  let canonical = format!(
    "v1\n{kind}\n{}\n{}\n{}",
    args.version, sha256, sha256
  );
  let signature = BASE64.encode(signing_key.sign(canonical.as_bytes()).to_bytes());
  let filename = args
    .binary
    .file_name()
    .and_then(|name| name.to_str())
    .ok_or_else(|| anyhow::anyhow!("binary path must have a filename"))?
    .to_string();

  let manifest = ReleaseManifest {
    version: args.version,
    os: args.os,
    arch: args.arch,
    sha256,
    signature,
    filename,
  };

  if let Some(parent) = args.output.parent() {
    fs::create_dir_all(parent)?;
  }
  fs::write(&args.output, serde_json::to_vec_pretty(&manifest)?)?;
  Ok(())
}

fn hex_sha256(data: &[u8]) -> String {
  let digest = Sha256::digest(data);
  digest.iter().map(|b| format!("{b:02x}")).collect()
}

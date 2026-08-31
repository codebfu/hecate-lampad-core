//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

/// Version embedded in the agent binary (`--version`, heartbeats, update checks).
///
/// Priority:
/// 1. `HECATE_AGENT_VERSION` — set by platform packaging scripts (deb/msi/pkg).
/// 2. Sibling `hecate-lampad/Cargo.toml` — monorepo / path dependency local builds.
/// 3. This crate's `CARGO_PKG_VERSION` — standalone core builds and tests.
fn main() {
    let version = resolve_agent_version();
    println!("cargo:rustc-env=HECATE_AGENT_VERSION={version}");
    println!("cargo:rerun-if-env-changed=HECATE_AGENT_VERSION");
    println!("cargo:rerun-if-changed=build.rs");
}

fn resolve_agent_version() -> String {
    if let Ok(version) = std::env::var("HECATE_AGENT_VERSION") {
        if !version.is_empty() {
            return version;
        }
    }

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"),
    );
    for candidate in consumer_cargo_toml_candidates(&manifest_dir) {
        if let Some(version) = read_package_version(&candidate) {
            println!(
                "cargo:warning=HECATE_AGENT_VERSION not set; using {version} from {}",
                candidate.display()
            );
            return version;
        }
    }

    std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION must be set")
}

fn consumer_cargo_toml_candidates(manifest_dir: &Path) -> [PathBuf; 2] {
    [
        manifest_dir.join("../hecate-lampad/Cargo.toml"),
        manifest_dir.join("../../hecate-lampad/Cargo.toml"),
    ]
}

fn read_package_version(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("version = ") {
            continue;
        }
        let start = line.find('"')? + 1;
        let end = line.rfind('"')?;
        if end <= start {
            continue;
        }
        return Some(line[start..end].to_string());
    }
    None
}

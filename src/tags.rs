//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Automatic machine tag collection for agent enrollment.

use hecate_protocol::machine_tags::{validate_custom_tags, validate_machine_tags, MachineTagError};
use std::env::consts::{ARCH, OS};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::Command;

/// Collects default namespaced tags from the local machine environment.
pub fn collect_default_tags() -> Vec<String> {
    let mut tags = vec![
        format!("os:{}", normalize(OS)),
        format!("arch:{}", normalize(ARCH)),
    ];
    tags.extend(detect_distro_tag());
    tags.extend(detect_virt_tag());
    tags.extend(detect_hypervisor_tag());
    tags.extend(detect_init_tag());
    dedupe_sort(tags)
}

/// Merges auto-detected tags with validated custom tags from agent config or CLI.
pub fn collect_agent_tags(config_tags: &[String]) -> Result<Vec<String>, MachineTagError> {
    let auto = collect_default_tags();
    if config_tags.is_empty() {
        return Ok(auto);
    }
    let custom = validate_custom_tags(config_tags)?;
    let mut merged = auto;
    merged.extend(custom);
    let merged = dedupe_sort(merged);
    validate_machine_tags(&merged)
}

fn normalize(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', "-")
}

fn dedupe_sort(mut tags: Vec<String>) -> Vec<String> {
    tags.sort();
    tags.dedup();
    tags
}

#[cfg(target_os = "linux")]
fn detect_distro_tag() -> Vec<String> {
    read_os_release_id("/etc/os-release")
        .map(|id| vec![format!("distro:{}", normalize(&id))])
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn detect_distro_tag() -> Vec<String> {
    vec!["distro:macos".into()]
}

#[cfg(target_os = "windows")]
fn detect_distro_tag() -> Vec<String> {
    vec!["distro:windows".into()]
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn detect_distro_tag() -> Vec<String> {
    vec![]
}

#[cfg(target_os = "linux")]
fn detect_virt_tag() -> Vec<String> {
    match Command::new("systemd-detect-virt").output() {
        Ok(output) if output.status.success() => {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            map_virt(&value)
        }
        _ => vec!["virt:physical".into()],
    }
}

#[cfg(target_os = "macos")]
fn detect_virt_tag() -> Vec<String> {
    let under_hypervisor = Command::new("sysctl")
        .args(["-n", "kern.hv_vmm_present"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "1")
        .unwrap_or(false);

    if under_hypervisor {
        vec!["virt:vm".into()]
    } else {
        vec!["virt:physical".into()]
    }
}

#[cfg(target_os = "windows")]
fn detect_virt_tag() -> Vec<String> {
    if let Ok(output) = Command::new("wmic")
        .args(["computersystem", "get", "hypervisorpresent"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.to_ascii_lowercase().contains("true") {
            return vec!["virt:vm".into()];
        }
    }
    vec!["virt:physical".into()]
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn detect_virt_tag() -> Vec<String> {
    vec![]
}

#[cfg(target_os = "linux")]
fn detect_hypervisor_tag() -> Vec<String> {
    detect_hypervisor_name()
        .map(|name| vec![format!("hypervisor:{}", normalize(&name))])
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn detect_hypervisor_tag() -> Vec<String> {
    vec![]
}

/// Detects the local hypervisor product when this host runs one (Linux only).
///
/// Priority: Proxmox VE → Xen dom0 → KVM (`/dev/kvm`).
#[cfg(target_os = "linux")]
fn detect_hypervisor_name() -> Option<String> {
    if Path::new("/etc/pve").is_dir() || Path::new("/usr/bin/pveversion").exists() {
        return Some("proxmox".into());
    }
    if is_xen_dom0() {
        return Some("xen".into());
    }
    if Path::new("/dev/kvm").exists() {
        return Some("kvm".into());
    }
    None
}

#[cfg(target_os = "linux")]
fn is_xen_dom0() -> bool {
    std::fs::read_to_string("/proc/xen/capabilities")
        .map(|content| xen_capabilities_indicate_dom0(&content))
        .unwrap_or(false)
}

#[cfg(any(test, target_os = "linux"))]
fn xen_capabilities_indicate_dom0(content: &str) -> bool {
    content.split_whitespace().any(|token| token == "control_d")
}

#[cfg(target_os = "linux")]
fn detect_init_tag() -> Vec<String> {
    if Path::new("/run/systemd/system").exists() {
        vec!["init:systemd".into()]
    } else {
        vec![]
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_init_tag() -> Vec<String> {
    vec![]
}

#[cfg(any(test, target_os = "linux"))]
fn read_os_release_id(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_os_release_id(&content)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_os_release_id(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(id) = line.strip_prefix("ID=") {
            let id = id.trim().trim_matches('"').to_string();
            if !id.is_empty() {
                return Some(id);
            }
        }
    }
    None
}

#[cfg(any(test, target_os = "linux"))]
fn map_virt(raw: &str) -> Vec<String> {
    match raw {
        "none" | "" => vec!["virt:physical".into()],
        "docker" | "lxc" | "openvz" | "podman" | "container" | "wsl" => {
            vec!["virt:container".into()]
        }
        _ => vec!["virt:vm".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_and_replaces_underscores() {
        assert_eq!(normalize("X86_64"), "x86-64");
        assert_eq!(normalize("Linux"), "linux");
    }

    #[test]
    fn dedupe_sort_removes_duplicates_and_sorts() {
        assert_eq!(
            dedupe_sort(vec!["b:2".into(), "a:1".into(), "b:2".into()]),
            vec!["a:1", "b:2"]
        );
    }

    #[test]
    fn parse_os_release_id_reads_id_field() {
        let content = r#"
NAME="Ubuntu"
VERSION="24.04 LTS"
ID=ubuntu
ID_LIKE=debian
"#;
        assert_eq!(parse_os_release_id(content).as_deref(), Some("ubuntu"));
    }

    #[test]
    fn parse_os_release_id_handles_quoted_values() {
        let content = r#"ID="debian""#;
        assert_eq!(parse_os_release_id(content).as_deref(), Some("debian"));
    }

    #[test]
    fn map_virt_classifies_container_environments() {
        assert_eq!(map_virt("docker"), vec!["virt:container"]);
        assert_eq!(map_virt("wsl"), vec!["virt:container"]);
    }

    #[test]
    fn map_virt_classifies_vm_environments() {
        assert_eq!(map_virt("kvm"), vec!["virt:vm"]);
        assert_eq!(map_virt("qemu"), vec!["virt:vm"]);
    }

    #[test]
    fn map_virt_classifies_physical_hosts() {
        assert_eq!(map_virt("none"), vec!["virt:physical"]);
    }

    #[test]
    fn xen_capabilities_detect_dom0() {
        assert!(xen_capabilities_indicate_dom0("control_d"));
        assert!(xen_capabilities_indicate_dom0("control_d xen_hvm"));
        assert!(!xen_capabilities_indicate_dom0(""));
        assert!(!xen_capabilities_indicate_dom0("hvm"));
    }

    #[test]
    fn collect_agent_tags_rejects_hypervisor_namespace() {
        assert!(collect_agent_tags(&["hypervisor:custom".into()]).is_err());
    }

    #[test]
    fn collect_agent_tags_merges_custom_tags() {
        let tags = collect_agent_tags(&["env:prod".into()]).expect("valid");
        assert!(tags.iter().any(|tag| tag == "env:prod"));
        assert!(tags.iter().any(|tag| tag.starts_with("os:")));
    }

    #[test]
    fn collect_agent_tags_rejects_reserved_namespace() {
        assert!(collect_agent_tags(&["os:custom".into()]).is_err());
    }

    #[test]
    fn collect_default_tags_includes_os_and_arch() {
        let tags = collect_default_tags();
        assert!(tags.iter().any(|tag| tag.starts_with("os:")));
        assert!(tags.iter().any(|tag| tag.starts_with("arch:")));
    }

    #[test]
    fn read_os_release_id_from_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("os-release");
        std::fs::write(&path, "ID=fedora\n").expect("write");
        let id = read_os_release_id(path.to_str().expect("path"));
        assert_eq!(id.as_deref(), Some("fedora"));
    }
}

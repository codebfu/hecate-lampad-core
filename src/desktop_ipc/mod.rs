//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Local IPC between hecate-lampad (system service) and helpers.

pub use hecate_lampad_helper_base::*;

pub mod client;

/// Build gui/display tags from helper presence and optional live info.
pub fn collect_gui_tags(info: Option<&DesktopInfoResult>) -> Vec<String> {
    if !helper_package_installed() {
        return Vec::new();
    }
    match info {
        Some(info) => {
            let mut tags = vec!["gui:ready".into()];
            let backend = info.display_backend.to_ascii_lowercase();
            let display = match backend.as_str() {
                "x11" => "display:x11",
                "wayland" => "display:wayland",
                "windows" => "display:windows",
                "macos" | "quartz" | "cocoa" => "display:macos",
                other if !other.is_empty() => {
                    tags.push(format!("display:{}", other.replace('_', "-")));
                    return tags;
                }
                _ => "display:unknown",
            };
            tags.push(display.into());
            tags
        }
        None => vec!["gui:none".into()],
    }
}

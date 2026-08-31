#!/usr/bin/env bash
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <completions-dir> <output-dir>" >&2
  exit 1
fi

SOURCE_DIR="$1"
OUTPUT_DIR="$2"

mkdir -p \
  "${OUTPUT_DIR}/bash" \
  "${OUTPUT_DIR}/zsh" \
  "${OUTPUT_DIR}/fish" \
  "${OUTPUT_DIR}/powershell"

install -m 644 "${SOURCE_DIR}/bash/hecate-lampad.bash" "${OUTPUT_DIR}/bash/hecate-lampad"
install -m 644 "${SOURCE_DIR}/zsh/_hecate-lampad" "${OUTPUT_DIR}/zsh/_hecate-lampad"
install -m 644 "${SOURCE_DIR}/fish/hecate-lampad.fish" "${OUTPUT_DIR}/fish/hecate-lampad.fish"
install -m 644 "${SOURCE_DIR}/powershell/_hecate-lampad.ps1" "${OUTPUT_DIR}/powershell/hecate-lampad.ps1"

echo "Staged shell completions from ${SOURCE_DIR} into ${OUTPUT_DIR}"

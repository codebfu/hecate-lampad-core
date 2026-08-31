#!/usr/bin/env bash
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-${VERSION:-}}"

if [ -z "${VERSION}" ]; then
  echo "VERSION is required (argument or environment variable)" >&2
  exit 1
fi

sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" "${ROOT}/Cargo.toml"

echo "Applied version ${VERSION}"

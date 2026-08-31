#!/bin/sh
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

# Install or validate the hecate-lampad sudoers fragment (Linux/macOS).
set -e

SRC="${1:-}"
DEST="${2:-/etc/sudoers.d/hecate-lampad}"

if [ -z "${SRC}" ] || [ ! -f "${SRC}" ]; then
  echo "Usage: install-elevation-policy.sh <sudoers-source-file> [dest-path]" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "install-elevation-policy.sh must run as root" >&2
  exit 1
fi

# macOS/BSD use group "wheel"; Linux typically uses "root".
ROOT_GROUP=root
case "$(uname -s)" in
  Darwin|FreeBSD|OpenBSD|NetBSD) ROOT_GROUP=wheel ;;
esac

install -d -m 755 /etc/sudoers.d
install -o root -g "${ROOT_GROUP}" -m 440 "${SRC}" "${DEST}"

if command -v visudo >/dev/null 2>&1; then
  visudo -c -f "${DEST}"
fi

#!/usr/bin/env bash
set -euo pipefail

# Keep the registry and namespace explicit so Docker and Renovate resolve the
# same official image instead of relying on each tool's default registry.
# renovate: datasource=docker depName=docker.io/library/busybox
backup_image="${TAILSTATE_BACKUP_IMAGE:-docker.io/library/busybox:1.38@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616}"
printf '%s\n' "$backup_image"

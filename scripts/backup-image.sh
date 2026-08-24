#!/usr/bin/env bash
set -euo pipefail

# Keep the registry and namespace explicit so Docker and Renovate resolve the
# same official image instead of relying on each tool's default registry.
# renovate: datasource=docker depName=docker.io/library/busybox
backup_image="${TAILSTATE_BACKUP_IMAGE:-docker.io/library/busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0}"
printf '%s\n' "$backup_image"

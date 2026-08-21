#!/usr/bin/env bash
set -euo pipefail

# renovate: datasource=docker depName=busybox
backup_image="${TAILSTATE_BACKUP_IMAGE:-busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0}"
printf '%s\n' "$backup_image"

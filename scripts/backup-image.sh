#!/usr/bin/env bash
set -euo pipefail

# Keep the registry and namespace explicit so Docker and Renovate resolve the
# same official image instead of relying on each tool's default registry.
# renovate: datasource=docker depName=docker.io/library/busybox
backup_image="${TAILSTATE_BACKUP_IMAGE:-docker.io/library/busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e}"
printf '%s\n' "$backup_image"

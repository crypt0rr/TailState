#!/usr/bin/env bash
set -euo pipefail

# Keep the registry and namespace explicit so Docker and Renovate resolve the
# same official image instead of relying on each tool's default registry.
# renovate: datasource=docker depName=docker.io/library/busybox
backup_image="${TAILSTATE_BACKUP_IMAGE:-docker.io/library/busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec}"
printf '%s\n' "$backup_image"

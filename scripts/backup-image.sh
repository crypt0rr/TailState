#!/usr/bin/env bash
set -euo pipefail

# renovate: datasource=docker depName=alpine
backup_image="${TAILSTATE_BACKUP_IMAGE:-alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b}"
printf '%s\n' "$backup_image"

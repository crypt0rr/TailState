#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

go_mod_version="$(awk '$1 == "go" { print $2; exit }' "$repo_root/go.mod")"
if [[ -z "$go_mod_version" ]]; then
    echo "unable to find the Go version in go.mod" >&2
    exit 1
fi

builder_ref="$(awk '$1 == "FROM" { for (i = 2; i <= NF; i++) if ($i ~ /^golang:/) { print $i; exit } }' "$repo_root/Dockerfile")"
if [[ -z "$builder_ref" ]]; then
    echo "unable to find the Go builder image in Dockerfile" >&2
    exit 1
fi

builder_version="${builder_ref#golang:}"
builder_version="${builder_version%%-*}"
if [[ -z "$builder_version" ]]; then
    echo "unable to determine the Go builder version from Dockerfile" >&2
    exit 1
fi

if [[ "$go_mod_version" != "$builder_version" ]]; then
    echo "Go toolchain mismatch: go.mod declares ${go_mod_version}, Dockerfile builds with ${builder_version}" >&2
    exit 1
fi

# Every ARG GO_VERSION default feeds the org.opencontainers.image.build.go
# label and must name the compiler that actually built the binary.
while IFS= read -r arg_version; do
    if [[ "$arg_version" != "$go_mod_version" ]]; then
        echo "Dockerfile ARG GO_VERSION=${arg_version} does not match go.mod ${go_mod_version}" >&2
        exit 1
    fi
done < <(awk -F= '$1 == "ARG GO_VERSION" { print $2 }' "$repo_root/Dockerfile")

# Hand-written base-image labels drift whenever Renovate bumps a digest pin.
# The runtime base is scratch and the builder digest lives in provenance, so
# reject any base.* label rather than trying to keep one in sync.
if grep -v '^[[:space:]]*#' "$repo_root/Dockerfile" | grep -q 'org\.opencontainers\.image\.base\.'; then
    echo "Dockerfile must not hard-code org.opencontainers.image.base.* labels; the builder digest is recorded in provenance" >&2
    exit 1
fi

printf 'Go toolchain aligned: go%s (CI and Docker builder %s)\n' \
    "$go_mod_version" "$builder_ref"

#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

go_mod_version="$(awk '$1 == "go" { print $2; exit }' "$repo_root/go.mod")"
if [[ -z "$go_mod_version" ]]; then
    echo "unable to find the Go version in go.mod" >&2
    exit 1
fi

builder_ref="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' "$repo_root/Dockerfile")"
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

printf 'Go toolchain aligned: go%s (CI and Docker builder %s)\n' \
    "$go_mod_version" "$builder_ref"

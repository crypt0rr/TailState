#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: container-backup-restore-smoke.sh IMAGE [PORT]}"
port="${2:-18083}"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
container_name="tailstate-backup-smoke-${run_id}"
key_file="$(mktemp)"
host_uid="$(id -u)"
host_gid="$(id -g)"
backup_dir="$(mktemp -d)"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
compose_file="$repo_dir/compose.yaml"
archive=""
backup_image="$(bash "$repo_dir/scripts/backup-image.sh")"

cleanup() {
    TAILSTATE_IMAGE="$image" \
        TAILSTATE_MASTER_KEY_FILE="$key_file" \
        TAILSTATE_CONTAINER_NAME="$container_name" \
        TAILSTATE_PORT="$port" \
        COMPOSE_PROJECT_NAME="tailstate-backup-smoke-${run_id}" \
        docker compose -f "$compose_file" down -v >/dev/null 2>&1 || true
    rm -rf "$backup_dir"
    if [[ -e "$key_file" ]]; then
        docker run --rm --user 0 \
            --volume "$key_file:/run/secrets/cleanup-key" \
            "$backup_image" \
            sh -ec 'chown "$1:$2" /run/secrets/cleanup-key && chmod 0600 /run/secrets/cleanup-key' \
            -- "$host_uid" "$host_gid" >/dev/null 2>&1 || true
    fi
    rm -f "$key_file"
}
wait_health() {
    local message="$1"
    for _ in $(seq 1 30); do
        if curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${port}/healthz" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    docker compose -f "$compose_file" logs >&2 || true
    echo "$message" >&2
    return 1
}
trap cleanup EXIT

openssl rand -base64 32 >"$key_file"
if ! docker image inspect "$backup_image" >/dev/null 2>&1; then
    docker pull "$backup_image" >/dev/null
fi
# Match the documented Compose secret ownership and mode exactly. The pinned
# sidecar performs the host-file ownership change without requiring host tools.
docker run --rm --user 0 \
    --volume "$key_file:/run/secrets/tailstate_master_key" \
    "$backup_image" \
    sh -ec 'chown 10001:10001 /run/secrets/tailstate_master_key && chmod 0400 /run/secrets/tailstate_master_key'
export TAILSTATE_IMAGE="$image"
export TAILSTATE_MASTER_KEY_FILE="$key_file"
export TAILSTATE_CONTAINER_NAME="$container_name"
export TAILSTATE_PORT="$port"
export COMPOSE_PROJECT_NAME="tailstate-backup-smoke-${run_id}"

docker compose -f "$compose_file" up -d --no-build >/dev/null
wait_health "TailState health endpoint did not become ready before backup"

"$repo_dir/scripts/backup.sh" "$backup_dir"
archive="$(find "$backup_dir" -maxdepth 1 -type f -name 'tailstate-data-*.tar.gz' -print -quit)"
if [[ -z "$archive" ]]; then
    echo "backup helper did not create an archive" >&2
    exit 1
fi
"$repo_dir/scripts/restore.sh" "$archive" --yes
wait_health "TailState health endpoint did not become ready after restore"

unsafe_dir="$(mktemp -d)"
ln -s /data "$unsafe_dir/escape"
unsafe_archive="$backup_dir/unsafe-special-file.tar.gz"
tar czf "$unsafe_archive" -C "$unsafe_dir" escape
rm -rf "$unsafe_dir"
if "$repo_dir/scripts/restore.sh" "$unsafe_archive" --yes; then
    echo "restore helper accepted an unsafe symlink archive" >&2
    exit 1
fi
wait_health "TailState became unavailable after rejecting an unsafe archive"
echo "TailState backup/restore smoke test passed"

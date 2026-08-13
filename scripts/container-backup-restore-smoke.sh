#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: container-backup-restore-smoke.sh IMAGE [PORT]}"
port="${2:-18083}"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
container_name="tailstate-backup-smoke-${run_id}"
key_file="$(mktemp)"
backup_dir="$(mktemp -d)"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
compose_file="$repo_dir/compose.yaml"
archive=""

cleanup() {
    TAILSTATE_IMAGE="$image" \
        TAILSTATE_MASTER_KEY_FILE="$key_file" \
        TAILSTATE_CONTAINER_NAME="$container_name" \
        TAILSTATE_PORT="$port" \
        COMPOSE_PROJECT_NAME="tailstate-backup-smoke-${run_id}" \
        docker compose -f "$compose_file" down -v >/dev/null 2>&1 || true
    rm -rf "$backup_dir"
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

chmod 644 "$key_file"
openssl rand -base64 32 >"$key_file"
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
echo "TailState backup/restore smoke test passed"

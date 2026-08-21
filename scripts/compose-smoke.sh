#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: compose-smoke.sh IMAGE [PORT]}"
port="${2:-18083}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_dir="$(cd -- "$script_dir/.." && pwd -P)"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
project="tailstate-compose-smoke-${run_id}"
container_name="tailstate-compose-${run_id}"
key_file="$(mktemp)"
host_uid="$(id -u)"
host_gid="$(id -g)"

# The function is invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317
cleanup() {
    COMPOSE_PROJECT_NAME="$project" \
        TAILSTATE_IMAGE="$image" \
        TAILSTATE_CONTAINER_NAME="$container_name" \
        TAILSTATE_PORT="$port" \
        TAILSTATE_MASTER_KEY_FILE="$key_file" \
        docker compose -f "$repo_dir/compose.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
    if [[ -n "${backup_image:-}" && -e "$key_file" ]]; then
        docker run --rm --user 0 \
            --volume "$key_file:/run/secrets/cleanup-key" \
            "$backup_image" \
            sh -ec 'chown "$1:$2" /run/secrets/cleanup-key && chmod 0600 /run/secrets/cleanup-key' \
            -- "$host_uid" "$host_gid" >/dev/null 2>&1 || true
    fi
    rm -f "$key_file"
}
trap cleanup EXIT

openssl rand -base64 32 >"$key_file"
backup_image="$(bash "$script_dir/backup-image.sh")"
if ! docker image inspect "$backup_image" >/dev/null 2>&1; then
    docker pull "$backup_image" >/dev/null
fi
# Exercise the same ownership and mode documented in README.md. The helper
# performs this change inside the pinned sidecar rather than requiring the CI
# host to run chown as root.
docker run --rm --user 0 \
    --volume "$key_file:/run/secrets/master-key" \
    "$backup_image" \
    sh -ec 'chown 10001:10001 /run/secrets/master-key && chmod 0400 /run/secrets/master-key'

export COMPOSE_PROJECT_NAME="$project"
export TAILSTATE_IMAGE="$image"
export TAILSTATE_CONTAINER_NAME="$container_name"
export TAILSTATE_PORT="$port"
export TAILSTATE_BIND_ADDRESS=127.0.0.1
export TAILSTATE_MASTER_KEY_FILE="$key_file"
export TAILSTATE_COOKIE_SECURE=false
export TAILSTATE_METRICS_TOKEN=

# This is the documented Compose startup path, with only the image and
# temporary secret overridden for an isolated test project.
docker compose -f "$repo_dir/compose.yaml" up -d

for _ in $(seq 1 30); do
    if curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${port}/healthz" >/dev/null; then
        metrics_status="$(curl --silent --show-error --max-time 2 --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${port}/metrics")"
        if [[ "$metrics_status" != "401" ]]; then
            docker compose -f "$repo_dir/compose.yaml" logs >&2 || true
            echo "TailState metrics endpoint unexpectedly returned HTTP ${metrics_status} without a token" >&2
            exit 1
        fi
        configured_user="$(docker inspect --format '{{.Config.User}}' "$container_name")"
        if [[ "$configured_user" != "10001:10001" ]]; then
            echo "Compose container runs as ${configured_user}, expected 10001:10001" >&2
            exit 1
        fi
        exit 0
    fi
    sleep 1
done

docker compose -f "$repo_dir/compose.yaml" logs >&2 || true
echo "TailState health endpoint did not become ready on port ${port}" >&2
exit 1

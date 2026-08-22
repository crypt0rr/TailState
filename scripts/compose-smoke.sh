#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: compose-smoke.sh IMAGE [PORT]}"
port="${2:-18083}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_dir="$(cd -- "$script_dir/.." && pwd -P)"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
project="tailstate-compose-smoke-${run_id}"
container_name="tailstate-compose-${run_id}"
project_dir="$(mktemp -d)"
key_file="$project_dir/secrets/tailstate_master_key"

# The function is invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317
cleanup() {
    if [[ -n "${project_dir:-}" && -f "$project_dir/compose.yaml" ]]; then
        COMPOSE_PROJECT_NAME="$project" \
            TAILSTATE_IMAGE="$image" \
            TAILSTATE_CONTAINER_NAME="$container_name" \
            TAILSTATE_PORT="$port" \
            TAILSTATE_BIND_ADDRESS=127.0.0.1 \
            TAILSTATE_MASTER_KEY_FILE="$key_file" \
            docker compose -f "$project_dir/compose.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    rm -rf "$project_dir"
}
trap cleanup EXIT

backup_image="$(bash "$script_dir/backup-image.sh")"
if ! docker image inspect "$backup_image" >/dev/null 2>&1; then
    docker pull "$backup_image" >/dev/null
fi

# Run the documented setup commands in an isolated project directory. Keeping
# the copy and generated secret out of the checkout prevents the smoke test
# from changing a developer's .env or secrets directory.
cp -R "$repo_dir/cmd" "$repo_dir/internal" "$project_dir/"
cp "$repo_dir/.env.example" "$repo_dir/compose.yaml" "$repo_dir/Dockerfile" "$repo_dir/go.mod" "$repo_dir/go.sum" "$repo_dir/.dockerignore" "$project_dir/"
cd "$project_dir"
cp .env.example .env
mkdir -p secrets
openssl rand -base64 32 > secrets/tailstate_master_key
chmod 600 .env
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo chown 10001:10001 secrets/tailstate_master_key
    sudo chmod 400 secrets/tailstate_master_key
else
    # Local/rootless environments often do not provide passwordless sudo. Use
    # the same pinned sidecar as backup/restore to exercise the final mode and
    # ownership without weakening the documented production instructions.
    docker run --rm --user 0 \
        --volume "$key_file:/run/secrets/master-key" \
        "$backup_image" \
        sh -ec 'chown 10001:10001 /run/secrets/master-key && chmod 0400 /run/secrets/master-key'
fi
if [[ "$(stat -c '%a' .env)" != "600" ]]; then
    echo "documented .env permissions were not applied" >&2
    exit 1
fi
if [[ "$(stat -c '%u:%g:%a' secrets/tailstate_master_key)" != "10001:10001:400" ]]; then
    echo "documented master-key ownership or permissions were not applied" >&2
    exit 1
fi

export COMPOSE_PROJECT_NAME="$project"
export TAILSTATE_IMAGE="$image"
export TAILSTATE_CONTAINER_NAME="$container_name"
export TAILSTATE_PORT="$port"
export TAILSTATE_BIND_ADDRESS=127.0.0.1
export TAILSTATE_COOKIE_SECURE=false
export TAILSTATE_METRICS_TOKEN=

# This is the documented Compose startup command, with only the image and
# temporary project variables overridden for an isolated test project.
docker compose up -d

for _ in $(seq 1 30); do
    if curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${port}/healthz" >/dev/null; then
        metrics_status="$(curl --silent --show-error --max-time 2 --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${port}/metrics")"
        if [[ "$metrics_status" != "401" ]]; then
            docker compose logs >&2 || true
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

docker compose logs >&2 || true
echo "TailState health endpoint did not become ready on port ${port}" >&2
exit 1

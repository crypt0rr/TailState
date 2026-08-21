#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: container-smoke.sh IMAGE [PORT]}"
port="${2:-18080}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
backup_image="$(bash "$script_dir/backup-image.sh")"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
container_name="tailstate-smoke-${run_id}"
volume_name="tailstate-smoke-${run_id}"
key_file="$(mktemp)"
host_uid="$(id -u)"
host_gid="$(id -g)"

# The function is invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317
cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    docker volume rm "$volume_name" >/dev/null 2>&1 || true
    if [[ -e "$key_file" ]]; then
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
# Match the documented Compose secret ownership and mode. The helper runs as
# root only inside the pinned, separately scanned sidecar; no host-level chown
# capability is required from the test runner.
if ! docker image inspect "$backup_image" >/dev/null 2>&1; then
    docker pull "$backup_image" >/dev/null
fi
docker run --rm --user 0 \
    --volume "$key_file:/run/secrets/master-key" \
    "$backup_image" \
    sh -ec 'chown 10001:10001 /run/secrets/master-key && chmod 0400 /run/secrets/master-key'
docker volume create "$volume_name" >/dev/null

docker run -d \
    --name "$container_name" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:noexec,nosuid,size=16m \
    --publish "${port}:8080" \
    --env TAILSTATE_MASTER_KEY_FILE=/run/secrets/master-key \
    --env TAILSTATE_TS_API_URL=http://127.0.0.1:9/api/v2 \
    --env TAILSTATE_TS_OAUTH_URL=http://127.0.0.1:9/api/v2/oauth/token \
    --volume "$key_file:/run/secrets/master-key:ro" \
    --volume "$volume_name:/data" \
    "$image" >/dev/null

for _ in $(seq 1 30); do
    if curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${port}/healthz" >/dev/null; then
        metrics_status="$(curl --silent --show-error --max-time 2 --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${port}/metrics")"
        if [[ "$metrics_status" != "401" ]]; then
            docker logs "$container_name" >&2 || true
            echo "TailState metrics endpoint unexpectedly returned HTTP ${metrics_status} without a token" >&2
            exit 1
        fi
        exit 0
    fi
    sleep 1
done

docker logs "$container_name" >&2 || true
echo "TailState health endpoint did not become ready on port ${port}" >&2
exit 1

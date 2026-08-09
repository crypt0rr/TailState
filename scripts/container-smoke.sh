#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: container-smoke.sh IMAGE [PORT]}"
port="${2:-18080}"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
container_name="tailstate-smoke-${run_id}"
volume_name="tailstate-smoke-${run_id}"
key_file="$(mktemp)"

cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    docker volume rm "$volume_name" >/dev/null 2>&1 || true
    rm -f "$key_file"
}
trap cleanup EXIT

chmod 644 "$key_file"
openssl rand -base64 32 >"$key_file"
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
        exit 0
    fi
    sleep 1
done

docker logs "$container_name" >&2 || true
echo "TailState health endpoint did not become ready on port ${port}" >&2
exit 1

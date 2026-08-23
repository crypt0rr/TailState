#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: proxy-smoke.sh IMAGE [PORT]}"
port="${2:-18084}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_dir="$(cd -- "$script_dir/.." && pwd -P)"
backup_image="${TAILSTATE_BACKUP_IMAGE:-$(bash "$script_dir/backup-image.sh")}"
proxy_image="$(awk '/image: caddy:2\.11-alpine@/ {print $2; exit}' "$repo_dir/compose.remote.yaml")"
run_id="${GITHUB_RUN_ID:-local}-${BASHPID}"
network="tailstate-proxy-smoke-${run_id}"
tailstate_name="tailstate-proxy-${run_id}"
caddy_name="tailstate-caddy-${run_id}"
data_volume="tailstate-proxy-data-${run_id}"
key_file="$(mktemp)"
caddyfile="$(mktemp)"

cleanup() {
	set +e
	docker rm -f "$caddy_name" "$tailstate_name" >/dev/null 2>&1
	docker volume rm "$data_volume" >/dev/null 2>&1
	docker network rm "$network" >/dev/null 2>&1
	if [[ -e "$key_file" ]]; then
		docker run --rm --user 0 \
			--volume "$key_file:/run/secrets/cleanup-key" \
			"$backup_image" \
			sh -ec 'chown "$1:$2" /run/secrets/cleanup-key && chmod 0600 /run/secrets/cleanup-key' \
			-- "$(id -u)" "$(id -g)" >/dev/null 2>&1
	fi
	rm -f "$key_file" "$caddyfile"
}
trap cleanup EXIT

if ! docker image inspect "$backup_image" >/dev/null 2>&1; then
	docker pull "$backup_image" >/dev/null
fi
docker pull "$proxy_image" >/dev/null

openssl rand -base64 32 >"$key_file"
docker run --rm --user 0 \
	--volume "$key_file:/run/secrets/master-key" \
	"$backup_image" \
	sh -ec 'chown 10001:10001 /run/secrets/master-key && chmod 0400 /run/secrets/master-key'

cat >"$caddyfile" <<'EOF'
https://localhost:8443 {
	tls internal
	reverse_proxy tailstate:8080
}
EOF

docker network create --subnet 172.30.0.0/24 "$network" >/dev/null
docker run -d \
	--name "$tailstate_name" \
	--network "$network" \
	--network-alias tailstate \
	--ip 172.30.0.3 \
	--read-only \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	--tmpfs /tmp:noexec,nosuid,size=16m \
	--env TAILSTATE_MASTER_KEY_FILE=/run/secrets/master-key \
	--env TAILSTATE_COOKIE_SECURE=true \
	--env TAILSTATE_TRUSTED_PROXIES=172.30.0.2/32 \
	--env TAILSTATE_TS_API_URL=http://127.0.0.1:9/api/v2 \
	--env TAILSTATE_TS_OAUTH_URL=http://127.0.0.1:9/api/v2/oauth/token \
	--volume "$key_file:/run/secrets/master-key:ro" \
	--volume "$data_volume:/data" \
	"$image" >/dev/null

docker run -d \
	--name "$caddy_name" \
	--network "$network" \
	--ip 172.30.0.2 \
	--publish "${port}:8443" \
	--volume "$caddyfile:/etc/caddy/Caddyfile:ro" \
	"$proxy_image" >/dev/null

for _ in $(seq 1 45); do
	if curl --insecure --fail --silent --show-error --max-time 2 "https://localhost:${port}/healthz" >/dev/null 2>&1; then
		break
	fi
	sleep 1
done

if ! curl --insecure --fail --silent --show-error --max-time 2 "https://localhost:${port}/healthz" >/dev/null; then
	docker logs "$tailstate_name" >&2 || true
	docker logs "$caddy_name" >&2 || true
	echo "TailState HTTPS proxy did not become ready on port ${port}" >&2
	exit 1
fi

setup_token="$(docker logs "$tailstate_name" 2>&1 | sed -n 's/.*"setup_token":"\([^"]*\)".*/\1/p' | tail -n 1)"
if [[ -z "$setup_token" ]]; then
	docker logs "$tailstate_name" >&2 || true
	echo "TailState setup token was not found in container logs" >&2
	exit 1
fi

status="$(curl --insecure --silent --show-error --max-time 5 \
	--output /dev/null --write-out '%{http_code}' \
	-H "Origin: https://localhost:${port}" \
	--data-urlencode "token=${setup_token}" \
	--data-urlencode 'password=a secure password' \
	--data-urlencode 'confirm=a secure password' \
	"https://localhost:${port}/setup/claim")"
if [[ "$status" != "303" ]]; then
	docker logs "$tailstate_name" >&2 || true
	docker logs "$caddy_name" >&2 || true
	echo "HTTPS proxy setup claim returned HTTP ${status}, expected 303" >&2
	exit 1
fi

echo "TailState HTTPS proxy smoke test passed"

#!/usr/bin/env bash
# Validate the HTTPS reverse-proxy override (compose.yaml + compose.remote.yaml).
#
# Static checks: only Caddy publishes ports, TailState publishes nothing, and
# TailState joins at least one non-internal network so it can reach the
# Tailscale API and notification providers.
#
# Runtime check: containers attached to exactly TailState's networks can reach
# the internet, while the internal proxy network alone cannot. Set
# TAILSTATE_SKIP_EGRESS_CHECK=1 to skip the runtime check on offline hosts.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_dir="$(cd -- "$script_dir/.." && pwd -P)"
cd "$repo_dir"

config="$(TAILSTATE_MASTER_KEY_FILE=/dev/null docker compose -f compose.yaml -f compose.remote.yaml config --format json)"

fail() {
	echo "remote compose check: $*" >&2
	exit 1
}

jq -e '.services.caddy.image | test("^caddy:2\\.11-alpine@sha256:")' <<<"$config" >/dev/null || fail "caddy image is not the pinned caddy:2.11-alpine digest"
jq -e '[.services.caddy.ports[]?.published] | (index("80") != null and index("443") != null)' <<<"$config" >/dev/null || fail "caddy must publish 80 and 443"
jq -e '(.services.tailstate.ports // []) | length == 0' <<<"$config" >/dev/null || fail "tailstate must not publish host ports"
jq -e '.services.tailstate.environment.TAILSTATE_COOKIE_SECURE == "true"' <<<"$config" >/dev/null || fail "tailstate must require secure cookies behind the proxy"
egress_networks="$(jq -r '. as $root | .services.tailstate.networks | keys[] | select(($root.networks[.].internal // false) != true)' <<<"$config")"
[[ -n "$egress_networks" ]] || fail "tailstate is attached only to internal networks and cannot reach the Tailscale API"
caddy_ip="$(jq -r '.services.caddy.networks["tailstate-private"].ipv4_address' <<<"$config")"
trusted="$(jq -r '.services.tailstate.environment.TAILSTATE_TRUSTED_PROXIES' <<<"$config")"
[[ "$trusted" == "${caddy_ip}/32" ]] || fail "TAILSTATE_TRUSTED_PROXIES ($trusted) must match the caddy address ($caddy_ip/32)"
echo "remote compose static checks passed (tailstate egress via: $(tr '\n' ' ' <<<"$egress_networks"))"

if [[ "${TAILSTATE_SKIP_EGRESS_CHECK:-0}" == "1" ]]; then
	echo "remote compose egress check skipped"
	exit 0
fi

backup_image="${TAILSTATE_BACKUP_IMAGE:-$(bash "$script_dir/backup-image.sh")}"
if ! docker image inspect "$backup_image" >/dev/null 2>&1; then
	docker pull "$backup_image" >/dev/null
fi
project="tailstate-remote-check-${GITHUB_RUN_ID:-local}-${BASHPID}"
probe="${project}-probe"
cleanup() {
	set +e
	docker rm -f "$probe" >/dev/null 2>&1
	for network in "${networks[@]}"; do
		docker network rm "$network" >/dev/null 2>&1
	done
}
networks=()
trap cleanup EXIT

# Recreate TailState's networks with the same internal flag Compose would use,
# without starting any service or pulling the application image.
while IFS=$'\t' read -r name internal; do
	network="${project}_${name}"
	args=()
	[[ "$internal" == "true" ]] && args+=(--internal)
	docker network create "${args[@]}" "$network" >/dev/null
	networks+=("$network")
done < <(jq -r '. as $root | .services.tailstate.networks | keys[] | [., (($root.networks[.].internal // false) | tostring)] | @tsv' <<<"$config")

reach() {
	docker exec "$probe" sh -c 'nc -z -w 5 api.tailscale.com 443' >/dev/null 2>&1
}

docker run -d --name "$probe" --network "${project}_tailstate-private" "$backup_image" sleep 120 >/dev/null
if reach; then
	fail "the internal proxy network unexpectedly reached the internet; the check cannot distinguish egress"
fi
for network in "${networks[@]}"; do
	[[ "$network" == "${project}_tailstate-private" ]] && continue
	docker network connect "$network" "$probe"
done
if ! reach; then
	fail "a container on TailState's networks (${networks[*]}) cannot reach api.tailscale.com:443"
fi
echo "remote compose egress check passed"

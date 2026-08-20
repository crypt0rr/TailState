#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 [OUTPUT_DIRECTORY] [COMPOSE_SERVICE]" >&2
    echo "       TAILSTATE_BACKUP_IMAGE may override the pinned Alpine sidecar" >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi
if [[ $# -gt 2 ]]; then
    usage
    exit 2
fi

output_dir="${1:-./backups}"
service="${2:-tailstate}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
backup_image="$(bash "$script_dir/backup-image.sh")"
host_uid="$(id -u)"
host_gid="$(id -g)"

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"

mapfile -t containers < <(docker compose ps -aq "$service")
if [[ ${#containers[@]} -ne 1 || -z "${containers[0]}" ]]; then
    echo "expected exactly one existing Compose container for service $service" >&2
    exit 1
fi
container="${containers[0]}"
running="$(docker inspect --format '{{.State.Running}}' "$container")"

restart() {
    local status=$?
    trap - EXIT
    if [[ "$running" == "true" ]]; then
        if ! docker compose start "$service" >/dev/null; then
            echo "backup completed, but failed to restart $service" >&2
            status=1
        fi
    fi
    exit "$status"
}
trap restart EXIT

if [[ "$running" == "true" ]]; then
    docker compose stop "$service" >/dev/null
fi

archive_name="tailstate-data-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
archive_path="$output_dir/$archive_name"
docker run --rm \
    --volumes-from "$container" \
    --volume "$output_dir:/backup" \
    "$backup_image" \
    sh -ec 'umask 077; tar czf "/backup/$1" -C /data .; chown "$2:$3" "/backup/$1"' -- "$archive_name" "$host_uid" "$host_gid"

(
    cd "$output_dir"
    sha256sum "$archive_name" >"$archive_name.sha256"
)
printf 'Backup written to %s\nChecksum written to %s.sha256\n' "$archive_path" "$archive_path"

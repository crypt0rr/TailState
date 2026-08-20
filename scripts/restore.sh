#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 ARCHIVE.tar.gz --yes [COMPOSE_SERVICE]" >&2
    echo "       A pre-restore archive is created beside ARCHIVE before replacement." >&2
    echo "       TAILSTATE_BACKUP_IMAGE may override the pinned Alpine sidecar" >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi
if [[ $# -lt 2 || $# -gt 3 || ${2:-} != "--yes" ]]; then
    usage
    exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
service="${3:-tailstate}"
# renovate: datasource=docker depName=alpine
backup_image="${TAILSTATE_BACKUP_IMAGE:-alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b}"
host_uid="$(id -u)"
host_gid="$(id -g)"

if [[ ! -f "$archive" ]]; then
    echo "archive not found: $archive" >&2
    exit 1
fi
archive_dir="$(dirname "$archive")"
archive_name="$(basename "$archive")"
checksum="$archive.sha256"
if [[ -f "$checksum" ]]; then
    (cd "$archive_dir" && sha256sum -c "$(basename "$checksum")")
fi

mapfile -t containers < <(docker compose ps -aq "$service")
if [[ ${#containers[@]} -ne 1 || -z "${containers[0]}" ]]; then
    echo "expected exactly one existing Compose container for service $service" >&2
    exit 1
fi
container="${containers[0]}"
running="$(docker inspect --format '{{.State.Running}}' "$container")"

if ! entries="$(docker run --rm --volume "$archive_dir:/backup:ro" "$backup_image" tar tzf "/backup/$archive_name")"; then
    echo "archive cannot be listed: $archive" >&2
    exit 1
fi
if printf '%s\n' "$entries" | grep -Eq '(^/|(^|/)\.\.(\/|$))'; then
    echo "archive contains an unsafe absolute or parent-directory path" >&2
    exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
pre_restore_name="${archive_name%.tar.gz}-pre-restore-$timestamp.tar.gz"
pre_restore_path="$archive_dir/$pre_restore_name"
restart() {
    local status=$?
    trap - EXIT
    if [[ "$status" -eq 0 && "$running" == "true" ]]; then
        if ! docker compose start "$service" >/dev/null; then
            echo "restore failed, and $service could not be restarted" >&2
            status=1
        fi
    elif [[ "$status" -ne 0 ]]; then
        echo "restore failed; $service was left stopped so the data volume can be inspected or recovered from the pre-restore archive" >&2
    fi
    exit "$status"
}
trap restart EXIT

if [[ "$running" == "true" ]]; then
    docker compose stop "$service" >/dev/null
fi

docker run --rm \
    --volumes-from "$container" \
    --volume "$archive_dir:/backup" \
    "$backup_image" \
    sh -ec 'umask 077; tar czf "/backup/$1" -C /data .; chown "$2:$3" "/backup/$1"' -- "$pre_restore_name" "$host_uid" "$host_gid"
(
    cd "$archive_dir"
    sha256sum "$pre_restore_name" >"$pre_restore_name.sha256"
)

docker run --rm \
    --volumes-from "$container" \
    --volume "$archive_dir:/backup:ro" \
    "$backup_image" \
    sh -ec '
        restore_dir="$(mktemp -d /tmp/tailstate-restore.XXXXXX)"
        previous_dir="$(mktemp -d /tmp/tailstate-previous.XXXXXX)"
        backup_ready=0
        restore_failed() {
            status=$?
            trap - EXIT
            if [ "$status" -ne 0 ] && [ "$backup_ready" -eq 1 ]; then
                rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true
                cp -a "$previous_dir"/. /data/ || {
                    echo "restore rollback failed; recover from the pre-restore archive" >&2
                    status=1
                }
            fi
            rm -rf "$restore_dir" "$previous_dir"
            exit "$status"
        }
        trap restore_failed EXIT
        tar xzf "/backup/$1" -C "$restore_dir"
        unsafe="$(find "$restore_dir" \( -type l -o -type b -o -type c -o -type p \) -print -quit)"
        if [ -n "$unsafe" ]; then
            echo "archive contains an unsafe special file: $unsafe" >&2
            exit 1
        fi
        cp -a /data/. "$previous_dir"/
        backup_ready=1
        find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
        cp -a "$restore_dir"/. /data/
    ' -- "$archive_name"

printf 'Restored %s into the %s data volume.\nPre-restore backup: %s\n' "$archive" "$service" "$pre_restore_path"

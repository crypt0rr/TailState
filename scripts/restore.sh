#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 ARCHIVE.tar.gz --yes [COMPOSE_SERVICE]" >&2
    echo "       A pre-restore archive is created beside ARCHIVE before replacement." >&2
    echo "       TAILSTATE_BACKUP_IMAGE may override the pinned BusyBox sidecar" >&2
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
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
backup_image="$(bash "$script_dir/backup-image.sh")"
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

# The successful path writes a pre-restore archive beside the source archive.
# Check that destination before stopping TailState; otherwise a read-only or
# full backup directory would leave a healthy service stopped even though no
# restore mutation had begun.
write_probe="$(mktemp "$archive_dir/.tailstate-restore-write.XXXXXX")" || {
    echo "restore directory is not writable: $archive_dir" >&2
    exit 1
}
rm -f "$write_probe"

mapfile -t containers < <(docker compose ps -aq "$service")
if [[ ${#containers[@]} -ne 1 || -z "${containers[0]}" ]]; then
    echo "expected exactly one existing Compose container for service $service" >&2
    exit 1
fi
container="${containers[0]}"
running="$(docker inspect --format '{{.State.Running}}' "$container")"

# The pre-restore archive is written after the service is stopped. Refuse to
# enter that state when the destination filesystem cannot conservatively hold
# an uncompressed copy of the data volume plus a small metadata margin. This
# turns a predictable disk-full condition into a safe preflight failure; the
# atomic swap and rollback still handle space exhaustion that occurs later.
available_kib="$(df -Pk "$archive_dir" | awk 'NR == 2 { print $4; exit }')"
if [[ "$available_kib" =~ ^[0-9]+$ ]]; then
    if ! data_kib="$(docker run --rm --volumes-from "$container" "$backup_image" du -sk /data | awk 'NR == 1 { print $1; exit }')"; then
        echo "could not measure the data volume before restore" >&2
        exit 1
    fi
    if [[ "$data_kib" =~ ^[0-9]+$ ]]; then
        required_kib=$((data_kib + 1024))
        if (( available_kib < required_kib )); then
            echo "insufficient free space for the pre-restore archive: ${available_kib} KiB available, ${required_kib} KiB required" >&2
            exit 1
        fi
    fi
fi

if ! entries="$(docker run --rm --volume "$archive_dir:/backup:ro" "$backup_image" tar tzf "/backup/$archive_name")"; then
    echo "archive cannot be listed: $archive" >&2
    exit 1
fi
if printf '%s\n' "$entries" | grep -Eq '(^/|(^|/)\.\.(\/|$))'; then
    echo "archive contains an unsafe absolute or parent-directory path" >&2
    exit 1
fi
if ! entry_types="$(docker run --rm --volume "$archive_dir:/backup:ro" "$backup_image" tar tvzf "/backup/$archive_name")"; then
    echo "archive metadata cannot be inspected: $archive" >&2
    exit 1
fi
unsafe_type="$(printf '%s\n' "$entry_types" | awk 'substr($1, 1, 1) ~ /^[lbcpsh]$/ { print; exit }')"
if [[ -n "$unsafe_type" ]]; then
    echo "archive contains an unsafe link or special file: $unsafe_type" >&2
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
        restore_dir="$(mktemp -d /data/.tailstate-restore.XXXXXX)"
        previous_dir="$(mktemp -d /data/.tailstate-previous.XXXXXX)"
        # 0: staged only, 1: old entries are moving, 2: new entries are
        # moving, 3: replacement committed. The phase lets rollback restore
        # the right set if a rename fails midway through either pass.
        phase=0
        move_entries() {
            source="$1"
            target="$2"
            for entry in "$source"/* "$source"/.[!.]* "$source"/..?*; do
                [ -e "$entry" ] || [ -L "$entry" ] || continue
                [ "$entry" = "$restore_dir" ] && continue
                [ "$entry" = "$previous_dir" ] && continue
                mv -- "$entry" "$target"/
            done
        }
        restore_failed() {
            status=$?
            trap - EXIT
            if [ "$status" -ne 0 ] && [ "$phase" -eq 1 ]; then
                move_entries "$previous_dir" /data || status=1
            elif [ "$status" -ne 0 ] && [ "$phase" -eq 2 ]; then
                # Both temporary directories live in the data volume, so all
                # moves are same-filesystem renames. Roll back any partially
                # applied replacement without copying the original database.
                move_entries /data "$restore_dir" || status=1
                move_entries "$previous_dir" /data || status=1
                if [ "$status" -ne 0 ]; then
                    echo "restore rollback failed; recover from the pre-restore archive" >&2
                fi
            fi
            rm -rf "$restore_dir" "$previous_dir" 2>/dev/null || true
            exit "$status"
        }
        trap restore_failed EXIT
        tar xzf "/backup/$1" -C "$restore_dir"
        unsafe="$(find "$restore_dir" \( -type l -o -type b -o -type c -o -type p \) -print -quit)"
        if [ -n "$unsafe" ]; then
            echo "archive contains an unsafe special file: $unsafe" >&2
            exit 1
        fi
        phase=1
        move_entries /data "$previous_dir"
        phase=2
        move_entries "$restore_dir" /data
        phase=3
        rm -rf "$restore_dir" "$previous_dir"
    ' -- "$archive_name"

printf 'Restored %s into the %s data volume.\nPre-restore backup: %s\n' "$archive" "$service" "$pre_restore_path"

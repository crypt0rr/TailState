#!/usr/bin/env bash
# Print the Docker mount source for the /data mount of a TailState container.
#
# Backup and restore helpers mount only this source instead of using
# --volumes-from, which would also expose the Compose master-key secret
# (/run/secrets) and any other mounts to the helper container.
set -euo pipefail

container="${1:?usage: data-volume.sh CONTAINER}"
source="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}' "$container")"
if [[ -z "$source" ]]; then
    echo "container $container has no /data mount" >&2
    exit 1
fi
printf '%s\n' "$source"

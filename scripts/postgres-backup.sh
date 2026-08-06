#!/usr/bin/env bash
# Create an atomic, locally verified PostgreSQL custom-format backup.
set -euo pipefail

umask 0077

container="${OLYMPUS_POSTGRES_CONTAINER:-olympus-postgres}"
backup_dir="${OLYMPUS_POSTGRES_BACKUP_DIR:-${HOME}/olympus-backups}"

case "$backup_dir" in
  "${HOME}"/*) ;;
  *)
    echo "refusing backup directory outside the runtime user's home" >&2
    exit 64
    ;;
esac

mkdir -p -- "$backup_dir"
chmod 0700 -- "$backup_dir"

if [[ "$(docker inspect --format '{{.State.Running}}' "$container")" != "true" ]]; then
  echo "PostgreSQL container is not running: $container" >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_path="${backup_dir}/authority-${timestamp}.dump"
partial_path="${final_path}.partial"
checksum_path="${final_path}.sha256"
checksum_partial="${checksum_path}.partial"

cleanup() {
  rm -f -- "$partial_path" "$checksum_partial"
}
trap cleanup EXIT

docker exec "$container" sh -euc \
  'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=9' \
  > "$partial_path"

[[ -s "$partial_path" ]] || {
  echo "pg_dump produced an empty backup" >&2
  exit 1
}

# Parsing the archive catches truncation and format corruption before the file
# is promoted to its final name. A separate restore drill proves semantics.
docker exec -i "$container" pg_restore --list < "$partial_path" > /dev/null

mv -- "$partial_path" "$final_path"
sha256sum -- "$final_path" > "$checksum_partial"
mv -- "$checksum_partial" "$checksum_path"
chmod 0600 -- "$final_path" "$checksum_path"
trap - EXIT

printf 'backup=%s\nchecksum=%s\n' "$final_path" "$checksum_path"

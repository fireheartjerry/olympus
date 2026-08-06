#!/usr/bin/env bash
# Atomically back up both Temporal PostgreSQL databases and verify the archives.
set -euo pipefail

umask 0077

container="${OLYMPUS_POSTGRES_CONTAINER:-olympus-postgres}"
backup_root="${OLYMPUS_POSTGRES_BACKUP_DIR:-${HOME}/olympus-backups}"

case "$backup_root" in
  "${HOME}"/*) ;;
  *)
    echo "refusing backup directory outside the runtime user's home" >&2
    exit 64
    ;;
esac

mkdir -p -- "$backup_root"
chmod 0700 -- "$backup_root"
[[ "$(docker inspect --format '{{.State.Running}}' "$container")" == "true" ]]

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_dir="${backup_root}/temporal-${timestamp}"
partial_dir="${final_dir}.partial"

cleanup() {
  rm -rf -- "$partial_dir"
}
trap cleanup EXIT
mkdir -- "$partial_dir"

for database in temporal temporal_visibility; do
  dump_path="${partial_dir}/${database}.dump"
  docker exec "$container" sh -euc \
    'exec pg_dump -U "$POSTGRES_USER" -d "$1" --format=custom --compress=9' \
    sh "$database" > "$dump_path"
  [[ -s "$dump_path" ]]
  docker exec -i "$container" pg_restore --list < "$dump_path" > /dev/null
  (cd "$partial_dir" && sha256sum -- "${database}.dump") >> "${partial_dir}/SHA256SUMS"
done

chmod 0600 -- "$partial_dir"/*
mv -- "$partial_dir" "$final_dir"
trap - EXIT

printf 'temporal-backup=%s\n' "$final_dir"

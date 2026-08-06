#!/usr/bin/env bash
# Restore both Temporal databases into an isolated disposable PostgreSQL instance.
set -euo pipefail

umask 0077

source_container="${OLYMPUS_POSTGRES_CONTAINER:-olympus-postgres}"
backup_root="${OLYMPUS_POSTGRES_BACKUP_DIR:-${HOME}/olympus-backups}"
backup_dir="${1:-}"

case "$backup_dir" in
  "${backup_root}"/temporal-*) ;;
  *)
    echo "usage: $0 ${backup_root}/temporal-TIMESTAMP" >&2
    exit 64
    ;;
esac
[[ -d "$backup_dir" && ! -L "$backup_dir" ]]
(cd "$backup_dir" && sha256sum --check --status SHA256SUMS)

database_user="$(docker exec "$source_container" sh -euc 'printf %s "$POSTGRES_USER"')"
image="$(docker inspect --format '{{.Config.Image}}' "$source_container")"
restore_password="$(openssl rand -hex 24)"
drill_container="temporal-restore-drill-$$"

cleanup() {
  docker rm --force "$drill_container" > /dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach \
  --name "$drill_container" \
  --network none \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=4g \
  --env "POSTGRES_USER=$database_user" \
  --env "POSTGRES_PASSWORD=$restore_password" \
  "$image" > /dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "$drill_container" pg_isready -U "$database_user" > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == "true" ]]

for database in temporal temporal_visibility; do
  docker exec "$drill_container" createdb -U "$database_user" "$database"
  docker exec -i "$drill_container" pg_restore \
    -U "$database_user" -d "$database" --no-owner < "${backup_dir}/${database}.dump"
  version="$({
    docker exec "$drill_container" psql -U "$database_user" -d "$database" \
      --tuples-only --no-align --command='SELECT curr_version FROM schema_version;'
  } | tr -d '[:space:]')"
  [[ -n "$version" ]]
  printf '%s-schema=%s\n' "$database" "$version"
done

printf 'temporal-restore-drill=passed image=%s\n' "$image"

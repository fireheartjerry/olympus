#!/usr/bin/env bash
# Restore one backup into an isolated, disposable PostgreSQL container.
set -euo pipefail

umask 0077

source_container="${OLYMPUS_POSTGRES_CONTAINER:-olympus-postgres}"
backup_dir="${OLYMPUS_POSTGRES_BACKUP_DIR:-${HOME}/olympus-backups}"
backup_path="${1:-}"

if [[ -z "$backup_path" ]]; then
  echo "usage: $0 /absolute/path/to/authority-TIMESTAMP.dump" >&2
  exit 64
fi

case "$backup_path" in
  "${backup_dir}"/authority-*.dump) ;;
  *)
    echo "refusing backup outside $backup_dir or with an unexpected name" >&2
    exit 64
    ;;
esac

[[ -f "$backup_path" && ! -L "$backup_path" ]] || {
  echo "backup must be a regular, non-symlink file" >&2
  exit 1
}
sha256sum --check --status "${backup_path}.sha256"

database_user="$(docker exec "$source_container" sh -euc 'printf %s "$POSTGRES_USER"')"
database_name="$(docker exec "$source_container" sh -euc 'printf %s "$POSTGRES_DB"')"
image="$(docker inspect --format '{{.Config.Image}}' "$source_container")"
restore_password="$(openssl rand -hex 24)"
drill_container="olympus-restore-drill-$$"

cleanup() {
  docker rm --force "$drill_container" > /dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach \
  --name "$drill_container" \
  --network none \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=2g \
  --env "POSTGRES_USER=$database_user" \
  --env "POSTGRES_PASSWORD=$restore_password" \
  --env "POSTGRES_DB=$database_name" \
  "$image" > /dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "$drill_container" pg_isready -U "$database_user" -d "$database_name" \
    > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == "true" ]] || {
  echo "disposable PostgreSQL did not become ready" >&2
  exit 1
}

docker exec -i "$drill_container" pg_restore \
  -U "$database_user" -d "$database_name" --clean --if-exists --no-owner \
  < "$backup_path"

table_count="$(
  docker exec "$drill_container" psql -U "$database_user" -d "$database_name" \
    --tuples-only --no-align \
    --command="SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"
)"
[[ "$table_count" =~ ^[0-9]+$ && "$table_count" -gt 0 ]] || {
  echo "restore completed without public tables" >&2
  exit 1
}

printf 'restore-drill=passed tables=%s image=%s\n' "$table_count" "$image"

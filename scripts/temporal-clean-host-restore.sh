#!/usr/bin/env bash
# Restore a verified Temporal bundle into a fresh, isolated PostgreSQL instance.
set -euo pipefail

umask 0077

backup_dir="${1:-}"
image="${FIRE_TEMPORAL_RESTORE_IMAGE:-postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777}"

if [[ -z "$backup_dir" || ! -d "$backup_dir" || -L "$backup_dir" ]]; then
  echo "usage: $0 VERIFIED_BACKUP_DIRECTORY" >&2
  exit 64
fi
(cd "$backup_dir" && sha256sum --check --status SHA256SUMS)

restore_user="temporal_restore"
restore_password="$(openssl rand -hex 24)"
drill_container="temporal-clean-restore-$$"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date +%s)"

cleanup() {
  docker rm --force "$drill_container" > /dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach \
  --name "$drill_container" \
  --network none \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=4g \
  --env "POSTGRES_USER=$restore_user" \
  --env "POSTGRES_PASSWORD=$restore_password" \
  "$image" > /dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "$drill_container" pg_isready -U "$restore_user" > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == "true" ]]

for database in temporal temporal_visibility; do
  docker exec "$drill_container" createdb -U "$restore_user" "$database"
  docker exec -i "$drill_container" pg_restore \
    -U "$restore_user" -d "$database" --no-owner < "${backup_dir}/${database}.dump"
  version="$({
    docker exec "$drill_container" psql -U "$restore_user" -d "$database" \
      --tuples-only --no-align --command='SELECT curr_version FROM schema_version;'
  } | tr -d '[:space:]')"
  [[ -n "$version" ]]
  printf '%s-schema=%s\n' "$database" "$version"
done

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
elapsed="$(( $(date +%s) - started_epoch ))"
printf 'temporal-clean-host-restore=passed image=%s started_at=%s finished_at=%s elapsed_seconds=%s\n' \
  "$image" "$started_at" "$finished_at" "$elapsed"

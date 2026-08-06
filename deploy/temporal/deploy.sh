#!/usr/bin/env bash
# Prepare PostgreSQL and start the pinned, loopback-only Temporal deployment.
set -euo pipefail

umask 0077

container="${OLYMPUS_POSTGRES_CONTAINER:-olympus-postgres}"
network="${FIRE_AUTHORITY_BACKEND_NETWORK:-fire-authority-backend}"
secret_file="${FIRE_TEMPORAL_POSTGRES_PASSWORD_FILE:-${HOME}/olympus/run/secrets/temporal-postgres-password}"
compose_file="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/compose.yaml"

case "$secret_file" in
  "${HOME}"/*) ;;
  *)
    echo "refusing Temporal secret path outside the runtime user's home" >&2
    exit 64
    ;;
esac

if ! docker network inspect "$network" > /dev/null 2>&1; then
  docker network create --driver bridge --internal "$network" > /dev/null
fi

if ! docker network connect "$network" "$container" > /dev/null 2>&1; then
  docker network inspect --format '{{range .Containers}}{{.Name}}{{"\n"}}{{end}}' "$network" \
    | grep --fixed-strings --line-regexp --quiet "$container"
fi

mkdir -p -- "$(dirname -- "$secret_file")"
chmod 0700 -- "$(dirname -- "$secret_file")"
if [[ ! -f "$secret_file" ]]; then
  openssl rand -hex 32 > "$secret_file"
fi
[[ ! -L "$secret_file" ]]
chmod 0400 -- "$secret_file"
[[ "$(stat -c '%u' "$secret_file")" == "1000" ]]

password="$(<"$secret_file")"
[[ "$password" =~ ^[0-9a-f]{64}$ ]]

docker exec "$container" sh -euc '
  exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres \
    --set=temporal_password="$1"
' sh "$password" <<'SQL'
SELECT format('CREATE ROLE temporal LOGIN PASSWORD %L', :'temporal_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'temporal') \gexec
SELECT format('ALTER ROLE temporal PASSWORD %L', :'temporal_password') \gexec
SELECT format('CREATE DATABASE temporal OWNER temporal')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'temporal') \gexec
SELECT format('CREATE DATABASE temporal_visibility OWNER temporal')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'temporal_visibility') \gexec
SQL
unset password

export FIRE_AUTHORITY_BACKEND_NETWORK="$network"
export FIRE_TEMPORAL_POSTGRES_PASSWORD_FILE="$secret_file"
docker compose -f "$compose_file" up -d --wait

health="$(docker inspect --format '{{.State.Health.Status}}' fire-temporal)"
[[ "$health" == "healthy" ]]
printf 'temporal=healthy address=127.0.0.1:7233 network=%s\n' "$network"

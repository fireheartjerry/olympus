#!/bin/sh
set -eu

: "${POSTGRES_SEEDS:?POSTGRES_SEEDS is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${SQL_PASSWORD:?SQL_PASSWORD is required}"

port="${DB_PORT:-5432}"
nc -z -w 10 "$POSTGRES_SEEDS" "$port"

setup_database() {
  database="$1"
  schema_dir="$2"
  if ! temporal-sql-tool \
    --plugin postgres12 --ep "$POSTGRES_SEEDS" -u "$POSTGRES_USER" -p "$port" \
    --db "$database" setup-schema -v 0.0; then
    echo "$database base schema setup did not run; versioned migration will prove existing state"
  fi
  temporal-sql-tool \
    --plugin postgres12 --ep "$POSTGRES_SEEDS" -u "$POSTGRES_USER" -p "$port" \
    --db "$database" update-schema -d "$schema_dir"
}

setup_database temporal /etc/temporal/schema/postgresql/v12/temporal/versioned
setup_database temporal_visibility /etc/temporal/schema/postgresql/v12/visibility/versioned

#!/bin/sh
set -eu

namespace="${DEFAULT_NAMESPACE:-default}"
address="${TEMPORAL_ADDRESS:-server:7233}"
retention="${NAMESPACE_RETENTION:-7d}"

attempt=1
while ! temporal operator cluster health --address "$address" >/dev/null 2>&1; do
  if [ "$attempt" -ge 30 ]; then
    echo "Temporal did not become healthy" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 2
done

if temporal operator namespace describe -n "$namespace" --address "$address" >/dev/null 2>&1; then
  echo "namespace $namespace already exists"
else
  temporal operator namespace create \
    -n "$namespace" --retention "$retention" --address "$address"
fi

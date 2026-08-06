#!/usr/bin/env bash
# Fail loudly on authority-plane capacity or service regressions.
set -euo pipefail

disk_warn_percent="${OLYMPUS_DISK_WARN_PERCENT:-80}"
swap_warn_percent="${OLYMPUS_SWAP_WARN_PERCENT:-95}"
memory_available_warn_percent="${OLYMPUS_MEMORY_AVAILABLE_WARN_PERCENT:-20}"
container="${OLYMPUS_POSTGRES_CONTAINER:-olympus-postgres}"

failures=()

disk_percent="$(df --output=pcent / | tail -1 | tr -dc '0-9')"
if (( disk_percent >= disk_warn_percent )); then
  failures+=("root-disk=${disk_percent}%")
fi

read -r memory_total memory_available < <(free -b | awk '/^Mem:/ {print $2, $7}')
memory_available_percent=$((memory_available * 100 / memory_total))

read -r swap_total swap_used < <(free -b | awk '/^Swap:/ {print $2, $3}')
swap_percent=0
if (( swap_total > 0 )); then
  swap_percent=$((swap_used * 100 / swap_total))
fi
if (( swap_percent >= swap_warn_percent && memory_available_percent < memory_available_warn_percent )); then
  failures+=("memory-available=${memory_available_percent}% swap=${swap_percent}%")
fi

if ! systemctl --user is-active --quiet olympus-gateway.service; then
  failures+=("gateway=inactive")
fi
if ! systemctl --user is-active --quiet olympus-audit-export.timer; then
  failures+=("audit-timer=inactive")
fi
if ! docker exec "$container" pg_isready > /dev/null 2>&1; then
  failures+=("postgres=unready")
fi

if (( ${#failures[@]} > 0 )); then
  printf 'Fire production health FAILED: %s\n' "${failures[*]}" >&2
  exit 1
fi

printf 'Fire production health OK: root-disk=%s%% memory-available=%s%% swap=%s%% gateway=active audit-timer=active postgres=ready\n' \
  "$disk_percent" "$memory_available_percent" "$swap_percent"

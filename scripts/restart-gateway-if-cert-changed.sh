#!/usr/bin/env bash
# Restart the gateway only when the TLS certificate on disk actually changed.
#
# uvicorn loads the certificate once at startup, so a renewed certificate does
# not take effect until the process restarts. But an unconditional daily
# restart would interrupt a ceremony in progress for no reason on the ~89 days
# a year the certificate did not change. Comparing a fingerprint makes the
# restart follow the renewal rather than the schedule.
set -euo pipefail

CERT=/home/ubuntu/olympus/run/tls/olympus.crt
STAMP=/home/ubuntu/olympus/run/tls/.last-deployed-fingerprint

[[ -r "$CERT" ]] || { echo "no certificate at $CERT" >&2; exit 1; }

current="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256)"
previous="$(cat "$STAMP" 2>/dev/null || true)"

if [[ "$current" == "$previous" ]]; then
  echo "certificate unchanged; leaving the gateway alone"
  exit 0
fi

echo "certificate changed; restarting the gateway"
systemctl --user restart olympus-gateway.service
printf '%s\n' "$current" > "$STAMP"

# Prove the new certificate is actually being served rather than assuming the
# restart worked. A renewal that silently fails here is worse than no renewal,
# because it looks handled.
sleep 5
served="$(echo | openssl s_client -connect 100.67.123.50:9443 \
  -servername vps-41e741fc.tail70f263.ts.net 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256)"
if [[ "$served" != "$current" ]]; then
  echo "gateway is not serving the renewed certificate" >&2
  exit 1
fi
echo "gateway is serving the renewed certificate"

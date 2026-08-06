# Systemd user units for the Olympus production gateway

Copies of what is installed on `vps-41e741fc`, kept here so the deployment is
reproducible rather than existing only in one home directory.

These are **user** units, not system units: the deployment has no root, and
does not need it. Nothing here binds a privileged port or writes outside
`/home/ubuntu`.

Do not add `CapabilityBoundingSet=` or `PrivateDevices=true` to these user
units. The OVH user manager cannot apply the capability changes they request
and fails the process with `218/CAPABILITIES`. `NoNewPrivileges=true` and the
remaining namespace restrictions are the compatible privilege boundary here.

```bash
cp deploy/systemd/*.service deploy/systemd/*.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now \
  olympus-gateway.service \
  olympus-audit-export.timer \
  olympus-tls-renew.timer \
  olympus-postgres-backup.timer \
  olympus-temporal-backup.timer \
  olympus-health-check.timer
loginctl enable-linger "$USER"   # so both survive logout and reboot
```

`enable-linger` is required. Without it the user manager stops at logout and
takes the gateway with it.

| Unit | Role |
|---|---|
| `olympus-gateway.service` | The authority gateway on `100.67.123.50:9443`, `Restart=on-failure` |
| `olympus-tls-renew.timer` | Daily certificate check, randomized by up to an hour |
| `olympus-tls-renew.service` | Runs `tailscale cert`, then restarts the gateway **only if the certificate actually changed** |
| `olympus-postgres-backup.timer` | Daily atomic custom-format PostgreSQL backup with archive and SHA-256 verification |
| `olympus-temporal-backup.timer` | Daily verified Temporal dumps followed by encrypted, signed, immutable off-host upload |
| `olympus-health-check.timer` | Five-minute disk, swap, gateway, audit-timer, PostgreSQL, and Temporal readiness check |

The conditional restart matters: `uvicorn` reads the certificate once at
startup, so a renewal needs a restart to take effect — but restarting daily
would interrupt a ceremony on the ~89 days a year nothing changed.

Backups are written with mode `0600` under `~/olympus-backups`. Prove a backup
before trusting it:

```bash
latest="$(find "$HOME/olympus-backups" -maxdepth 1 -type f -name 'authority-*.dump' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
scripts/postgres-restore-drill.sh "$latest"

latest_temporal="$(find "$HOME/olympus-backups" -maxdepth 1 -type d -name 'temporal-*' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
scripts/temporal-restore-drill.sh "$latest_temporal"
```

The local drill creates a network-isolated PostgreSQL container with tmpfs
storage, restores and queries the backup, then removes the container. A timer
run succeeds only after its archive is uploaded with explicit AES-256 server-
side encryption, verified Object Lock retention, a pinned-key Ed25519
attestation, and an owner-only local receipt. The five-minute health check
fails when that receipt is older than 26 hours.

For direct clean-host recovery and the measured RPO/RTO drill, follow
`docs/operations/temporal-disaster-recovery.md`.

Run `systemd-analyze --user verify deploy/systemd/*.service deploy/systemd/*.timer`
before installing unit changes. Copy units, reload, start each oneshot manually,
and only then enable its timer. Do not restart the healthy gateway merely to
install a timer.

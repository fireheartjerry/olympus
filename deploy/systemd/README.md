# Systemd user units for the Olympus production gateway

Copies of what is installed on `vps-41e741fc`, kept here so the deployment is
reproducible rather than existing only in one home directory.

These are **user** units, not system units: the deployment has no root, and
does not need it. Nothing here binds a privileged port or writes outside
`/home/ubuntu`.

```bash
cp deploy/systemd/*.service deploy/systemd/*.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now olympus-gateway.service olympus-tls-renew.timer
loginctl enable-linger "$USER"   # so both survive logout and reboot
```

`enable-linger` is required. Without it the user manager stops at logout and
takes the gateway with it.

| Unit | Role |
|---|---|
| `olympus-gateway.service` | The authority gateway on `100.67.123.50:9443`, `Restart=on-failure` |
| `olympus-tls-renew.timer` | Daily certificate check, randomized by up to an hour |
| `olympus-tls-renew.service` | Runs `tailscale cert`, then restarts the gateway **only if the certificate actually changed** |

The conditional restart matters: `uvicorn` reads the certificate once at
startup, so a renewal needs a restart to take effect — but restarting daily
would interrupt a ceremony on the ~89 days a year nothing changed.

# Olympus Production Gateway — Deployment Runbook

**Status:** Deployed and validated on `vps-41e741fc`; enrollment ceremony pending

**Date:** 2026-08-01

**Owner:** Jerry

**Scope:** `src/olympus/runtime/production_gateway.py`,
`src/olympus/gateway/production_settings.py`, `.env.production` (untracked)

## 1. Listener inventory taken before deploying

Nothing here was displaced. The host already had:

| Port | Owner | Backend |
|---|---|---|
| 443 (tailnet IP + IPv6) | `tailscale serve` | `127.0.0.1:14000` → Docker `agentic-chrome` |
| 8443 (tailnet IP + IPv6) | `tailscale serve` | `127.0.0.1:13000` → Docker `chatgpt-browser` |
| 9433 (loopback) | Docker `agentic-chrome` | Chrome CDP |
| 9333 (loopback) | Docker `chatgpt-browser` | Chrome CDP |
| 5433 (loopback) | Docker `olympus-postgres` | PostgreSQL |
| 13000 / 13001 / 14000 (loopback) | Docker browser containers | HTTP |

Olympus took **9443**, which was unused. Note it is one digit from 9433, an
existing Chrome CDP port; they are different services and must not be confused.

`tailscale serve` configuration was not modified, no container was stopped or
reconfigured, and nothing proxies through 443 or 8443.

## 2. Binding and reachability

The gateway binds `100.67.123.50:9443` — the Tailscale interface address only.
Verified:

- Listening: `100.67.123.50:9443`
- Connection **refused** on the public address `144.217.94.114:9443`
- Connection **refused** on `127.0.0.1:9443`

`http_host` rejects `0.0.0.0`, `::`, and the empty string at settings
validation, so a wildcard bind cannot be introduced by configuration alone.

Ingress is therefore restricted to the tailnet, whose only members are Jerry's
own devices (`vps-41e741fc`, `iphone-xs`, `jerry-windows`). The tailnet packet
filter is default-allow across `100.64.0.0/10`, so no ACL change was needed for
9443.

## 3. TLS

Olympus terminates its own TLS. It does **not** sit behind a reverse proxy: the
production app rejects any request carrying `X-Forwarded-Host` or
`X-Forwarded-Proto`, because an intermediary able to assert an origin on the
browser's behalf would dissolve the WebAuthn boundary. `uvicorn` is configured
with `proxy_headers=False` and an empty `forwarded_allow_ips` to match.

Certificate material (existing Tailscale-issued Let's Encrypt cert, reused, not
re-issued):

- `/home/ubuntu/olympus/run/tls/olympus.crt`, `/home/ubuntu/olympus/run/tls/olympus.key`
- Subject `CN = vps-41e741fc.tail70f263.ts.net`, SAN `DNS:vps-41e741fc.tail70f263.ts.net`
- Issuer Let's Encrypt; valid `Jul 29 2026` → **`Oct 27 2026`**
- TLS 1.2 minimum

`curl` without `-k` returns `ssl_verify_result 0`: the chain validates against
the public trust store, which is what an iPhone will require.

**Renewal:** re-run `tailscale cert --cert-file ... --key-file ...` before
Oct 27 2026 and restart the service.

## 4. Origin, RP ID, and the port

These three strings are deliberately different, and conflating them is the
single most likely way to break the ceremony:

| | Value |
|---|---|
| Public origin | `https://vps-41e741fc.tail70f263.ts.net:9443` |
| Host header | `vps-41e741fc.tail70f263.ts.net:9443` |
| WebAuthn RP ID | `vps-41e741fc.tail70f263.ts.net` |

A WebAuthn relying-party ID is a bare domain and **cannot carry a port** by
specification; the port belongs to the origin, which the browser checks
separately.

`ProductionGatewaySettings` was audited for this and found **already correct** —
it compares `webauthn_origin.host`, which pydantic parses without the port, so a
legitimate explicit TLS port was never folded into the RP ID comparison. No fix
was required. Regression tests now pin the behaviour in both directions
(`test_explicit_tls_port_in_origin_is_not_part_of_the_rp_id`,
`test_port_bearing_origin_still_requires_the_rp_id_to_equal_the_hostname`), so a
future "simplification" cannot quietly break it.

Two guards were added:

- If the origin names a non-default port, it must equal the port actually
  served. Otherwise every ceremony fails the origin check with nothing in the
  response explaining why. Port 443 is exempt, because pydantic fills it in for
  an origin that never named a port and treating that as explicit would invent a
  constraint the operator did not write.
- `public_host_header` derives the Host header from the origin, so the port
  appears there and nowhere near the RP ID.

## 5. Validated end to end

| Check | Result |
|---|---|
| TLS chain validates without `-k` | `ssl_verify_result 0` |
| `/health/live` | 200 |
| `/health/ready` (PostgreSQL reachable) | 200 `{"status":"ready"}` |
| Enrollment page `/` | 200, offers Register Face ID / Authorize / Recover |
| `POST /v1/webauthn/register/options` with correct origin | 200 |
| Returned RP ID | `vps-41e741fc.tail70f263.ts.net` (no port) |
| Returned selection | `residentKey: required`, `userVerification: required` |
| No `Origin` header | 403 |
| Origin without the port | 403 |
| Origin on another host | 403 |
| `http://` origin | 403 |
| Correct origin + `X-Forwarded-Host` | 403 |
| Correct origin + `X-Forwarded-Proto` | 403 |
| Wrong `Host` header on `/` | 403 |
| PostgreSQL migrations | at head `20260729_01` |
| Restart recovery | challenges survived; page and readiness returned |
| `kill -9` under supervision | self-healed, active within seconds |
| 443 / 8443 after deployment | all four listeners intact, containers up |
| `tailscale serve` config | unchanged |
| Audit export end to end | 25/25 live checks (see `audit-export-signing.md`) |

Full suite: **467 passed** under `-W error`, with real PostgreSQL (no skips).

## 6. Supervision

Runs as a lingering systemd **user** service (root was not available and is not
needed):

```bash
systemctl --user status olympus-gateway.service
systemctl --user restart olympus-gateway.service
journalctl --user -u olympus-gateway.service -f
```

`Restart=on-failure`, `UMask=0077`, `NoNewPrivileges=true`, `ProtectSystem=full`.

## 7. Before the ceremony

- **`iphone-xs` must be online on Tailscale.** It was last seen 16 hours ago.
  The enrollment page is unreachable from a device that is not on the tailnet.
- `bootstrap_enabled=true` is set, and the credential table is empty
  (`webauthn_credentials` count 0). The bootstrap ceremony refuses to run
  otherwise, and refuses to run again once a credential exists.
- **After enrolling, set `OLYMPUS_PRODUCTION_BOOTSTRAP_ENABLED=false` and
  restart.** The service-level check already refuses a second bootstrap once a
  credential exists, but leaving the flag on is a standing invitation that costs
  nothing to withdraw.

## 8. Not enabled in this deployment

Discord command authority. It requires a live bot credential (the current token
is stale — see `discord-credential-recovery.md`) and a Temporal workflow
gateway, neither of which enrollment needs. The boundary is wired to
`DiscordAuthorityDisabled`, which refuses every interaction outright rather than
appearing wired while doing nothing.

# Discord Credential Recovery and Authority Bootstrap Readiness

This is the narrowly scoped procedure for the two Discord Developer Portal
values Olympus cannot derive for itself, and the state everything else is in
while they are outstanding.

Nothing here should be performed repeatedly. Rotating a Discord bot token
invalidates the previous secret immediately, so a blind retry loop guarantees
that every copy of the credential on every host is stale.

## 1. What is already proven

The stored bot credential was diagnosed once, not repeatedly:

| Check | Result |
| --- | --- |
| File mode | `600` on both `.env` files |
| Git ignore status | ignored in both repositories |
| Line endings | LF; no CRLF contamination |
| Token SHA-256 | identical across both files |
| Token shape | 81 characters, three dot-separated segments, no whitespace |
| First segment decodes to | `1511423683292561608` — the correct application |
| Authorization header | `Bot <token>` |
| `GET /api/v10/users/@me` | **HTTP 401** |

Every local explanation is therefore eliminated: parsing, whitespace, line
endings, environment loading, header construction, and application identity
are all correct. The token is well-formed and belongs to the right
application, and Discord still rejects it.

The remaining explanation is issuance state. A token is invalidated the moment
**Reset Token** is pressed in the Developer Portal, and any copy taken before
that press is dead regardless of how correctly it is stored. The stored secret
is stale.

## 2. Value one — bot token

1. Open the Discord Developer Portal, application **9to5**
   (`1511423683292561608`), and select **Bot**.
2. Press **Reset Token** and copy the new value **once**. It is displayed a
   single time.
3. Write it to both files, replacing only the `DISCORD_BOT_TOKEN` line and
   leaving the guild and channel lines untouched:
   - `/home/ubuntu/code/9to5/.env`
   - `/home/ubuntu/code/9to5-galaxy-r3/.env`
4. Keep mode `600` and LF endings. Do not paste the value into a shell command,
   a commit, an issue, or a chat message; a token in shell history is a token
   that has to be reset again.

Confirm without revealing the secret:

```bash
# Expect: identical digests, HTTP 200, and the nightclaw bot identity.
for f in /home/ubuntu/code/9to5/.env /home/ubuntu/code/9to5-galaxy-r3/.env; do
  python3 - "$f" <<'EOF'
import hashlib, sys
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("DISCORD_BOT_TOKEN="):
        value = line.split("=", 1)[1].strip()
        print(sys.argv[1], hashlib.sha256(value.encode()).hexdigest())
EOF
done
```

The previous digest was
`205914fe399a511b91627c1c1fbc5edfa2ac6cb632f713640d4f6c2e2bade7a8`. A new
digest equal to that one means the file was not actually updated.

## 3. Value two — application public key

Separate from the bot token and **not** interchangeable with it. Olympus uses
it to verify the Ed25519 signature on Discord interaction requests, which is
what stops a forged request from reaching the authority boundary.

Developer Portal → application **9to5** → **General Information** → **Public
Key**. It is 64 hexadecimal characters and is not a secret in the way the
token is, but it is still configuration, not source, so it belongs in the
untracked environment.

Set it in the untracked
`/home/ubuntu/olympus/.worktrees/trusted-authority-control/.env.production`:

```
OLYMPUS_PRODUCTION_DISCORD_APPLICATION_PUBLIC_KEY=<64 hex characters>
```

This is the **only** field still blocking `ProductionGatewaySettings` from
constructing. Every other production value validates today.

## 4. What is ready and waiting

| Item | State |
| --- | --- |
| WebAuthn relying-party ID | `vps-41e741fc.tail70f263.ts.net` |
| WebAuthn origin | `https://vps-41e741fc.tail70f263.ts.net` |
| RP ID equals origin host | enforced by `ProductionGatewaySettings`, verified |
| TLS certificate | issued for that exact name, valid to 2026-10-27 |
| Hostname stability | Tailscale MagicDNS; not localhost, not an IP, not a temporary tunnel |
| Commander, guild, channel allowlist | configured |
| Control store | PostgreSQL, Alembic schema applied |
| Emergency freeze latch | path and verification key configured |
| Credential store | empty, which is the precondition bootstrap requires |

The relying-party ID is the bare hostname with no scheme, port, or path, and
the allowed origin is bound to exactly one production HTTPS origin. Neither
the development shared token nor a loopback address is part of the production
identity boundary.

## 5. Face ID enrollment ceremony

Cannot begin until section 3 is done, because the production gateway will not
construct without that value.

`begin_registration` refuses unless bootstrap is explicitly enabled **and**
the credential store holds zero credentials, so the ceremony cannot be
replayed to silently add a second authenticator later. Registering or revoking
a credential after bootstrap requires an existing credential with fresh user
verification.

When the value is in place the ceremony is: enable bootstrap from the local
host console, open the origin above on the phone over Tailscale, and complete
Face ID user verification. That is the human-only step.

## 6. Explicitly not done

- No credential was created, guessed, rotated, or transmitted.
- The bot was not launched; authentication has not passed.
- No fallback or weakened authentication path was added to let work proceed.

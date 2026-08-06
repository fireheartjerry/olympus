# PostgreSQL authority store

This Compose definition records the live container's current PostgreSQL image
by immutable digest, its loopback-only host binding, and its existing external
volume name. It adds a real health check and conservative CPU/memory ceilings.

It is **not** an instruction to recreate the live container immediately.
Recreation is allowed only after:

1. `scripts/postgres-backup.sh` succeeds.
2. `scripts/postgres-restore-drill.sh` restores that exact backup successfully.
3. The existing environment key names and database/user identities are copied
   into an untracked, mode-`0600` `.env.postgres` without printing values.
4. `docker compose config --quiet` succeeds.
5. The old `docker inspect olympus-postgres` metadata is saved for rollback.
6. A maintenance window is explicit and gateway/audit post-checks are ready.

The external `olympus-pgdata` volume is preserved across Compose teardown. Do
not pass `--volumes`, rename the volume, initialize a new empty volume over it,
or run destructive database reset commands.

After a controlled recreation, require all of:

```bash
docker compose ps
docker inspect olympus-postgres --format '{{.State.Health.Status}}'
systemctl --user is-active olympus-gateway.service
systemctl --user start olympus-audit-export.service
scripts/production-health-check.sh
```

# Bounded OVH Temporal deployment

This is Fire's single-host production pilot: the official `temporalio/server`
image is pinned by digest, schemas are managed explicitly, PostgreSQL owns all
durable state, and host networking is safe because every Temporal service
binds explicitly to OVH loopback. The frontend is `127.0.0.1:7233`; Temporal
reaches the already-loopback-only PostgreSQL listener at `127.0.0.1:5433`.

It is intentionally not high availability. A host loss causes downtime until
OVH is restored; it must not cause workflow-state loss when the PostgreSQL
backups are current. Kubernetes, Temporal UI, Elasticsearch, and `auto-setup`
are deliberately absent.

Before startup, create the external Docker network, attach the existing
`olympus-postgres` container, create role `temporal` plus databases `temporal`
and `temporal_visibility`, and place a 0400 secret owned by UID/GID 1000 at the
path named by `FIRE_TEMPORAL_POSTGRES_PASSWORD_FILE`.

Start and verify:

```bash
export FIRE_TEMPORAL_POSTGRES_PASSWORD_FILE="$HOME/olympus/run/secrets/temporal-postgres-password"
docker compose -f deploy/temporal/compose.yaml up -d --wait
docker compose -f deploy/temporal/compose.yaml ps
docker run --rm --network host \
  temporalio/admin-tools@sha256:dbc5fcd6ee8f0f4d808bf765af9a87dea9d8a283abfdcfbd2fc148496ba66107 \
  temporal operator cluster health --address 127.0.0.1:7233
```

Never run `docker compose down -v`; the Temporal data is in PostgreSQL, but
that command is a bad operational reflex and eventually eats something real.

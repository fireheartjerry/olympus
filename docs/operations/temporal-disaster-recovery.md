# Temporal disaster recovery

## Recovery contract

Temporal is Tier 1 because it owns durable workflow history, retry state,
cancellation, and approval waits. Fire accepts a **maximum 26-hour RPO** and a
**60-minute RTO** for this single-host pilot. The daily timer runs at 03:25 UTC
with up to 15 minutes of jitter; the extra margin covers execution and alert
detection. These are recovery targets, not an availability claim.

This runbook restores only Temporal's `temporal` and `temporal_visibility`
databases. Authority and node-mesh databases have separate local backups and
remain a required off-host follow-up before whole-platform host-loss recovery
is complete.

## Protected inventory

| Asset | Source | Off-host protection | Restore dependency |
|---|---|---|---|
| Temporal core state | PostgreSQL `temporal` | custom dump in signed tar | PostgreSQL 16 |
| Temporal visibility | PostgreSQL `temporal_visibility` | custom dump in signed tar | PostgreSQL 16 |
| Backup identity | owner-only JSON receipt | exact S3 bucket/key/version | committed verifier |
| Authenticity | KMS Ed25519 sidecar | pinned public key in repository | no AWS credentials |

The archive and signature sidecar are uploaded to the existing audit-export
bucket with `If-None-Match: *`, explicit SSE-S3 (`AES256`), versioning, and the
bucket's 30-day Object Lock default. The production exporter cannot delete a
version, change retention, set legal holds, alter the bucket policy, bypass
Governance, or read/delete the KMS private key.

Governance retention is a deliberate reversible choice. It defeats deletion
through the exporter identity, including an attempted bypass, but an AWS root
or separately privileged bypass principal can still defeat it. Moving to
Compliance mode is an irreversible governance decision and is not smuggled
into an operational patch.

## Detection and authorization

`olympus-temporal-backup.service` fails if local verification, upload,
encryption, retention observation, signing, or receipt creation fails. The
five-minute production health check fails if the timer is inactive or no
off-host receipt is newer than 26 hours. Inspect with:

```bash
systemctl --user status olympus-temporal-backup.timer olympus-temporal-backup.service
journalctl --user -u olympus-temporal-backup.service -n 100 --no-pager
scripts/production-health-check.sh
```

Only Jerry may authorize a production restore. A drill may run on a disposable
host without production authority or node credentials. Do not copy the AWS
profile to the recovery host; use short-lived, exact-version presigned reads.

## Clean-host restore

On OVH, select the newest owner-only receipt and create a 15-minute handoff:

```bash
receipt="$(find "$HOME/olympus-backups/offhost-receipts" -maxdepth 1 \
  -type f -name 'temporal-*.json' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
python -m olympus.runtime.temporal_offhost_backup presign \
  --receipt "$receipt" --output "$HOME/olympus-backups/recovery-handoff.json"
```

Transfer the receipt and handoff over the private tailnet. On the clean host,
download the exact versioned archive and sidecar named in the handoff without
logging either URL. Delete the handoff immediately after download. Then run:

```bash
python -m olympus.runtime.temporal_offhost_backup verify \
  --receipt temporal-receipt.json \
  --archive temporal-backup.tar \
  --signature temporal-backup.sig.json \
  --extract verified-temporal-backup
scripts/temporal-clean-host-restore.sh verified-temporal-backup
```

Verification is offline: it checks receipt-to-attestation identity, archive
size and SHA-256, the signature against the committed Ed25519 public key and
trust window, the exact allowlist of regular tar members, and the two source
checksums before writing restore material. The restore container has no
network, uses tmpfs, queries `schema_version` in both databases, and is removed
on exit.

For an actual OVH rebuild, install the same pinned Fire release and PostgreSQL
major version, create empty `temporal` and `temporal_visibility` databases,
restore both dumps with `pg_restore --no-owner`, run the same schema queries,
start Temporal, and require the cluster health gate before starting workflow
workers. Preserve the failed host and its local state for forensics.

## Rollback and abort criteria

Abort without promoting the restore if any signature, checksum, version,
retention, archive-member, `pg_restore`, schema-version, or Temporal health
check fails. Never repair a failed dump in place. Select an earlier immutable
version and repeat into a new empty instance.

If restored Temporal starts but workflow reconciliation reports impossible or
duplicate side effects, stop workers, retain the restored databases, and
return to the previous untouched database instance. Temporal state restoration
does not authorize replaying external effects; adapter receipts and workflow
idempotency keys remain the authority for reconciliation.

## Drill evidence

Record for every drill:

| Field | Required evidence |
|---|---|
| Backup identity | backup ID, SHA-256, exact S3 version IDs |
| Immutability | overwrite, delete, and Governance-bypass denials |
| Encryption | observed `AES256` on archive and sidecar |
| RPO | restore completion minus backup `created_at` |
| RTO | clean-host download start through successful schema queries |
| Isolation | recovery host, networkless/tmpfs container, cleanup result |
| Result | both schema versions, pass/fail, operator, timestamp |

The first production drill is part of this release. Repeat quarterly and after
any change to PostgreSQL major version, Temporal persistence schema, S3/KMS
policy, backup format, or restore tooling. The next scheduled drill is
2026-11-06.

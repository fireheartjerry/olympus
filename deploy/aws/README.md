# Production AWS policy artifacts

These files are the reviewed source of truth for the policies attached to the
`olympus-audit-exporter` IAM user in account `892077329800`:

- `olympus-audit-exporter-inline.json` is inline policy
  `olympus-audit-exporter-v1`.
- `olympus-audit-exporter-managed.json` is the document for managed policy
  `arn:aws:iam::892077329800:policy/OlympusAuditExporter`; production uses
  version `v2`, with `v1` retained for rollback.

The Temporal prefix is intentionally split across statements. Writes require
the explicit `s3:x-amz-server-side-encryption = AES256` condition. Reads cover
exact object versions and lock metadata. No allow grants deletion, retention
mutation, lifecycle mutation, Governance bypass, or control of the signing key;
the existing explicit denies still cover the entire bucket.

Never apply these policies from an AWS root session. Use an IAM Identity Center
permission set or a tightly scoped break-glass administration role. Before a
change, retrieve and archive the live policy versions, validate both candidate
documents with IAM Access Analyzer, and confirm their expected account, bucket,
prefix, and KMS key identifiers.

After applying, simulate at least these cases for
`arn:aws:s3:::olympus-audit-export-892077329800/backups/temporal/proof.tar`:

| Action | Required result |
|---|---|
| `s3:PutObject` with `AES256` context | allowed |
| `s3:PutObject` without encryption context | implicit deny |
| `s3:GetObjectVersion` | allowed |
| `s3:GetObjectRetention` | allowed |
| `s3:DeleteObject` | explicit deny |
| `s3:BypassGovernanceRetention` | explicit deny |

Finish with `scripts/audit_export_live_proof.py` and an off-host Temporal upload
using `--prove-boundary`. A policy edit is incomplete until both live probes
pass and the owner-only recovery receipt exists.

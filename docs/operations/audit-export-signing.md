# Olympus Signed Audit Export — Operator Runbook

**Status:** Implemented and verified live against real S3 and real KMS, over both audit chains

**Date:** 2026-08-01

**Owner:** Jerry

**Scope:** `src/olympus/audit_export/`, AWS account `892077329800` (`us-west-2`)

## 1. Two different claims, deliberately kept apart

The most common way to misread this subsystem is to treat it as one guarantee.
It is two, and they answer different questions.

| | Question it answers | Mechanism | What defeats it |
|---|---|---|---|
| **Integrity** | Are these events contiguous and unaltered *relative to each other*? | SHA-256 hash chain over events and segments | Nothing — but it is trivially satisfiable by a forger |
| **Authenticity** | Did *Olympus* write these exact bytes, to *this exact object*? | Ed25519 signature from a KMS key, over a canonical attestation | Only possession of a KMS key nobody can export |

Integrity does not imply authenticity. Anyone who can produce bytes can produce
a perfectly self-consistent hash chain, because every hash in it is computed
from the bytes they chose. A rewritten chain is internally flawless; it just
isn't ours.

Authenticity does not imply integrity either. A genuinely signed segment can
still be presented out of order, spliced onto the wrong predecessor, or offered
as the head of a chain it does not begin.

The code keeps these apart on purpose:

- `AuditExporter.verify()` — integrity only.
- `AuditExporter.verify_authenticity(keyring)` — authenticity **and** linkage.

Both are asserted separately in `tests/audit_export/test_signing.py`
(`test_hash_intact_does_not_imply_authentic`,
`test_authentic_segment_out_of_place_is_still_refused`), so the distinction
cannot quietly erode into a single conflated check.

## 2. What a signature commits to

Each segment written to S3 gets a write-once sidecar at `<key>.sig.json`
containing an attestation and an Ed25519 signature over it. The signed bytes
are a domain-separated, canonically encoded statement — sorted keys, no
insignificant whitespace — so exactly one encoding exists per value.

The attestation binds:

| Field | Substitution it forecloses |
|---|---|
| `segment_sha256` | Modified bytes |
| `first_previous_hash`, `last_event_hash` | A segment spliced onto the wrong predecessor |
| `chain`, `first_sequence`, `last_sequence` | A real segment replayed at the wrong position, or another chain's segment |
| `bucket`, `object_key`, `version_id` | The right bytes presented as a different stored object, including a rollback to a superseded version |
| `retention_mode`, `retention_until` | An unsealed object passed off as a sealed one |
| `signer_key_id` | Trust resolved against whatever key happens to verify, rather than a pinned identity |
| `signed_at` | Expiry and revocation being undecidable |
| `schema_version` | Silent reinterpretation under a future format |

The sidecar is written through the same write-once path as the segment, so it
falls under the same Object Lock retention. A later compromise can no more
replace a signature than it can replace the bytes the signature covers.

## 3. Live inventory

| Thing | Value |
|---|---|
| Bucket | `olympus-audit-export-892077329800` (`us-west-2`) |
| Object Lock | **GOVERNANCE**, 30-day default retention |
| KMS key | `arn:aws:kms:us-west-2:892077329800:key/f67d65fc-829e-4ed8-b9a1-e3d9782a3ae2` |
| Alias | `alias/olympus-audit-signer` |
| Key spec | `ECC_NIST_EDWARDS25519` (Ed25519), `SIGN_VERIFY` |
| Signing algorithm | `ED25519_SHA_512` (pure Ed25519, not prehashed) |
| Exporter identity | `arn:aws:iam::892077329800:user/olympus-audit-exporter` |
| Pinned public key | `src/olympus/audit_export/trusted_signers.json` |

This key is **dedicated to Olympus**. Pneuma has its own signing identity
(`pneuma-kms-signer`, `pneuma-signer-bootstrap`) and the two are never shared:
a compromise of one project's signer must not let it forge the other's audit
history.

**Why pure Ed25519 and not `ED25519_PH_SHA_512`.** Prehashed Ed25519 (Ed25519ph)
is a different algorithm, and the standard Python `cryptography` library
implements only the pure variant. Choosing the prehashed algorithm would have
made offline verification depend on a hand-rolled implementation of the
signature scheme, which is precisely the code nobody should hand-roll. The
attestation is kept small (well under the 4096-byte KMS `RAW` limit) so the
pure algorithm is usable: the segment is bound by digest, not by value.

## 4. Exporter permissions

The exporter holds `kms:Sign` on one key ARN, conditioned to
`ED25519_SHA_512` and `MessageType=RAW`, and nothing else on KMS. It does
**not** hold `kms:GetPublicKey` — verification uses the pinned public key, and a
verifier that has to ask AWS is not offline.

On S3 it may append (`PutObject`), read (`GetObject`, `GetObjectVersion`),
enumerate (`ListBucket`, `ListBucketVersions`), and read sealing metadata. It is
explicitly denied — in both its identity policy and the older managed policy,
whose denials union — `DeleteObject`, `DeleteObjectVersion`,
`PutObjectRetention`, `PutObjectLegalHold`, `PutBucketObjectLockConfiguration`,
`PutLifecycleConfiguration`, and `BypassGovernanceRetention`.

Note it also holds no `ObjectLock*` argument on write. Naming a retention on
`PutObject` requires `s3:PutObjectRetention`, and that is the same permission
that can *shorten* one. The exporter states no retention and relies on the
bucket default, which `assert_retention_configured()` checks at startup so a
misconfigured bucket fails loudly instead of silently accepting unprotected
writes.

Every one of these denials was exercised live; see §7.

## 5. GOVERNANCE mode: what it does and does not protect against

Object Lock stays in **GOVERNANCE** mode. This is a deliberate choice, not an
unfinished migration to COMPLIANCE.

**What it protects against:** a compromised *exporter identity*. An attacker
holding the exporter's credentials cannot delete a segment, shorten its
retention, place or lift a legal hold, reconfigure the bucket's lock, or invoke
governance bypass. The pre-tamper history survives in a place the attacker's
database access does not reach.

**What it does not protect against:** the **AWS account root**, or any identity
granted `s3:BypassGovernanceRetention`. GOVERNANCE mode is enforced by IAM, and
IAM answers to root. A sufficiently privileged principal in account
`892077329800` can remove these objects.

COMPLIANCE mode would close that gap — nobody, including root, can delete a
COMPLIANCE-locked object before its retention expires — at the cost of being
irreversible: a misconfigured retention period cannot be corrected, and the
storage bill cannot be stopped. That tradeoff has been considered and
GOVERNANCE was chosen. **Do not migrate to COMPLIANCE without an explicit
decision to accept irreversibility.**

The signature layer is what narrows the remaining gap. Root can *delete* the
evidence, but root cannot *forge* it: producing a segment that verifies requires
signing under a key that cannot be exported from KMS, and any object that root
substitutes will fail verification against the pinned public key. Deletion is
detectable as a gap in the sequence; forgery is not possible.

Normal export operations must never use root credentials. Root exists to
provision the bucket, the key, and the exporter identity — nothing else.

## 6. Verifying offline

The verifier imports no AWS SDK, opens no socket, and reads no credential.
`tests/audit_export/test_signing.py::test_offline_verification_touches_no_network_and_no_aws`
enforces this rather than asserting it in a comment: it monkeypatches
`socket.socket.connect` to raise, and scans the verifier's own source for
`boto3` and `botocore`.

Collect an evidence bundle (needs read access) and then verify it anywhere:

```bash
# On a machine with read access to the bucket:
python -c "
import asyncio, boto3
from pathlib import Path
from olympus.audit_export.exporter import AuditExporter
from olympus.audit_export.store import S3ObjectLockStore
from olympus.audit_export.offline_verify import write_evidence_bundle
s3 = boto3.Session(profile_name='olympus-audit-exporter', region_name='us-west-2').client('s3')
ex = AuditExporter(store=S3ObjectLockStore(bucket='olympus-audit-export-892077329800', client=s3),
                   chain='CHAIN_NAME', bucket='olympus-audit-export-892077329800')
ev = asyncio.run(ex.collect_evidence())
write_evidence_bundle(Path('./bundle'), bucket='olympus-audit-export-892077329800',
                      chain='CHAIN_NAME', evidence=ev)
"

# Anywhere at all — air-gapped, no credentials, no network:
python -m olympus.audit_export.offline_verify ./bundle
```

Exit status is `0` for authentic, `1` for not authentic, `2` for an unusable
bundle. The bundle manifest's ordering is untrusted input: verification
re-derives the expected order from the signed sequence ranges, so reversing the
manifest fails.

## 7. What was proven live

Run against the real bucket and real KMS key as the real exporter identity —
25 checks, all passing:

- Bucket sealed GOVERNANCE / 30 days; mode confirmed as specified.
- 5 events exported as 3 segments; hash chain intact; every segment signed by
  the pinned key; all events attested.
- Stored objects and their signature sidecars both carry `GOVERNANCE` mode and
  a real retain-until date.
- The downloaded bundle verifies offline against the committed public key.
- Hostile: modified bytes refused; a signature moved from another segment
  refused.
- Hostile, S3 — all `AccessDenied`: delete, versioned delete, retention
  mutation, legal-hold mutation, governance bypass, lock reconfiguration.
  Overwrite refused with `PreconditionFailed`.
- Hostile, KMS — all `AccessDeniedException`: key deletion, key disable, public
  key read, and signing with the prehashed algorithm.
- Re-export is a no-op (resumable, never rewrites).

Two of these were initially reported as passing on weak evidence and were
corrected: a malformed `put_object_retention` call failed validation with
`InvalidArgument` before authorization was ever evaluated, and `kms:Decrypt`
returns `InvalidCiphertextException` for a malformed blob without resolving a
resource to authorize against. The retention check now sends a well-formed
request and genuinely returns `AccessDenied`; the decrypt check was replaced
with `GetPublicKey`, which is a real authorization decision.

## 8. Rotation and revocation

To rotate: create a new KMS key and alias, add it to `trusted_signers.json`
with its own `not_before`, and set the retiring key's `not_after` to the
cutover. Both keys stay pinned — removing the old one would make the history it
signed unverifiable.

To revoke: set `revoked_at` on the entry. Signatures dated before that instant
still verify, by design; revocation must not retroactively void honest history,
or every real compromise would also destroy the evidence of what preceded it
(`test_signatures_made_before_revocation_still_verify`).

**Known limit:** `signed_at` is asserted by the signer. An attacker who has
obtained use of the key can backdate it to just before a revocation. Revocation
therefore bounds future damage; it does not by itself establish which
signatures in the overlap window were honest. Pair a revocation with a
re-verification of the retained chain against an independently known-good
sequence high-water mark.

The `public_key_der_sha256` fingerprint in the trust store is redundant with the
key itself, and that is the point: it gives a human reviewing a diff of that
file something short to compare, so a swapped key is visible without decoding
base64. `load_keyring()` refuses a mismatch.

## 9. Both chains, and why that needed fixing

Export works over the node-mesh log and the authority log, but they are not the
same shape and the code originally assumed they were:

| | node-mesh | authority |
|---|---|---|
| `body` | method returning a dict | canonical JSON **text** |
| `previous_hash` / `event_hash` | hex `str` | raw `bytes` |

Only `sequence`, `previous_hash`, and `event_hash` are genuinely common, which
is all `ChainedEvent` now claims. Export had been exercised solely against the
node-mesh shape, so the first real authority export — the production Face ID
lease — failed with `TypeError: 'str' object is not callable`, and would have
failed again on serialization, since raw bytes are not representable in JSON.

Hashes are normalized to hex at the boundary and the canonical JSON body is
parsed back into structure, so a segment has one spelling whatever produced it.
That is what lets a verifier compare links across chains at all.

Verified live afterwards: authority chain `authority-production`, one event
(`lease-issued`), sealed under GOVERNANCE, signed by the pinned key, and
`AUTHENTIC` under offline verification.

## 10. The export actually runs now

An export subsystem that only runs when someone remembers protects nothing.
Between runs every new audit event lives solely in PostgreSQL — the one place a
compromised control plane can rewrite it — so "manual export" meant the
protected window was whatever the last human action happened to be.

This was not theoretical. When the timer was added, the production chain held
three events and exactly **one** was off-host; the two most recent
authorizations existed only in the database.

`olympus-audit-export.timer` now runs every 15 minutes (and 2 minutes after
boot, `Persistent=true` so downtime is caught up rather than silently skipped).

It is a **separate one-shot process, not a loop inside the gateway.** Export
talks to AWS; the gateway serves the Face ID ceremony. Folding one into the
other would let an S3 outage, a throttle, or an expired credential stall the
process authority depends on. A timer-run job can fail on its own.

Each run:

1. Confirms the bucket still has Object Lock retention **before** writing — a
   bucket whose lock was removed would accept the writes happily and produce a
   chain that looks exported but can be deleted at will.
2. Exports everything not yet off-host, signing each segment.
3. Verifies authenticity **every run**, not only when something was written:
   the question is whether the off-host copy is still trustworthy, and that
   answer can change without this process having done anything.
4. Exits non-zero and loud on failure. A silent failure is the worst outcome
   here, because the operator would believe evidence exists when it does not.

```bash
systemctl --user list-timers olympus-audit-export.timer
journalctl --user -u olympus-audit-export.service -n 20
systemctl --user start olympus-audit-export.service   # force a run
```

Configuration lives in `.env.production` under `OLYMPUS_PRODUCTION_AUDIT_EXPORT_*`.
Bucket and signing key must be set together or not at all: a bucket without a
key would export segments nobody can attribute, and a key without a bucket
exports nothing while looking configured.

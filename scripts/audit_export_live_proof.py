"""Live proof of the signed audit export against real AWS.

Run this after any change to the export, signing, or IAM surface. It exercises
the real bucket, the real KMS key, and the real least-privileged exporter
identity, and it asserts the denials as well as the successes — a boundary that
is only ever tested from the inside is not a boundary.

    AWS_PROFILE is not read; the exporter profile is named explicitly so this
    can never accidentally run as root.

    python scripts/audit_export_live_proof.py
"""

import asyncio
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import boto3

from olympus.audit_export.exporter import AuditExporter
from olympus.audit_export.offline_verify import verify_bundle, write_evidence_bundle
from olympus.audit_export.signing import KmsEd25519Signer, signature_key_for
from olympus.audit_export.store import S3ObjectLockStore
from olympus.audit_export.trust import load_keyring
from olympus.nodes.audit import AuditAction, AuditDecision, AuditDraft, NodeAuditLog

BUCKET = "olympus-audit-export-892077329800"
KEY_ARN = "arn:aws:kms:us-west-2:892077329800:key/f67d65fc-829e-4ed8-b9a1-e3d9782a3ae2"
CHAIN = f"signed-proof-{int(time.time())}"


def chain(count):
    log = NodeAuditLog()
    for index in range(count):
        log.append_draft(
            AuditDraft(
                actor="operator",
                action=AuditAction.SESSION_OPENED,
                decision=AuditDecision.OBSERVE,
                payload={"index": index, "chain": CHAIN},
            )
        )
    return log.events()


def ok(label, condition, detail=""):
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
    return condition


async def main():
    session = boto3.Session(profile_name="olympus-audit-exporter", region_name="us-west-2")
    s3 = session.client("s3")
    kms = session.client("kms")
    results = []

    print(f"chain: {CHAIN}\nidentity: {session.client('sts').get_caller_identity()['Arn']}\n")

    store = S3ObjectLockStore(
        bucket=BUCKET,
        client=s3,
        expected_retention_days=30,
        expected_retention_mode="GOVERNANCE",
    )
    mode, days = await store.assert_retention_configured()
    results.append(ok("bucket sealed", True, f"{mode} for {days} days"))
    results.append(ok("mode is GOVERNANCE as specified", mode == "GOVERNANCE"))

    exporter = AuditExporter(
        store=store,
        chain=CHAIN,
        max_events_per_segment=2,
        signer=KmsEd25519Signer(key_id=KEY_ARN, client=kms),
        bucket=BUCKET,
    )

    print("\n-- export --")
    result = await exporter.export(chain(5))
    results.append(
        ok("segments written", result.segments_written == 3, str(result.segments_written))
    )
    results.append(ok("events exported", result.events_exported == 5))

    print("\n-- integrity (hash chain) --")
    integrity = await exporter.verify()
    results.append(ok("chain intact", integrity.intact, str(integrity.problems)))

    print("\n-- authenticity (KMS key) --")
    keyring = load_keyring()
    authenticity = await exporter.verify_authenticity(keyring)
    results.append(ok("signed by pinned key", authenticity.authentic, str(authenticity.problems)))
    results.append(ok("all events attested", authenticity.events == 5))

    print("\n-- retention actually applied to stored objects --")
    evidence = await exporter.collect_evidence()
    head = s3.head_object(Bucket=BUCKET, Key=evidence[0].object_key)
    results.append(ok("object under GOVERNANCE", head.get("ObjectLockMode") == "GOVERNANCE"))
    results.append(
        ok(
            "retain-until set",
            bool(head.get("ObjectLockRetainUntilDate")),
            str(head.get("ObjectLockRetainUntilDate")),
        )
    )
    sidecar_head = s3.head_object(Bucket=BUCKET, Key=signature_key_for(evidence[0].object_key))
    results.append(
        ok("signature sidecar also sealed", sidecar_head.get("ObjectLockMode") == "GOVERNANCE")
    )

    print("\n-- offline verification on downloaded bytes --")
    bundle = Path(tempfile.mkdtemp(prefix="olympus-audit-bundle-"))
    write_evidence_bundle(bundle, bucket=BUCKET, chain=CHAIN, evidence=evidence)
    offline = verify_bundle(bundle)
    results.append(
        ok(
            "verifies offline against committed public key",
            offline.authentic,
            str(offline.problems),
        )
    )

    print("\n-- hostile: modified bytes rejected offline --")
    victim = bundle / "000000.segment.json"
    original = victim.read_bytes()
    victim.write_bytes(original.replace(b'"actor":"operator"', b'"actor":"attacker"'))
    tampered = verify_bundle(bundle)
    results.append(
        ok("tampered bundle refused", not tampered.authentic, str(tampered.problems[:1]))
    )
    victim.write_bytes(original)

    print("\n-- hostile: substituted signature rejected --")
    import shutil

    shutil.copy(bundle / "000001.sig.json", bundle / "000000.sig.json")
    substituted = verify_bundle(bundle)
    results.append(
        ok(
            "substituted signature refused",
            not substituted.authentic,
            str(substituted.problems[:1]),
        )
    )

    print("\n-- hostile: exporter cannot unseal what it wrote --")
    key = evidence[0].object_key
    for label, call in [
        ("delete refused", lambda: s3.delete_object(Bucket=BUCKET, Key=key)),
        (
            "versioned delete refused",
            lambda: s3.delete_object(Bucket=BUCKET, Key=key, VersionId=evidence[0].version_id),
        ),
        # A well-formed request on purpose: a malformed one would fail
        # validation before authorization and prove nothing about the denial.
        (
            "retention mutation refused",
            lambda: s3.put_object_retention(
                Bucket=BUCKET,
                Key=key,
                Retention={
                    "Mode": "GOVERNANCE",
                    "RetainUntilDate": datetime(2026, 8, 3, tzinfo=UTC),
                },
            ),
        ),
        (
            "legal hold mutation refused",
            lambda: s3.put_object_legal_hold(Bucket=BUCKET, Key=key, LegalHold={"Status": "OFF"}),
        ),
        (
            "governance bypass refused",
            lambda: s3.delete_object(
                Bucket=BUCKET,
                Key=key,
                VersionId=evidence[0].version_id,
                BypassGovernanceRetention=True,
            ),
        ),
        (
            "lock reconfiguration refused",
            lambda: s3.put_object_lock_configuration(
                Bucket=BUCKET,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
                },
            ),
        ),
        (
            "overwrite refused",
            lambda: s3.put_object(Bucket=BUCKET, Key=key, Body=b"rewritten", IfNoneMatch="*"),
        ),
    ]:
        try:
            call()
            results.append(ok(label, False, "THE CALL SUCCEEDED"))
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            results.append(ok(label, True, code))

    print("\n-- hostile: exporter cannot destroy or misuse the signing key --")
    for label, call in [
        (
            "key deletion refused",
            lambda: kms.schedule_key_deletion(KeyId=KEY_ARN, PendingWindowInDays=7),
        ),
        ("key disable refused", lambda: kms.disable_key(KeyId=KEY_ARN)),
        # Not decrypt: KMS rejects a malformed blob before it evaluates policy,
        # so that call would "pass" without demonstrating anything. GetPublicKey
        # is a real authorization decision, and it is denied because the
        # exporter holds kms:Sign and nothing else.
        ("public key read refused", lambda: kms.get_public_key(KeyId=KEY_ARN)),
        (
            "prehash algorithm refused",
            lambda: kms.sign(
                KeyId=KEY_ARN,
                Message=b"x",
                MessageType="RAW",
                SigningAlgorithm="ED25519_PH_SHA_512",
            ),
        ),
    ]:
        try:
            call()
            results.append(ok(label, False, "THE CALL SUCCEEDED"))
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            results.append(ok(label, True, code))

    print("\n-- resumability --")
    again = await exporter.export(chain(5))
    results.append(ok("re-export is a no-op", again.segments_written == 0))

    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


sys.exit(asyncio.run(main()))

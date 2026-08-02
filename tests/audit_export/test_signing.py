"""Hostile tests for key-backed authenticity of exported audit segments.

Every test here takes the position of someone who already holds valid material
and is trying to make a false claim out of it: real segments in the wrong
order, a real signature moved onto a different object, a real key past its
trust window. Verification is only worth anything if it says no to each.
"""

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from olympus.audit_export.exporter import AuditExporter
from olympus.audit_export.offline_verify import (
    BundleError,
    load_evidence_bundle,
    verify_bundle,
    write_evidence_bundle,
)
from olympus.audit_export.signing import (
    ChainLinkMismatch,
    InvalidSignature,
    Keyring,
    LocalEd25519Signer,
    MalformedAttestation,
    ObjectIdentityMismatch,
    SegmentDigestMismatch,
    SignatureError,
    SignedSegment,
    TrustedSigner,
    UnknownSigner,
    UntrustedSigner,
    build_attestation,
    sign_segment,
    signature_key_for,
    verify_signed_segment,
)
from olympus.audit_export.store import InMemoryWriteOnceStore
from olympus.audit_export.trust import (
    DEFAULT_TRUST_STORE,
    TrustStoreError,
    keyring_from_mapping,
    load_keyring,
)
from olympus.nodes.audit import AuditAction, AuditDecision, AuditDraft, NodeAuditLog

pytestmark = pytest.mark.asyncio

BUCKET = "olympus-audit-test"
CHAIN = "hostile"
KEY_ID = "arn:aws:kms:us-west-2:000000000000:key/test-signer"
SIGNED_AT = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _chain(count: int) -> tuple:
    log = NodeAuditLog()
    for index in range(count):
        log.append_draft(
            AuditDraft(
                actor="operator",
                action=AuditAction.SESSION_OPENED,
                decision=AuditDecision.OBSERVE,
                payload={"index": index},
            )
        )
    return log.events()


def _keyring(signer: LocalEd25519Signer, **overrides) -> Keyring:
    fields = {
        "key_id": signer.key_id,
        "public_key_der": signer.public_key_der,
        "not_before": SIGNED_AT - timedelta(days=1),
        "not_after": SIGNED_AT + timedelta(days=365),
    }
    fields.update(overrides)
    return Keyring(signers={signer.key_id: TrustedSigner(**fields)})


async def _signed_export(events_count: int = 5, max_events: int = 2):
    signer = LocalEd25519Signer(key_id=KEY_ID)
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(
        store=store,
        chain=CHAIN,
        max_events_per_segment=max_events,
        signer=signer,
        bucket=BUCKET,
        now=lambda: SIGNED_AT,
    )
    await exporter.export(_chain(events_count))
    return signer, store, exporter


# --- the happy path, so every rejection below means something -----------------


async def test_signed_export_is_authentic_and_hash_intact() -> None:
    signer, _store, exporter = await _signed_export()

    integrity = await exporter.verify()
    authenticity = await exporter.verify_authenticity(_keyring(signer))

    assert integrity.intact is True
    assert authenticity.authentic is True
    assert authenticity.segments == 3
    assert authenticity.events == 5
    assert authenticity.last_sequence == 5


async def test_attestation_binds_every_required_fact() -> None:
    _signer, store, exporter = await _signed_export(events_count=2, max_events=2)
    evidence = await exporter.collect_evidence()
    attestation = SignedSegment.from_bytes(evidence[0].sidecar_body).attestation

    # Each of these is a substitution the signature must foreclose.
    assert attestation.chain == CHAIN
    assert attestation.first_sequence == 1
    assert attestation.last_sequence == 2
    assert attestation.bucket == BUCKET
    assert attestation.object_key == evidence[0].object_key
    assert attestation.version_id == evidence[0].version_id
    assert attestation.retention_mode == "GOVERNANCE"
    assert attestation.retention_until
    assert attestation.signer_key_id == KEY_ID
    assert attestation.schema_version == 1
    assert attestation.first_previous_hash == "0" * 64
    assert attestation.last_event_hash
    assert attestation.segment_sha256

    # The signature sidecar is itself sealed write-once, so a later compromise
    # cannot quietly replace the attestation either.
    assert signature_key_for(evidence[0].object_key) in store.objects


# --- modified bytes -----------------------------------------------------------


async def test_modified_segment_bytes_are_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    evidence = await exporter.collect_evidence()
    item = evidence[0]

    document = json.loads(item.segment_body)
    document["events"][0]["detail"] = {"index": 999}
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    with pytest.raises(SegmentDigestMismatch):
        verify_signed_segment(
            segment_body=tampered,
            sidecar_body=item.sidecar_body,
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_a_single_flipped_byte_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    flipped = bytearray(item.segment_body)
    flipped[-2] ^= 0x01

    with pytest.raises(SegmentDigestMismatch):
        verify_signed_segment(
            segment_body=bytes(flipped),
            sidecar_body=item.sidecar_body,
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


# --- reordered segments -------------------------------------------------------


async def test_reordered_segments_are_rejected_though_each_is_validly_signed() -> None:
    signer, _store, exporter = await _signed_export()
    evidence = list(await exporter.collect_evidence())
    assert len(evidence) == 3

    from olympus.audit_export.signing import verify_exported_chain

    # Every segment here is genuine and correctly signed. Only the order lies.
    swapped = [evidence[1], evidence[0], evidence[2]]
    result = verify_exported_chain(
        evidence=swapped,
        keyring=_keyring(signer),
        bucket=BUCKET,
        chain=CHAIN,
        genesis_hash="0" * 64,
    )

    assert result.authentic is False
    assert any("expected 1" in problem for problem in result.problems)


async def test_a_dropped_segment_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    evidence = list(await exporter.collect_evidence())

    from olympus.audit_export.signing import verify_exported_chain

    result = verify_exported_chain(
        evidence=[evidence[0], evidence[2]],
        keyring=_keyring(signer),
        bucket=BUCKET,
        chain=CHAIN,
        genesis_hash="0" * 64,
    )

    assert result.authentic is False
    assert any("missing, duplicated, or reordered" in problem for problem in result.problems)


# --- substituted signatures ---------------------------------------------------


async def test_signature_from_another_segment_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    evidence = await exporter.collect_evidence()

    # A real signature, made by the real key, over a real segment — just not
    # this one. Binding the object identity into the statement is what stops it.
    with pytest.raises(ObjectIdentityMismatch):
        verify_signed_segment(
            segment_body=evidence[0].segment_body,
            sidecar_body=evidence[1].sidecar_body,
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=evidence[0].object_key,
            version_id=evidence[0].version_id,
        )


async def test_forged_signature_bytes_are_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]

    document = json.loads(item.sidecar_body)
    forged = bytearray(base64.b64decode(document["signature"]))
    forged[0] ^= 0xFF
    document["signature"] = base64.b64encode(bytes(forged)).decode("ascii")

    with pytest.raises(InvalidSignature):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=json.dumps(document).encode("utf-8"),
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_signature_from_a_different_key_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]

    # The attacker signs the very same statement with a key they control, then
    # presents it under the pinned key's identity.
    impostor = LocalEd25519Signer(key_id=KEY_ID)
    attestation = SignedSegment.from_bytes(item.sidecar_body).attestation
    forged = SignedSegment(
        attestation=attestation,
        signature=await impostor.sign(attestation.statement()),
    )

    with pytest.raises(InvalidSignature):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=forged.document(),
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_editing_the_attestation_invalidates_the_signature() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    signed = SignedSegment.from_bytes(item.sidecar_body)

    # Claim COMPLIANCE sealing the object never had, keeping the real signature.
    lying = SignedSegment(
        attestation=replace(signed.attestation, retention_mode="COMPLIANCE"),
        signature=signed.signature,
    )

    with pytest.raises(InvalidSignature):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=lying.document(),
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


# --- incorrect predecessors ---------------------------------------------------


async def test_wrong_predecessor_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[1]

    with pytest.raises(ChainLinkMismatch):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
            expected_previous_hash="f" * 64,
        )


async def test_segment_from_another_chain_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]

    with pytest.raises(ChainLinkMismatch):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
            expected_chain="some-other-chain",
        )


# --- wrong object identities --------------------------------------------------


@pytest.mark.parametrize(
    "field, value",
    [
        ("bucket", "someone-elses-bucket"),
        ("object_key", "audit/hostile/999999999999-999999999999.json"),
        ("version_id", "a-superseded-version"),
    ],
)
async def test_wrong_object_identity_is_rejected(field: str, value: str) -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]

    presented = {
        "bucket": BUCKET,
        "object_key": item.object_key,
        "version_id": item.version_id,
    }
    presented[field] = value

    with pytest.raises(ObjectIdentityMismatch):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=_keyring(signer),
            **presented,
        )


# --- unknown, expired, and revoked signer identities --------------------------


async def test_unknown_signer_is_rejected() -> None:
    _signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    stranger = LocalEd25519Signer(key_id="arn:aws:kms:us-west-2:000000000000:key/not-pinned")

    with pytest.raises(UnknownSigner):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=_keyring(stranger),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_expired_signer_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    keyring = _keyring(
        signer,
        not_before=SIGNED_AT - timedelta(days=30),
        not_after=SIGNED_AT - timedelta(days=1),
    )

    with pytest.raises(UntrustedSigner, match="expired"):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=keyring,
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_signature_predating_trust_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    keyring = _keyring(signer, not_before=SIGNED_AT + timedelta(days=1))

    with pytest.raises(UntrustedSigner, match="before it was trusted"):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=keyring,
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_revoked_signer_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    keyring = _keyring(signer, revoked_at=SIGNED_AT - timedelta(seconds=1))

    with pytest.raises(UntrustedSigner, match="revoked"):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=keyring,
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_signatures_made_before_revocation_still_verify() -> None:
    # Revocation must not retroactively void honest history, or every real
    # compromise would also destroy the evidence of what came before it.
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    keyring = _keyring(signer, revoked_at=SIGNED_AT + timedelta(days=1))

    attestation = verify_signed_segment(
        segment_body=item.segment_body,
        sidecar_body=item.sidecar_body,
        keyring=keyring,
        bucket=BUCKET,
        object_key=item.object_key,
        version_id=item.version_id,
    )
    assert attestation.signer_key_id == KEY_ID


# --- malformed input ----------------------------------------------------------


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d.update({"signing_algorithm": "ED25519_PH_SHA_512"}), "signing algorithm"),
        (lambda d: d.update({"signature": "not base64!!"}), "base64"),
        (lambda d: d.update({"signature": base64.b64encode(b"short").decode()}), "64 bytes"),
        (lambda d: d["attestation"].pop("version_id"), "do not match the schema"),
        (lambda d: d["attestation"].update({"schema_version": 99}), "schema version"),
        (lambda d: d["attestation"].update({"extra": 1}), "do not match the schema"),
    ],
)
async def test_malformed_sidecars_are_rejected(mutate, expected: str) -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    document = json.loads(item.sidecar_body)
    mutate(document)

    with pytest.raises(MalformedAttestation, match=expected):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=json.dumps(document).encode("utf-8"),
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_naive_signed_at_is_rejected() -> None:
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[0]
    document = json.loads(item.sidecar_body)
    document["attestation"]["signed_at"] = "2026-08-01T12:00:00"

    with pytest.raises(MalformedAttestation, match="UTC offset"):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=json.dumps(document).encode("utf-8"),
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
        )


async def test_signer_refuses_to_misattribute_its_own_signature() -> None:
    signer = LocalEd25519Signer(key_id=KEY_ID)
    attestation = build_attestation(
        chain=CHAIN,
        first_sequence=1,
        last_sequence=1,
        first_previous_hash="0" * 64,
        last_event_hash="a" * 64,
        segment_body=b"{}",
        bucket=BUCKET,
        object_key="audit/hostile/x.json",
        version_id="v1",
        retention_mode="GOVERNANCE",
        retention_until="2099-01-01T00:00:00+00:00",
        signer_key_id="arn:aws:kms:us-west-2:000000000000:key/someone-else",
        signed_at=SIGNED_AT,
    )

    with pytest.raises(SignatureError, match="misattributes"):
        await sign_segment(attestation=attestation, signer=signer)


# --- offline verification -----------------------------------------------------


async def test_evidence_bundle_verifies_offline(tmp_path: Path) -> None:
    signer, _store, exporter = await _signed_export()
    evidence = await exporter.collect_evidence()
    write_evidence_bundle(tmp_path, bucket=BUCKET, chain=CHAIN, evidence=evidence)

    # A trust store written the way the shipped one is, but pinning the test key.
    trust_store = tmp_path / "trust.json"
    trust_store.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signers": [
                    {
                        "key_id": KEY_ID,
                        "public_key_der_b64": base64.b64encode(signer.public_key_der).decode(),
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2028-01-01T00:00:00+00:00",
                    }
                ],
            }
        )
    )

    result = verify_bundle(tmp_path, trust_store=trust_store)
    assert result.authentic is True
    assert result.events == 5


async def test_tampered_bundle_fails_offline_verification(tmp_path: Path) -> None:
    signer, _store, exporter = await _signed_export()
    write_evidence_bundle(
        tmp_path, bucket=BUCKET, chain=CHAIN, evidence=await exporter.collect_evidence()
    )
    trust_store = tmp_path / "trust.json"
    trust_store.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signers": [
                    {
                        "key_id": KEY_ID,
                        "public_key_der_b64": base64.b64encode(signer.public_key_der).decode(),
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2028-01-01T00:00:00+00:00",
                    }
                ],
            }
        )
    )

    victim = tmp_path / "000000.segment.json"
    original = victim.read_bytes()
    assert b'"actor":"operator"' in original
    victim.write_bytes(original.replace(b'"actor":"operator"', b'"actor":"attacker"'))

    result = verify_bundle(tmp_path, trust_store=trust_store)
    assert result.authentic is False
    assert any("attestation covers" in problem for problem in result.problems)


async def test_offline_verification_touches_no_network_and_no_aws(tmp_path: Path) -> None:
    """The offline claim, enforced rather than asserted in a comment."""
    import socket

    signer, _store, exporter = await _signed_export()
    write_evidence_bundle(
        tmp_path, bucket=BUCKET, chain=CHAIN, evidence=await exporter.collect_evidence()
    )
    trust_store = tmp_path / "trust.json"
    trust_store.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signers": [
                    {
                        "key_id": KEY_ID,
                        "public_key_der_b64": base64.b64encode(signer.public_key_der).decode(),
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2028-01-01T00:00:00+00:00",
                    }
                ],
            }
        )
    )

    real_socket = socket.socket
    real_connect = socket.socket.connect

    def _forbidden(*args, **kwargs):
        raise AssertionError("offline verification attempted a network connection")

    socket.socket.connect = _forbidden  # type: ignore[method-assign]
    try:
        result = verify_bundle(tmp_path, trust_store=trust_store)
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket = real_socket  # type: ignore[misc]

    assert result.authentic is True

    # And it must not have reached an AWS SDK by another route. The verifier's
    # whole point is that it works where AWS does not, so the modules it and
    # its dependencies are built from must not name one.
    import inspect

    from olympus.audit_export import offline_verify, signing, trust

    for module in (offline_verify, signing, trust):
        source = inspect.getsource(module)
        assert "boto3" not in source, f"{module.__name__} references boto3"
        assert "botocore" not in source, f"{module.__name__} references botocore"


async def test_bundle_manifest_order_is_not_taken_on_trust(tmp_path: Path) -> None:
    signer, _store, exporter = await _signed_export()
    write_evidence_bundle(
        tmp_path, bucket=BUCKET, chain=CHAIN, evidence=await exporter.collect_evidence()
    )
    trust_store = tmp_path / "trust.json"
    trust_store.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signers": [
                    {
                        "key_id": KEY_ID,
                        "public_key_der_b64": base64.b64encode(signer.public_key_der).decode(),
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2028-01-01T00:00:00+00:00",
                    }
                ],
            }
        )
    )

    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["segments"].reverse()
    manifest_path.write_text(json.dumps(manifest))

    result = verify_bundle(tmp_path, trust_store=trust_store)
    assert result.authentic is False


async def test_unreadable_bundle_is_reported_not_ignored(tmp_path: Path) -> None:
    with pytest.raises(BundleError):
        load_evidence_bundle(tmp_path)


# --- the pinned trust store shipped with this repository ----------------------


async def test_shipped_trust_store_contains_public_material_only() -> None:
    raw = DEFAULT_TRUST_STORE.read_text(encoding="utf-8")
    lowered = raw.lower()
    # Markers of actual secret material, not the word "private" in prose.
    for forbidden in (
        "begin private key",
        "begin ec private key",
        "begin openssh private key",
        "aws_secret_access_key",
        "aws_access_key_id",
        "akia",
    ):
        assert forbidden not in lowered, f"trust store appears to contain {forbidden!r}"

    keyring = load_keyring()
    assert keyring.signers
    for signer in keyring.signers.values():
        # A bare Ed25519 SubjectPublicKeyInfo is 44 bytes; a private key is not.
        assert len(signer.public_key_der) == 44


async def test_shipped_trust_store_pins_the_olympus_audit_signer() -> None:
    keyring = load_keyring()
    signer = keyring.resolve(
        "arn:aws:kms:us-west-2:892077329800:key/f67d65fc-829e-4ed8-b9a1-e3d9782a3ae2"
    )
    assert base64.b64encode(signer.public_key_der).decode() == (
        "MCowBQYDK2VwAyEAmyWAyfnPsjTYus8ldTu4HJ/gQYmqpfvpVpSrLmfj8gQ="
    )
    assert signer.revoked_at is None


async def test_swapped_public_key_fails_the_declared_fingerprint() -> None:
    other = LocalEd25519Signer(key_id=KEY_ID)
    document = {
        "schema_version": 1,
        "signers": [
            {
                "key_id": KEY_ID,
                "public_key_der_b64": base64.b64encode(other.public_key_der).decode(),
                "public_key_der_sha256": "00" * 32,
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2028-01-01T00:00:00+00:00",
            }
        ],
    }
    with pytest.raises(TrustStoreError, match="fingerprint"):
        keyring_from_mapping(document)


async def test_trust_store_rejects_duplicate_signers() -> None:
    other = LocalEd25519Signer(key_id=KEY_ID)
    entry = {
        "key_id": KEY_ID,
        "public_key_der_b64": base64.b64encode(other.public_key_der).decode(),
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2028-01-01T00:00:00+00:00",
    }
    with pytest.raises(TrustStoreError, match="duplicate"):
        keyring_from_mapping({"schema_version": 1, "signers": [entry, dict(entry)]})


# --- integrity and authenticity stay distinct ---------------------------------


async def test_hash_intact_does_not_imply_authentic() -> None:
    """An unsigned export is internally consistent and still unattributed.

    This is the distinction the documentation draws, asserted in code so it
    cannot quietly erode: passing ``verify`` says nothing about who wrote the
    bytes.
    """
    store = InMemoryWriteOnceStore()
    unsigned = AuditExporter(store=store, chain=CHAIN, max_events_per_segment=2, bucket=BUCKET)
    await unsigned.export(_chain(4))

    assert (await unsigned.verify()).intact is True
    assert unsigned.signs is False
    with pytest.raises(RuntimeError, match="signature"):
        await unsigned.collect_evidence()


async def test_authentic_segment_out_of_place_is_still_refused() -> None:
    """And the converse: a perfect signature does not excuse a broken link."""
    signer, _store, exporter = await _signed_export()
    item = (await exporter.collect_evidence())[2]

    # Individually flawless.
    verify_signed_segment(
        segment_body=item.segment_body,
        sidecar_body=item.sidecar_body,
        keyring=_keyring(signer),
        bucket=BUCKET,
        object_key=item.object_key,
        version_id=item.version_id,
    )

    # Offered as the head of the chain, it is refused.
    with pytest.raises(ChainLinkMismatch):
        verify_signed_segment(
            segment_body=item.segment_body,
            sidecar_body=item.sidecar_body,
            keyring=_keyring(signer),
            bucket=BUCKET,
            object_key=item.object_key,
            version_id=item.version_id,
            expected_first_sequence=1,
        )

import base64
import hashlib
import io
import json
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from olympus.audit_export.signing import Keyring, LocalEd25519Signer, TrustedSigner
from olympus.backup.temporal import (
    BACKUP_FORMAT_VERSION,
    BackupReceipt,
    StoredBackupIdentity,
    TemporalBackupError,
    build_attestation,
    create_archive,
    sign_backup,
    verify_and_extract,
)
from olympus.runtime.temporal_offhost_backup import (
    _prove_write_once_boundary,
    _put_bytes_once,
    _put_file_once,
)

SIGNED_AT = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
KEY_ID = "arn:aws:kms:us-west-2:000000000000:key/test-backup-signer"


class _S3Error(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class _FakeLockedS3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_calls: list[dict[str, object]] = []

    def put_object(self, **values: object) -> dict[str, str]:
        self.put_calls.append(values)
        key = str(values["Key"])
        if key in self.objects:
            raise _S3Error("PreconditionFailed")
        raw = values["Body"]
        body = raw.read() if hasattr(raw, "read") else bytes(raw)  # type: ignore[arg-type]
        self.objects[key] = body
        return {"ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode()}

    def head_object(self, **values: object) -> dict[str, object]:
        body = self.objects[str(values["Key"])]
        return {
            "ContentLength": len(body),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode(),
            "ServerSideEncryption": "AES256",
            "ObjectLockMode": "GOVERNANCE",
            "ObjectLockRetainUntilDate": SIGNED_AT + timedelta(days=30),
            "VersionId": "immutable-version-1",
        }

    def delete_object(self, **values: object) -> None:
        raise _S3Error("AccessDenied")


def _source(root: Path) -> Path:
    source = root / "temporal-20260806T115500Z"
    source.mkdir()
    files = {
        "temporal.dump": b"temporal-custom-format\x00",
        "temporal_visibility.dump": b"visibility-custom-format\x00",
    }
    checksums = []
    for name, body in files.items():
        (source / name).write_bytes(body)
        checksums.append(f"{hashlib.sha256(body).hexdigest()}  {name}\n")
    (source / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
    return source


def _keyring(signer: LocalEd25519Signer) -> Keyring:
    return Keyring(
        signers={
            signer.key_id: TrustedSigner(
                key_id=signer.key_id,
                public_key_der=signer.public_key_der,
                not_before=SIGNED_AT - timedelta(days=1),
                not_after=SIGNED_AT + timedelta(days=365),
            )
        }
    )


async def _material(
    root: Path,
) -> tuple[Path, Path, BackupReceipt, Keyring]:
    archive = root / "backup.tar"
    digest, size, backup_id, created_at = create_archive(_source(root), archive)
    signer = LocalEd25519Signer(key_id=KEY_ID)
    identity = StoredBackupIdentity(
        object_key=f"backups/temporal/2026/08/06/{backup_id}.tar",
        version_id="version-1",
        sha256=digest,
        size=size,
        server_side_encryption="AES256",
        retention_mode="GOVERNANCE",
        retention_until=(SIGNED_AT + timedelta(days=30)).isoformat(),
    )
    attestation = build_attestation(
        backup_id=backup_id,
        created_at=created_at,
        identity=identity,
        bucket="immutable-backups",
        signer_key_id=signer.key_id,
        signed_at=SIGNED_AT,
    )
    signature = root / "backup.sig.json"
    signature.write_bytes(await sign_backup(attestation, signer))
    receipt = BackupReceipt(
        schema_version=BACKUP_FORMAT_VERSION,
        backup_id=backup_id,
        created_at=created_at,
        uploaded_at=SIGNED_AT.isoformat(),
        bucket="immutable-backups",
        object_key=identity.object_key,
        version_id=identity.version_id,
        archive_sha256=digest,
        archive_size=size,
        server_side_encryption=identity.server_side_encryption,
        retention_mode=identity.retention_mode,
        retention_until=identity.retention_until,
        signature_object_key=f"{identity.object_key}.sig.json",
        signature_version_id="version-2",
        signer_key_id=signer.key_id,
    )
    return archive, signature, receipt, _keyring(signer)


@pytest.mark.asyncio
async def test_verified_signed_archive_extracts_exact_temporal_state(tmp_path: Path) -> None:
    archive, signature, receipt, keyring = await _material(tmp_path)
    restored = tmp_path / "restored"

    attestation = verify_and_extract(
        archive_path=archive,
        signature_path=signature,
        receipt=receipt,
        keyring=keyring,
        output_dir=restored,
    )

    assert attestation.backup_id == receipt.backup_id
    assert (restored / "temporal.dump").read_bytes() == b"temporal-custom-format\x00"
    assert (restored / "temporal_visibility.dump").read_bytes() == b"visibility-custom-format\x00"


@pytest.mark.asyncio
async def test_archive_tampering_fails_before_extraction(tmp_path: Path) -> None:
    archive, signature, receipt, keyring = await _material(tmp_path)
    archive.write_bytes(archive.read_bytes() + b"attacker")

    with pytest.raises(TemporalBackupError, match="size"):
        verify_and_extract(
            archive_path=archive,
            signature_path=signature,
            receipt=receipt,
            keyring=keyring,
            output_dir=tmp_path / "never-created",
        )


@pytest.mark.asyncio
async def test_receipt_cannot_redirect_a_valid_signed_backup(tmp_path: Path) -> None:
    archive, signature, receipt, keyring = await _material(tmp_path)

    with pytest.raises(TemporalBackupError, match="receipt does not match"):
        verify_and_extract(
            archive_path=archive,
            signature_path=signature,
            receipt=replace(receipt, version_id="rollback-version"),
            keyring=keyring,
            output_dir=tmp_path / "never-created",
        )


@pytest.mark.asyncio
async def test_validly_signed_archive_with_extra_member_is_rejected(tmp_path: Path) -> None:
    archive, _signature, receipt, _keyring_value = await _material(tmp_path)
    original = archive.read_bytes()
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as source:
        for member in source.getmembers():
            body = source.extractfile(member)
            assert body is not None
            members[member.name] = body.read()
    archive.unlink()
    with tarfile.open(archive, mode="x") as target:
        for name, body in {**members, "../escape": b"forbidden"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            target.addfile(info, io.BytesIO(body))

    signer = LocalEd25519Signer(key_id=KEY_ID)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    identity = StoredBackupIdentity(
        object_key=receipt.object_key,
        version_id=receipt.version_id,
        sha256=digest,
        size=archive.stat().st_size,
        server_side_encryption=receipt.server_side_encryption,
        retention_mode=receipt.retention_mode,
        retention_until=receipt.retention_until,
    )
    attestation = build_attestation(
        backup_id=receipt.backup_id,
        created_at=receipt.created_at,
        identity=identity,
        bucket=receipt.bucket,
        signer_key_id=KEY_ID,
        signed_at=SIGNED_AT,
    )
    signature = tmp_path / "malicious.sig.json"
    signature.write_bytes(await sign_backup(attestation, signer))
    malicious_receipt = replace(receipt, archive_sha256=digest, archive_size=archive.stat().st_size)

    with pytest.raises(TemporalBackupError, match="unexpected members"):
        verify_and_extract(
            archive_path=archive,
            signature_path=signature,
            receipt=malicious_receipt,
            keyring=_keyring(signer),
            output_dir=tmp_path / "never-created",
        )


def test_source_checksum_failure_prevents_archive_creation(tmp_path: Path) -> None:
    source = _source(tmp_path)
    (source / "temporal.dump").write_bytes(b"corrupted")

    with pytest.raises(TemporalBackupError, match="checksum"):
        create_archive(source, tmp_path / "backup.tar")


def test_backup_archive_is_reproducible(tmp_path: Path) -> None:
    source = _source(tmp_path)
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"

    first_digest, _, _, _ = create_archive(source, first)
    second_digest, _, _, _ = create_archive(source, second)

    assert first_digest == second_digest
    assert first.read_bytes() == second.read_bytes()


def test_receipt_requires_exact_schema() -> None:
    with pytest.raises(TemporalBackupError, match="fields do not match"):
        BackupReceipt.from_mapping({"schema_version": 1, "surprise": json.dumps({})})


def test_s3_upload_is_explicitly_encrypted_and_content_idempotent(tmp_path: Path) -> None:
    client = _FakeLockedS3()
    archive = tmp_path / "backup.tar"
    archive.write_bytes(b"immutable Temporal state")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    first = _put_file_once(client, "bucket", "key", archive, digest, "application/x-tar")
    second = _put_file_once(client, "bucket", "key", archive, digest, "application/x-tar")

    assert first == second
    assert client.put_calls[0]["ServerSideEncryption"] == "AES256"
    assert client.put_calls[0]["IfNoneMatch"] == "*"


def test_s3_retry_rejects_different_existing_content(tmp_path: Path) -> None:
    client = _FakeLockedS3()
    client.objects["key"] = b"older unexpected bytes"
    archive = tmp_path / "backup.tar"
    archive.write_bytes(b"new bytes")

    with pytest.raises(TemporalBackupError, match="length|checksum"):
        _put_file_once(
            client,
            "bucket",
            "key",
            archive,
            hashlib.sha256(archive.read_bytes()).hexdigest(),
            "application/x-tar",
        )


def test_signature_sidecar_upload_is_content_idempotent() -> None:
    client = _FakeLockedS3()

    first = _put_bytes_once(client, "bucket", "key.sig.json", b"signed", "application/json")
    second = _put_bytes_once(client, "bucket", "key.sig.json", b"signed", "application/json")

    assert first == second


def test_live_boundary_proof_requires_overwrite_and_delete_denials() -> None:
    client = _FakeLockedS3()
    receipt = BackupReceipt(
        schema_version=1,
        backup_id="temporal-20260806T115500Z",
        created_at="2026-08-06T11:55:00+00:00",
        uploaded_at="2026-08-06T12:00:00+00:00",
        bucket="bucket",
        object_key="key",
        version_id="immutable-version-1",
        archive_sha256="0" * 64,
        archive_size=1,
        server_side_encryption="AES256",
        retention_mode="GOVERNANCE",
        retention_until="2026-09-05T12:00:00+00:00",
        signature_object_key="key.sig.json",
        signature_version_id="immutable-version-2",
        signer_key_id=KEY_ID,
    )
    client.objects["key"] = b"x"

    proof = _prove_write_once_boundary(client, "bucket", receipt)

    assert proof == {
        "tested": True,
        "overwrite": "PreconditionFailed",
        "delete": "AccessDenied",
        "governance_bypass": "AccessDenied",
    }

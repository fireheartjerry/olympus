"""Upload, attest, retrieve, and verify immutable off-host Temporal backups."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from olympus.audit_export.signing import KmsEd25519Signer
from olympus.audit_export.store import S3ObjectLockStore
from olympus.audit_export.trust import load_keyring
from olympus.backup.temporal import (
    BACKUP_FORMAT_VERSION,
    BackupReceipt,
    StoredBackupIdentity,
    TemporalBackupError,
    build_attestation,
    create_archive,
    latest_backup,
    load_receipt,
    save_receipt,
    sign_backup,
    verify_and_extract,
)
from olympus.gateway.production_settings import ProductionGatewaySettings

OWNER_ONLY_MODE = stat.S_IRUSR | stat.S_IWUSR
DEFAULT_PRESIGN_SECONDS = 900


def _aws_clients(settings: ProductionGatewaySettings) -> tuple[Any, Any]:
    try:
        import boto3
    except ImportError as exc:
        raise TemporalBackupError("off-host upload requires the 'aws' package extra") from exc
    session = boto3.Session(
        profile_name=settings.audit_export_profile,
        region_name=settings.audit_export_region,
    )
    return session.client("s3"), session.client("kms")


def _backup_root() -> Path:
    configured = os.getenv("FIRE_POSTGRES_BACKUP_DIR") or os.getenv("OLYMPUS_POSTGRES_BACKUP_DIR")
    root = Path(configured) if configured else Path.home() / "olympus-backups"
    resolved = root.resolve()
    home = Path.home().resolve()
    if resolved == home or home not in resolved.parents:
        raise TemporalBackupError("backup root must remain beneath the runtime user's home")
    return resolved


async def upload(
    *, backup_dir: Path, prove_boundary: bool = False
) -> tuple[BackupReceipt, Path, dict[str, object]]:
    settings = ProductionGatewaySettings()
    bucket = settings.audit_export_bucket
    key_id = settings.audit_export_kms_key_id
    if bucket is None or key_id is None:
        raise TemporalBackupError("immutable object storage and KMS signing are not configured")
    s3, kms = _aws_clients(settings)
    store = S3ObjectLockStore(
        bucket=bucket,
        client=s3,
        expected_retention_days=settings.audit_export_retention_days,
        expected_retention_mode=settings.audit_export_retention_mode,
    )
    mode, days = await store.assert_retention_configured()

    root = _backup_root()
    receipt_root = root / "offhost-receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    os.chmod(receipt_root, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="temporal-offhost-", suffix=".tar", dir=root
    )
    os.close(descriptor)
    temporary_archive = Path(temporary_name)
    await asyncio.to_thread(temporary_archive.unlink)
    try:
        digest, size, backup_id, created_at = create_archive(backup_dir, temporary_archive)
        stamp = datetime.fromisoformat(created_at)
        object_key = f"backups/temporal/{stamp:%Y/%m/%d}/{backup_id}.tar"
        archive_identity = await asyncio.to_thread(
            _put_file_once,
            s3,
            bucket,
            object_key,
            temporary_archive,
            digest,
            "application/x-tar",
        )
        if archive_identity.retention_mode != mode:
            raise TemporalBackupError("stored backup retention mode differs from bucket policy")
        retain_until = datetime.fromisoformat(archive_identity.retention_until)
        if retain_until < datetime.now(UTC) + timedelta(days=days - 1):
            raise TemporalBackupError("stored backup retention is shorter than the verified policy")

        signer = KmsEd25519Signer(key_id=key_id, client=kms)
        # The retention timestamp is observed from the immutable object and is
        # stable across retries. Deriving the signing time from it keeps the
        # Ed25519 sidecar byte-identical if a process crashes after PutObject.
        observed_upload_time = retain_until - timedelta(days=days)
        attestation = build_attestation(
            backup_id=backup_id,
            created_at=created_at,
            identity=archive_identity,
            bucket=bucket,
            signer_key_id=key_id,
            signed_at=observed_upload_time,
        )
        sidecar = await sign_backup(attestation, signer)
        signature_key = f"{object_key}.sig.json"
        signature_identity = await asyncio.to_thread(
            _put_bytes_once,
            s3,
            bucket,
            signature_key,
            sidecar,
            "application/json",
        )
        if signature_identity.retention_mode != mode:
            raise TemporalBackupError("signature sidecar is not under the expected retention mode")
        if datetime.fromisoformat(signature_identity.retention_until) < retain_until:
            raise TemporalBackupError(
                "signature sidecar expires before the backup it authenticates"
            )

        receipt = BackupReceipt(
            schema_version=BACKUP_FORMAT_VERSION,
            backup_id=backup_id,
            created_at=created_at,
            uploaded_at=datetime.now(UTC).isoformat(),
            bucket=bucket,
            object_key=object_key,
            version_id=archive_identity.version_id,
            archive_sha256=digest,
            archive_size=size,
            server_side_encryption=archive_identity.server_side_encryption,
            retention_mode=archive_identity.retention_mode,
            retention_until=archive_identity.retention_until,
            signature_object_key=signature_key,
            signature_version_id=signature_identity.version_id,
            signer_key_id=key_id,
        )
        receipt_path = receipt_root / f"{backup_id}.json"
        save_receipt(receipt_path, receipt)
        boundary: dict[str, object] = (
            await asyncio.to_thread(_prove_write_once_boundary, s3, bucket, receipt)
            if prove_boundary
            else {"tested": False}
        )
        return receipt, receipt_path, boundary
    finally:
        await asyncio.to_thread(temporary_archive.unlink, missing_ok=True)


def presign(receipt: BackupReceipt, output: Path, *, expires_seconds: int) -> None:
    if not 60 <= expires_seconds <= 3600:
        raise TemporalBackupError("presigned recovery links must last between 60 and 3600 seconds")
    settings = ProductionGatewaySettings()
    s3, _ = _aws_clients(settings)
    if receipt.bucket != settings.audit_export_bucket:
        raise TemporalBackupError("receipt names a bucket outside this recovery configuration")
    archive_url = s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": receipt.bucket,
            "Key": receipt.object_key,
            "VersionId": receipt.version_id,
        },
        ExpiresIn=expires_seconds,
    )
    signature_url = s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": receipt.bucket,
            "Key": receipt.signature_object_key,
            "VersionId": receipt.signature_version_id,
        },
        ExpiresIn=expires_seconds,
    )
    document = {
        "schema_version": 1,
        "expires_at": (datetime.now(UTC) + timedelta(seconds=expires_seconds)).isoformat(),
        "receipt": receipt.to_mapping(),
        "archive_url": archive_url,
        "signature_url": signature_url,
    }
    _atomic_secret_json(output, document)


def _put_file_once(
    client: Any,
    bucket: str,
    key: str,
    path: Path,
    sha256: str,
    content_type: str,
) -> StoredBackupIdentity:
    try:
        with path.open("rb") as body:
            response = client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentLength=path.stat().st_size,
                ContentType=content_type,
                ChecksumSHA256=base64.b64encode(bytes.fromhex(sha256)).decode("ascii"),
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
    except Exception as exc:  # noqa: BLE001 - translated into content-idempotence
        if _error_code(exc) not in {"PreconditionFailed", "412"}:
            raise
        return _head_identity(client, bucket, key, sha256, path.stat().st_size)
    expected_checksum = base64.b64encode(bytes.fromhex(sha256)).decode("ascii")
    if response.get("ChecksumSHA256") not in {None, expected_checksum}:
        raise TemporalBackupError("S3 returned a different checksum for the uploaded backup")
    return _head_identity(client, bucket, key, sha256, path.stat().st_size)


def _put_bytes_once(
    client: Any, bucket: str, key: str, body: bytes, content_type: str
) -> StoredBackupIdentity:
    digest = hashlib.sha256(body).hexdigest()
    try:
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentLength=len(body),
            ContentType=content_type,
            ChecksumSHA256=base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
            ServerSideEncryption="AES256",
            IfNoneMatch="*",
        )
    except Exception as exc:  # noqa: BLE001 - translated into content-idempotence
        if _error_code(exc) not in {"PreconditionFailed", "412"}:
            raise
    return _head_identity(client, bucket, key, digest, len(body))


def _head_identity(
    client: Any, bucket: str, key: str, expected_sha256: str, expected_size: int
) -> StoredBackupIdentity:
    response = client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    if int(response.get("ContentLength", -1)) != expected_size:
        raise TemporalBackupError("stored backup length differs from the uploaded archive")
    checksum = str(response.get("ChecksumSHA256") or "")
    expected_checksum = base64.b64encode(bytes.fromhex(expected_sha256)).decode("ascii")
    if checksum != expected_checksum:
        raise TemporalBackupError("stored backup checksum differs from the uploaded archive")
    encryption = str(response.get("ServerSideEncryption") or "")
    if encryption != "AES256":
        raise TemporalBackupError("stored backup is not explicitly encrypted with SSE-S3")
    retain_until = response.get("ObjectLockRetainUntilDate")
    if not isinstance(retain_until, datetime):
        raise TemporalBackupError("stored backup has no Object Lock retention timestamp")
    version_id = str(response.get("VersionId") or "")
    if not version_id:
        raise TemporalBackupError("stored backup has no immutable object version")
    return StoredBackupIdentity(
        object_key=key,
        version_id=version_id,
        sha256=expected_sha256,
        size=expected_size,
        server_side_encryption=encryption,
        retention_mode=str(response.get("ObjectLockMode") or ""),
        retention_until=retain_until.isoformat(),
    )


def _prove_write_once_boundary(
    client: Any, bucket: str, receipt: BackupReceipt
) -> dict[str, object]:
    outcomes: dict[str, str] = {}
    calls: dict[str, Callable[[], object]] = {
        "overwrite": lambda: client.put_object(
            Bucket=bucket,
            Key=receipt.object_key,
            Body=b"forbidden replacement",
            ServerSideEncryption="AES256",
            IfNoneMatch="*",
        ),
        "delete": lambda: client.delete_object(
            Bucket=bucket,
            Key=receipt.object_key,
            VersionId=receipt.version_id,
        ),
        "governance_bypass": lambda: client.delete_object(
            Bucket=bucket,
            Key=receipt.object_key,
            VersionId=receipt.version_id,
            BypassGovernanceRetention=True,
        ),
    }
    for name, call in calls.items():
        try:
            call()
        except Exception as exc:  # noqa: BLE001 - this is an authorization proof
            code = _error_code(exc)
            if code not in {"AccessDenied", "PreconditionFailed", "412"}:
                raise TemporalBackupError(
                    f"{name} failed for an unexpected reason: {code}"
                ) from exc
            outcomes[name] = code
        else:
            raise TemporalBackupError(f"immutable backup boundary allowed {name}")
    return {"tested": True, **outcomes}


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return type(exc).__name__


def _atomic_secret_json(path: Path, value: object) -> None:
    if path.exists():
        raise TemporalBackupError(f"refusing to replace secret handoff {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, OWNER_ONLY_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    upload_command = commands.add_parser("upload")
    source = upload_command.add_mutually_exclusive_group(required=True)
    source.add_argument("--latest", action="store_true")
    source.add_argument("--backup-dir", type=Path)
    upload_command.add_argument("--prove-boundary", action="store_true")

    presign_command = commands.add_parser("presign")
    presign_command.add_argument("--receipt", type=Path, required=True)
    presign_command.add_argument("--output", type=Path, required=True)
    presign_command.add_argument("--expires-seconds", type=int, default=DEFAULT_PRESIGN_SECONDS)

    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--receipt", type=Path, required=True)
    verify_command.add_argument("--archive", type=Path, required=True)
    verify_command.add_argument("--signature", type=Path, required=True)
    verify_command.add_argument("--extract", type=Path, required=True)
    return parser


async def _run(arguments: argparse.Namespace) -> int:
    if arguments.command == "upload":
        root = _backup_root()
        if arguments.latest:
            backup_dir = latest_backup(root)
        elif isinstance(arguments.backup_dir, Path):
            backup_dir = arguments.backup_dir.resolve()
        else:  # argparse enforces this; keep the authority boundary explicit.
            raise TemporalBackupError("a backup source is required")
        receipt, receipt_path, boundary = await upload(
            backup_dir=backup_dir, prove_boundary=arguments.prove_boundary
        )
        print(
            json.dumps(
                {
                    "backup_id": receipt.backup_id,
                    "receipt": str(receipt_path),
                    "encrypted": receipt.server_side_encryption,
                    "retention_mode": receipt.retention_mode,
                    "retention_until": receipt.retention_until,
                    "boundary": boundary,
                },
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "presign":
        presign(
            load_receipt(arguments.receipt),
            arguments.output,
            expires_seconds=arguments.expires_seconds,
        )
        print("protected presigned recovery handoff created")
        return 0
    if arguments.command == "verify":
        receipt = load_receipt(arguments.receipt)
        attestation = verify_and_extract(
            archive_path=arguments.archive,
            signature_path=arguments.signature,
            receipt=receipt,
            keyring=load_keyring(),
            output_dir=arguments.extract,
        )
        print(
            json.dumps(
                {
                    "backup_id": attestation.backup_id,
                    "archive_sha256": attestation.archive_sha256,
                    "signature": "verified-pinned-ed25519",
                    "encrypted": attestation.server_side_encryption,
                    "retention_mode": attestation.retention_mode,
                    "extracted": str(arguments.extract),
                },
                sort_keys=True,
            )
        )
        return 0
    raise TemporalBackupError("unknown backup command")


def main() -> int:
    try:
        return asyncio.run(_run(_parser().parse_args()))
    except (OSError, TemporalBackupError, ValueError) as exc:
        print(f"off-host Temporal backup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

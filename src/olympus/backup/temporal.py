from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from olympus.audit_export.signing import Keyring

BACKUP_FORMAT_VERSION = 1
ATTESTATION_SCHEMA_VERSION = 1
SIGNING_ALGORITHM = "ED25519_SHA_512"
ATTESTATION_CONTEXT = b"fire-temporal-backup-attestation-v1"
EXPECTED_ARCHIVE_MEMBERS = frozenset(
    {"BACKUP.json", "SHA256SUMS", "temporal.dump", "temporal_visibility.dump"}
)
BACKUP_ID_PATTERN = re.compile(r"temporal-(?P<stamp>[0-9]{8}T[0-9]{6}Z)")
OWNER_ONLY_MODE = stat.S_IRUSR | stat.S_IWUSR


class TemporalBackupError(RuntimeError):
    """A backup cannot be safely created, trusted, or restored."""


class BackupSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    async def sign(self, statement: bytes) -> bytes: ...


@dataclass(frozen=True)
class BackupAttestation:
    schema_version: int
    backup_id: str
    created_at: str
    archive_sha256: str
    archive_size: int
    bucket: str
    object_key: str
    version_id: str
    server_side_encryption: str
    retention_mode: str
    retention_until: str
    signer_key_id: str
    signed_at: str

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "archive_sha256": self.archive_sha256,
            "archive_size": self.archive_size,
            "bucket": self.bucket,
            "object_key": self.object_key,
            "version_id": self.version_id,
            "server_side_encryption": self.server_side_encryption,
            "retention_mode": self.retention_mode,
            "retention_until": self.retention_until,
            "signer_key_id": self.signer_key_id,
            "signed_at": self.signed_at,
        }

    def statement(self) -> bytes:
        body = json.dumps(
            self.to_mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        return ATTESTATION_CONTEXT + b"\n" + body

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> BackupAttestation:
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise TemporalBackupError("backup attestation fields do not match the schema")
        try:
            result = cls(
                schema_version=_required_int(value["schema_version"]),
                backup_id=str(value["backup_id"]),
                created_at=str(value["created_at"]),
                archive_sha256=str(value["archive_sha256"]),
                archive_size=_required_int(value["archive_size"]),
                bucket=str(value["bucket"]),
                object_key=str(value["object_key"]),
                version_id=str(value["version_id"]),
                server_side_encryption=str(value["server_side_encryption"]),
                retention_mode=str(value["retention_mode"]),
                retention_until=str(value["retention_until"]),
                signer_key_id=str(value["signer_key_id"]),
                signed_at=str(value["signed_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TemporalBackupError("backup attestation contains an invalid field") from exc
        if result.schema_version != ATTESTATION_SCHEMA_VERSION:
            raise TemporalBackupError("unsupported backup attestation schema")
        _backup_created_at(result.backup_id)
        _aware_timestamp(result.created_at, "created_at")
        _aware_timestamp(result.signed_at, "signed_at")
        _aware_timestamp(result.retention_until, "retention_until")
        if not re.fullmatch(r"[0-9a-f]{64}", result.archive_sha256):
            raise TemporalBackupError("backup attestation has an invalid archive digest")
        if result.archive_size < 1:
            raise TemporalBackupError("backup attestation has an invalid archive size")
        return result


@dataclass(frozen=True)
class SignedBackupAttestation:
    attestation: BackupAttestation
    signature: bytes

    def document(self) -> bytes:
        return json.dumps(
            {
                "schema_version": ATTESTATION_SCHEMA_VERSION,
                "signing_algorithm": SIGNING_ALGORITHM,
                "attestation": self.attestation.to_mapping(),
                "signature": base64.b64encode(self.signature).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> SignedBackupAttestation:
        try:
            document = json.loads(raw)
            if not isinstance(document, dict):
                raise TypeError("not an object")
            if document.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
                raise ValueError("unsupported signature document schema")
            if document.get("signing_algorithm") != SIGNING_ALGORITHM:
                raise ValueError("unsupported signing algorithm")
            mapping = document["attestation"]
            if not isinstance(mapping, dict):
                raise TypeError("attestation is not an object")
            signature = base64.b64decode(str(document["signature"]), validate=True)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise TemporalBackupError("backup signature document is malformed") from exc
        if len(signature) != 64:
            raise TemporalBackupError("backup signature is not Ed25519-sized")
        return cls(BackupAttestation.from_mapping(mapping), signature)


@dataclass(frozen=True)
class StoredBackupIdentity:
    object_key: str
    version_id: str
    sha256: str
    size: int
    server_side_encryption: str
    retention_mode: str
    retention_until: str


@dataclass(frozen=True)
class BackupReceipt:
    schema_version: int
    backup_id: str
    created_at: str
    uploaded_at: str
    bucket: str
    object_key: str
    version_id: str
    archive_sha256: str
    archive_size: int
    server_side_encryption: str
    retention_mode: str
    retention_until: str
    signature_object_key: str
    signature_version_id: str
    signer_key_id: str

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "uploaded_at": self.uploaded_at,
            "bucket": self.bucket,
            "object_key": self.object_key,
            "version_id": self.version_id,
            "archive_sha256": self.archive_sha256,
            "archive_size": self.archive_size,
            "server_side_encryption": self.server_side_encryption,
            "retention_mode": self.retention_mode,
            "retention_until": self.retention_until,
            "signature_object_key": self.signature_object_key,
            "signature_version_id": self.signature_version_id,
            "signer_key_id": self.signer_key_id,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> BackupReceipt:
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise TemporalBackupError("backup receipt fields do not match the schema")
        try:
            receipt = cls(
                schema_version=_required_int(value["schema_version"]),
                backup_id=str(value["backup_id"]),
                created_at=str(value["created_at"]),
                uploaded_at=str(value["uploaded_at"]),
                bucket=str(value["bucket"]),
                object_key=str(value["object_key"]),
                version_id=str(value["version_id"]),
                archive_sha256=str(value["archive_sha256"]),
                archive_size=_required_int(value["archive_size"]),
                server_side_encryption=str(value["server_side_encryption"]),
                retention_mode=str(value["retention_mode"]),
                retention_until=str(value["retention_until"]),
                signature_object_key=str(value["signature_object_key"]),
                signature_version_id=str(value["signature_version_id"]),
                signer_key_id=str(value["signer_key_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TemporalBackupError("backup receipt contains an invalid field") from exc
        if receipt.schema_version != BACKUP_FORMAT_VERSION:
            raise TemporalBackupError("unsupported backup receipt schema")
        _backup_created_at(receipt.backup_id)
        _aware_timestamp(receipt.created_at, "created_at")
        _aware_timestamp(receipt.uploaded_at, "uploaded_at")
        _aware_timestamp(receipt.retention_until, "retention_until")
        if not re.fullmatch(r"[0-9a-f]{64}", receipt.archive_sha256):
            raise TemporalBackupError("backup receipt has an invalid archive digest")
        if receipt.archive_size < 1:
            raise TemporalBackupError("backup receipt has an invalid archive size")
        return receipt


def load_receipt(path: Path) -> BackupReceipt:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TemporalBackupError("backup receipt is unreadable") from exc
    if not isinstance(document, dict):
        raise TemporalBackupError("backup receipt is not an object")
    return BackupReceipt.from_mapping(document)


def save_receipt(path: Path, receipt: BackupReceipt) -> None:
    _atomic_owner_only_json(path, receipt.to_mapping())


def latest_backup(root: Path) -> Path:
    candidates = sorted(
        path
        for path in root.glob("temporal-????????T??????Z")
        if path.is_dir() and not path.is_symlink() and BACKUP_ID_PATTERN.fullmatch(path.name)
    )
    if not candidates:
        raise TemporalBackupError(f"no complete Temporal backup exists under {root}")
    return candidates[-1]


def create_archive(backup_dir: Path, archive_path: Path) -> tuple[str, int, str, str]:
    backup_id = backup_dir.name
    created_at = _backup_created_at(backup_id).isoformat()
    checksums = _verify_source_backup(backup_dir)
    manifest = {
        "schema_version": BACKUP_FORMAT_VERSION,
        "backup_id": backup_id,
        "created_at": created_at,
        "files": {
            name: {"sha256": checksums[name], "size": (backup_dir / name).stat().st_size}
            for name in ("temporal.dump", "temporal_visibility.dump")
        },
    }
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists():
        raise TemporalBackupError(f"refusing to replace existing archive {archive_path}")
    manifest_body = _canonical_json(manifest) + b"\n"
    timestamp = int(_backup_created_at(backup_id).timestamp())
    with tarfile.open(archive_path, mode="x") as archive:
        _add_bytes(archive, "BACKUP.json", manifest_body, timestamp)
        for name in ("SHA256SUMS", "temporal.dump", "temporal_visibility.dump"):
            _add_file(archive, backup_dir / name, name, timestamp)
    os.chmod(archive_path, OWNER_ONLY_MODE)
    return _sha256_file(archive_path), archive_path.stat().st_size, backup_id, created_at


def verify_and_extract(
    *,
    archive_path: Path,
    signature_path: Path,
    receipt: BackupReceipt,
    keyring: Keyring,
    output_dir: Path,
) -> BackupAttestation:
    try:
        signed = SignedBackupAttestation.from_bytes(signature_path.read_bytes())
        archive_size = archive_path.stat().st_size
    except OSError as exc:
        raise TemporalBackupError("downloaded recovery material is unreadable") from exc
    attestation = signed.attestation
    comparisons = {
        "backup_id": receipt.backup_id,
        "created_at": receipt.created_at,
        "bucket": receipt.bucket,
        "object_key": receipt.object_key,
        "version_id": receipt.version_id,
        "archive_sha256": receipt.archive_sha256,
        "archive_size": receipt.archive_size,
        "server_side_encryption": receipt.server_side_encryption,
        "retention_mode": receipt.retention_mode,
        "retention_until": receipt.retention_until,
        "signer_key_id": receipt.signer_key_id,
    }
    if any(getattr(attestation, name) != expected for name, expected in comparisons.items()):
        raise TemporalBackupError("receipt does not match the signed backup identity")
    if archive_size != attestation.archive_size:
        raise TemporalBackupError("downloaded backup size does not match its attestation")
    if _sha256_file(archive_path) != attestation.archive_sha256:
        raise TemporalBackupError("downloaded backup digest does not match its attestation")

    signer = keyring.resolve(attestation.signer_key_id)
    signed_at = _aware_timestamp(attestation.signed_at, "signed_at")
    signer.assert_trusted_at(signed_at)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    public_key = load_der_public_key(signer.public_key_der)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TemporalBackupError("pinned backup signer is not an Ed25519 key")
    try:
        public_key.verify(signed.signature, attestation.statement())
    except InvalidSignature as exc:
        raise TemporalBackupError("backup signature does not verify") from exc

    if output_dir.exists():
        raise TemporalBackupError("restore output directory must not already exist")
    output_dir.mkdir(parents=True, mode=0o700)
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            members = archive.getmembers()
            if {member.name for member in members} != EXPECTED_ARCHIVE_MEMBERS:
                raise TemporalBackupError("backup archive has unexpected members")
            if any(
                not member.isfile()
                or member.name.startswith(("/", "\\"))
                or ".." in Path(member.name).parts
                for member in members
            ):
                raise TemporalBackupError(
                    "backup archive contains a non-regular or absolute member"
                )
            for member in members:
                source = archive.extractfile(member)
                if source is None:
                    raise TemporalBackupError("backup archive member is unreadable")
                target = output_dir / member.name
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, OWNER_ONLY_MODE)
                with os.fdopen(descriptor, "wb") as destination:
                    while chunk := source.read(1024 * 1024):
                        destination.write(chunk)
        _verify_source_backup(output_dir)
        manifest = json.loads((output_dir / "BACKUP.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("backup_id") != receipt.backup_id:
            raise TemporalBackupError("archive manifest names a different backup")
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        for child in output_dir.iterdir():
            child.unlink(missing_ok=True)
        output_dir.rmdir()
        raise TemporalBackupError("backup archive cannot be safely extracted") from exc
    except Exception:
        for child in output_dir.iterdir():
            child.unlink(missing_ok=True)
        output_dir.rmdir()
        raise
    return attestation


async def sign_backup(attestation: BackupAttestation, signer: BackupSigner) -> bytes:
    if signer.key_id != attestation.signer_key_id:
        raise TemporalBackupError("backup attestation names a different signer")
    signature = await signer.sign(attestation.statement())
    if len(signature) != 64:
        raise TemporalBackupError("backup signer returned a non-Ed25519 signature")
    return SignedBackupAttestation(attestation, signature).document()


def build_attestation(
    *,
    backup_id: str,
    created_at: str,
    identity: StoredBackupIdentity,
    bucket: str,
    signer_key_id: str,
    signed_at: datetime,
) -> BackupAttestation:
    if signed_at.tzinfo is None:
        raise ValueError("signed_at must be timezone-aware")
    return BackupAttestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        backup_id=backup_id,
        created_at=created_at,
        archive_sha256=identity.sha256,
        archive_size=identity.size,
        bucket=bucket,
        object_key=identity.object_key,
        version_id=identity.version_id,
        server_side_encryption=identity.server_side_encryption,
        retention_mode=identity.retention_mode,
        retention_until=identity.retention_until,
        signer_key_id=signer_key_id,
        signed_at=signed_at.astimezone(UTC).isoformat(),
    )


def _verify_source_backup(directory: Path) -> dict[str, str]:
    expected_files = {"temporal.dump", "temporal_visibility.dump"}
    try:
        lines = (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise TemporalBackupError("backup checksum manifest is unreadable") from exc
    checksums: dict[str, str] = {}
    for line in lines:
        digest, separator, name = line.partition("  ")
        if not separator or name not in expected_files or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise TemporalBackupError("backup checksum manifest is malformed")
        if name in checksums:
            raise TemporalBackupError("backup checksum manifest repeats a file")
        checksums[name] = digest
    if set(checksums) != expected_files:
        raise TemporalBackupError("backup checksum manifest is incomplete")
    for name, expected in checksums.items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or _sha256_file(path) != expected:
            raise TemporalBackupError(f"backup file {name} fails checksum verification")
    return checksums


def _backup_created_at(backup_id: str) -> datetime:
    match = BACKUP_ID_PATTERN.fullmatch(backup_id)
    if match is None:
        raise TemporalBackupError("backup directory has a non-canonical identifier")
    return datetime.strptime(match.group("stamp"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def _aware_timestamp(value: str, field: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TemporalBackupError(f"{field} is not an ISO-8601 timestamp") from exc
    if result.tzinfo is None:
        raise TemporalBackupError(f"{field} must be timezone-aware")
    return result


def _required_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str, bytes, bytearray)):
        raise TypeError("integer field has an unsupported type")
    return int(value)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _add_bytes(archive: tarfile.TarFile, name: str, body: bytes, mtime: int) -> None:
    import io

    info = tarfile.TarInfo(name)
    info.size = len(body)
    info.mtime = mtime
    info.mode = 0o600
    archive.addfile(info, io.BytesIO(body))


def _add_file(archive: tarfile.TarFile, source: Path, name: str, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = source.stat().st_size
    info.mtime = mtime
    info.mode = 0o600
    with source.open("rb") as body:
        archive.addfile(info, body)


def _atomic_owner_only_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_bytes(_canonical_json(value) + b"\n")
    os.chmod(temporary, OWNER_ONLY_MODE)
    temporary.replace(path)

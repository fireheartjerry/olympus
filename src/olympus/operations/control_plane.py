import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import uuid4

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox


class BackupCorrupt(RuntimeError):
    pass


class ControlPlaneMode(StrEnum):
    NORMAL = "normal"
    CONSTRAINED = "constrained"
    DEGRADED = "degraded"
    SURVIVAL = "survival"


@dataclass(frozen=True)
class ControlPlaneSample:
    cpu_percent: int
    memory_percent: int
    disk_percent: int
    postgresql_ready: bool
    temporal_ready: bool

    def __post_init__(self) -> None:
        if any(
            value < 0 or value > 100
            for value in (self.cpu_percent, self.memory_percent, self.disk_percent)
        ):
            raise ValueError("control-plane utilization must be a percentage")


def evaluate_control_plane(sample: ControlPlaneSample) -> ControlPlaneMode:
    if not sample.postgresql_ready or not sample.temporal_ready or sample.disk_percent >= 85:
        return ControlPlaneMode.SURVIVAL
    if sample.cpu_percent >= 90 or sample.memory_percent >= 85 or sample.disk_percent >= 70:
        return ControlPlaneMode.DEGRADED
    if sample.cpu_percent >= 80 or sample.memory_percent >= 75 or sample.disk_percent >= 60:
        return ControlPlaneMode.CONSTRAINED
    return ControlPlaneMode.NORMAL


@dataclass(frozen=True)
class EncryptedBackup:
    backup_id: str
    created_at: datetime
    ciphertext: bytes
    plaintext_digest: str


class EncryptedBackupStore:
    def __init__(self, *, encryption_key: bytes, maximum_rpo: timedelta) -> None:
        if len(encryption_key) != SecretBox.KEY_SIZE:
            raise ValueError("backup encryption key must be exactly 32 bytes")
        if maximum_rpo <= timedelta(0):
            raise ValueError("maximum RPO must be positive")
        self._box = SecretBox(encryption_key)
        self._maximum_rpo = maximum_rpo

    def create(
        self,
        snapshot: dict[str, bytes],
        *,
        created_at: datetime,
    ) -> EncryptedBackup:
        _require_aware(created_at, "created_at")
        if not snapshot or any(not key.strip() for key in snapshot):
            raise ValueError("backup snapshot must contain named canonical stores")
        plaintext = _encode_snapshot(snapshot)
        return EncryptedBackup(
            backup_id=f"backup-{uuid4()}",
            created_at=created_at,
            ciphertext=bytes(self._box.encrypt(plaintext)),
            plaintext_digest=hashlib.sha256(plaintext).hexdigest(),
        )

    def restore(self, backup: EncryptedBackup, *, now: datetime) -> dict[str, bytes]:
        _require_aware(now, "now")
        age = now - backup.created_at
        if age < timedelta(0) or age > self._maximum_rpo:
            raise BackupCorrupt("backup is outside the required RPO")
        try:
            plaintext = self._box.decrypt(backup.ciphertext)
        except CryptoError as exc:
            raise BackupCorrupt("backup authentication failed") from exc
        if hashlib.sha256(plaintext).hexdigest() != backup.plaintext_digest:
            raise BackupCorrupt("backup plaintext digest does not match")
        return _decode_snapshot(plaintext)


def _encode_snapshot(snapshot: dict[str, bytes]) -> bytes:
    encoded = {
        key: base64.b64encode(value).decode("ascii") for key, value in sorted(snapshot.items())
    }
    return json.dumps(encoded, sort_keys=True, separators=(",", ":")).encode()


def _decode_snapshot(plaintext: bytes) -> dict[str, bytes]:
    try:
        encoded = json.loads(plaintext)
        if not isinstance(encoded, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in encoded.items()
        ):
            raise TypeError
        return {key: base64.b64decode(value, validate=True) for key, value in encoded.items()}
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise BackupCorrupt("backup payload cannot be decoded") from exc


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

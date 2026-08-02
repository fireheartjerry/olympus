import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast


class InvalidEmergencyLatch(RuntimeError):
    """Raised when the emergency latch or its recovery proof is invalid."""


class FreezeReason(StrEnum):
    OPERATOR_REQUEST = "operator-request"
    ANOMALY = "anomaly"
    AUTHORITY_INCONSISTENCY = "authority-inconsistency"


@dataclass(frozen=True)
class CanonicalRecoveryProof:
    recovery_id: str
    authority_epoch: int
    freeze_epoch: int
    repository_proof: bytes

    def __post_init__(self) -> None:
        if not self.recovery_id.strip():
            raise ValueError("recovery_id must not be empty")
        if self.authority_epoch < 1 or self.freeze_epoch < 1:
            raise ValueError("recovery epochs must be strictly positive")
        if not self.repository_proof:
            raise ValueError("repository_proof must not be empty")


class LatchSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...


class LatchVerifier(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> bool: ...

    def verify_recovery(self, proof: CanonicalRecoveryProof) -> bool: ...


class EmergencyFreezeLatch:
    def __init__(
        self,
        *,
        path: Path,
        signer: LatchSigner,
        verifier: LatchVerifier,
    ) -> None:
        if not path.is_absolute():
            raise ValueError("emergency latch path must be absolute")
        self._path = path
        self._signer = signer
        self._verifier = verifier

    def is_set(self) -> bool:
        if not self._path.exists():
            return False
        envelope = self._read_envelope()
        payload = envelope.get("payload")
        if not isinstance(payload, dict) or payload.get("state") != "frozen":
            raise InvalidEmergencyLatch("emergency latch payload is invalid")
        return True

    def set(self, request_id: str, reason: FreezeReason, now: datetime) -> None:
        if self._path.exists():
            if not self.is_set():
                raise InvalidEmergencyLatch("emergency latch is not frozen")
            return
        if not request_id.strip():
            raise ValueError("freeze request_id must not be empty")
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("freeze timestamp must be timezone-aware")
        self._write_envelope(
            {
                "version": 1,
                "state": "frozen",
                "request_id": request_id,
                "reason": reason.value,
                "set_at": now.isoformat(),
            }
        )

    def reconcile_and_clear(self, proof: CanonicalRecoveryProof) -> None:
        if not self._verifier.verify_recovery(proof):
            raise InvalidEmergencyLatch("repository recovery proof is invalid")
        if not self.is_set():
            return
        self._path.unlink()
        self._fsync_directory()

    def _read_envelope(self) -> dict[str, object]:
        try:
            envelope = json.loads(self._path.read_bytes())
            payload = envelope["payload"]
            signature_hex = envelope["signature"]
            if not isinstance(payload, dict) or not isinstance(signature_hex, str):
                raise TypeError
            payload_bytes = _canonical_json(payload)
            signature = bytes.fromhex(signature_hex)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise InvalidEmergencyLatch("emergency latch cannot be decoded") from exc
        if not self._verifier.verify(payload_bytes, signature):
            raise InvalidEmergencyLatch("emergency latch signature is invalid")
        return cast(dict[str, object], envelope)

    def _write_envelope(self, payload: dict[str, object]) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload_bytes = _canonical_json(payload)
        envelope = _canonical_json(
            {
                "payload": payload,
                "signature": self._signer.sign(payload_bytes).hex(),
            }
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self._path.name}.",
            dir=self._path.parent,
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as temporary_file:
                descriptor = -1
                temporary_file.write(envelope)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, self._path)
            self._fsync_directory()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)

    def _fsync_directory(self) -> None:
        directory_descriptor = os.open(self._path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

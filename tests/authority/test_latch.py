import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from olympus.authority.latch import (
    CanonicalRecoveryProof,
    EmergencyFreezeLatch,
    FreezeReason,
    InvalidEmergencyLatch,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)


class Ed25519TestSigner:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload).signature

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._key.verify_key.verify(payload, signature)
        except Exception:
            return False
        return True

    def verify_recovery(self, proof: CanonicalRecoveryProof) -> bool:
        return proof.repository_proof == b"repository-issued-proof"


def make_latch(path: Path) -> EmergencyFreezeLatch:
    signer = Ed25519TestSigner()
    return EmergencyFreezeLatch(path=path, signer=signer, verifier=signer)


def test_set_is_atomic_restrictive_and_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "freeze.json"
    latch = make_latch(path)

    latch.set("freeze-1", FreezeReason.OPERATOR_REQUEST, NOW)
    first = path.read_bytes()
    latch.set("freeze-2", FreezeReason.ANOMALY, NOW)

    assert latch.is_set()
    assert path.read_bytes() == first
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert list(tmp_path.iterdir()) == [path]


def test_tampered_latch_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "freeze.json"
    latch = make_latch(path)
    latch.set("freeze-1", FreezeReason.OPERATOR_REQUEST, NOW)
    envelope = json.loads(path.read_text())
    envelope["payload"]["request_id"] = "attacker"
    path.write_text(json.dumps(envelope))

    with pytest.raises(InvalidEmergencyLatch):
        latch.is_set()


def test_clear_requires_repository_issued_recovery_proof(tmp_path: Path) -> None:
    path = tmp_path / "freeze.json"
    latch = make_latch(path)
    latch.set("freeze-1", FreezeReason.OPERATOR_REQUEST, NOW)

    with pytest.raises(InvalidEmergencyLatch, match="recovery proof"):
        latch.reconcile_and_clear(
            CanonicalRecoveryProof(
                recovery_id="recovery-1",
                authority_epoch=3,
                freeze_epoch=2,
                repository_proof=b"forged",
            )
        )
    assert latch.is_set()

    latch.reconcile_and_clear(
        CanonicalRecoveryProof(
            recovery_id="recovery-1",
            authority_epoch=3,
            freeze_epoch=2,
            repository_proof=b"repository-issued-proof",
        )
    )
    assert not latch.is_set()


def test_replace_failure_leaves_existing_latch_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "freeze.json"
    latch = make_latch(path)
    latch.set("freeze-1", FreezeReason.OPERATOR_REQUEST, NOW)
    original = path.read_bytes()

    def fail_replace(source: str | Path, destination: str | Path) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="injected"):
        latch._write_envelope(  # noqa: SLF001
            {"version": 1, "state": "frozen", "request_id": "freeze-2"}
        )
    assert path.read_bytes() == original
    assert latch.is_set()

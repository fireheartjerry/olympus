from datetime import UTC, datetime, timedelta

import pytest
from nacl.secret import SecretBox

from olympus.operations.control_plane import (
    BackupCorrupt,
    ControlPlaneMode,
    ControlPlaneSample,
    EncryptedBackupStore,
    evaluate_control_plane,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)


@pytest.mark.parametrize(
    ("sample", "mode"),
    [
        (ControlPlaneSample(40, 50, 40, True, True), ControlPlaneMode.NORMAL),
        (ControlPlaneSample(85, 75, 60, True, True), ControlPlaneMode.CONSTRAINED),
        (ControlPlaneSample(95, 88, 75, True, True), ControlPlaneMode.DEGRADED),
        (ControlPlaneSample(50, 50, 50, False, True), ControlPlaneMode.SURVIVAL),
    ],
)
def test_health_thresholds_preserve_control_plane_priority(
    sample: ControlPlaneSample,
    mode: ControlPlaneMode,
) -> None:
    assert evaluate_control_plane(sample) is mode


def test_encrypted_backup_round_trip_meets_rpo_and_detects_corruption() -> None:
    backups = EncryptedBackupStore(
        encryption_key=b"k" * SecretBox.KEY_SIZE,
        maximum_rpo=timedelta(minutes=15),
    )
    snapshot = {
        "postgresql": b"canonical-db",
        "temporal": b"workflow-history",
        "minio": b"artifact-manifest",
    }

    backup = backups.create(snapshot, created_at=NOW)
    restored = backups.restore(backup, now=NOW + timedelta(minutes=10))

    assert restored == snapshot
    with pytest.raises(BackupCorrupt):
        backups.restore(
            backup.__class__(
                backup_id=backup.backup_id,
                created_at=backup.created_at,
                ciphertext=backup.ciphertext[:-1] + b"x",
                plaintext_digest=backup.plaintext_digest,
            ),
            now=NOW + timedelta(minutes=10),
        )


def test_restore_rejects_backup_outside_rpo() -> None:
    backups = EncryptedBackupStore(
        encryption_key=b"k" * SecretBox.KEY_SIZE,
        maximum_rpo=timedelta(minutes=15),
    )
    backup = backups.create({"postgresql": b"state"}, created_at=NOW)

    with pytest.raises(BackupCorrupt, match="RPO"):
        backups.restore(backup, now=NOW + timedelta(minutes=16))

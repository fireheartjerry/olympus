import pytest

from olympus.persistence.ownership import (
    CanonicalOwner,
    DataOwnershipError,
    DataOwnershipRegistry,
    DatumKind,
    InMemoryArtifactPlane,
)


def test_every_datum_has_one_canonical_owner_and_rebuildable_projections() -> None:
    registry = DataOwnershipRegistry.production_defaults()

    assert registry.owner_of(DatumKind.WORKFLOW_STATE) is CanonicalOwner.TEMPORAL
    assert registry.owner_of(DatumKind.AUTHORITY) is CanonicalOwner.POSTGRESQL
    assert registry.owner_of(DatumKind.ARTIFACT) is CanonicalOwner.MINIO
    assert registry.is_projection_rebuildable("redis-job-cache")
    assert registry.is_projection_rebuildable("pgvector-context-index")


def test_cache_or_index_cannot_be_registered_as_canonical() -> None:
    with pytest.raises(DataOwnershipError, match="derived"):
        DataOwnershipRegistry(
            owners={
                DatumKind.AUTHORITY: CanonicalOwner.REDIS,
                DatumKind.WORKFLOW_STATE: CanonicalOwner.TEMPORAL,
                DatumKind.ARTIFACT: CanonicalOwner.MINIO,
                DatumKind.AUDIT: CanonicalOwner.POSTGRESQL,
                DatumKind.SENSITIVE_CONFIG: CanonicalOwner.SECRETS_BROKER,
            }
        )


def test_artifact_backup_restore_and_corruption_detection() -> None:
    plane = InMemoryArtifactPlane()
    artifact = plane.put(
        job_id="job-1",
        logical_name="report.json",
        content=b'{"result":"ok"}',
        media_type="application/json",
    )
    backup = plane.backup()

    restored = InMemoryArtifactPlane.restore(backup)

    assert restored.get(artifact.digest) == b'{"result":"ok"}'
    corrupted = dict(backup)
    corrupted[artifact.digest] = b"corrupt"
    with pytest.raises(DataOwnershipError, match="digest"):
        InMemoryArtifactPlane.restore(corrupted)


def test_artifacts_are_content_addressed_and_idempotent() -> None:
    plane = InMemoryArtifactPlane()
    first = plane.put("job-1", "result", b"same", "text/plain")
    second = plane.put("job-1", "result-copy", b"same", "text/plain")

    assert first.digest == second.digest
    assert plane.object_count == 1

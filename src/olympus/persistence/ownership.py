import hashlib
from dataclasses import dataclass
from enum import StrEnum


class DataOwnershipError(RuntimeError):
    pass


class DatumKind(StrEnum):
    AUTHORITY = "authority"
    WORKFLOW_STATE = "workflow-state"
    ARTIFACT = "artifact"
    AUDIT = "audit"
    SENSITIVE_CONFIG = "sensitive-config"


class CanonicalOwner(StrEnum):
    POSTGRESQL = "postgresql"
    TEMPORAL = "temporal"
    MINIO = "minio"
    SECRETS_BROKER = "secrets-broker"
    REDIS = "redis"
    PGVECTOR = "pgvector"


class DataOwnershipRegistry:
    _derived_only = {CanonicalOwner.REDIS, CanonicalOwner.PGVECTOR}

    def __init__(
        self,
        *,
        owners: dict[DatumKind, CanonicalOwner],
        projections: frozenset[str] = frozenset(),
    ) -> None:
        if set(owners) != set(DatumKind):
            raise DataOwnershipError("every datum kind must have exactly one canonical owner")
        if set(owners.values()) & self._derived_only:
            raise DataOwnershipError("cache and index stores are derived, never canonical")
        if any(not projection.strip() for projection in projections):
            raise DataOwnershipError("projection identities must not be empty")
        self._owners = dict(owners)
        self._projections = projections

    @classmethod
    def production_defaults(cls) -> "DataOwnershipRegistry":
        return cls(
            owners={
                DatumKind.AUTHORITY: CanonicalOwner.POSTGRESQL,
                DatumKind.WORKFLOW_STATE: CanonicalOwner.TEMPORAL,
                DatumKind.ARTIFACT: CanonicalOwner.MINIO,
                DatumKind.AUDIT: CanonicalOwner.POSTGRESQL,
                DatumKind.SENSITIVE_CONFIG: CanonicalOwner.SECRETS_BROKER,
            },
            projections=frozenset({"redis-job-cache", "pgvector-context-index"}),
        )

    def owner_of(self, datum: DatumKind) -> CanonicalOwner:
        return self._owners[datum]

    def is_projection_rebuildable(self, projection_id: str) -> bool:
        return projection_id in self._projections


@dataclass(frozen=True)
class ArtifactManifest:
    job_id: str
    logical_name: str
    digest: str
    size_bytes: int
    media_type: str


class InMemoryArtifactPlane:
    """A deterministic MinIO contract fake; object bytes remain the canonical datum."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._manifests: list[ArtifactManifest] = []

    @property
    def object_count(self) -> int:
        return len(self._objects)

    def put(
        self,
        job_id: str,
        logical_name: str,
        content: bytes,
        media_type: str,
    ) -> ArtifactManifest:
        if not job_id.strip() or not logical_name.strip() or not media_type.strip():
            raise ValueError("artifact identity and media type are required")
        digest = hashlib.sha256(content).hexdigest()
        self._objects.setdefault(digest, content)
        manifest = ArtifactManifest(
            job_id=job_id,
            logical_name=logical_name,
            digest=digest,
            size_bytes=len(content),
            media_type=media_type,
        )
        self._manifests.append(manifest)
        return manifest

    def get(self, digest: str) -> bytes:
        try:
            content = self._objects[digest]
        except KeyError as exc:
            raise DataOwnershipError("artifact does not exist") from exc
        if hashlib.sha256(content).hexdigest() != digest:
            raise DataOwnershipError("artifact digest verification failed")
        return content

    def backup(self) -> dict[str, bytes]:
        return dict(self._objects)

    @classmethod
    def restore(cls, backup: dict[str, bytes]) -> "InMemoryArtifactPlane":
        plane = cls()
        for digest, content in backup.items():
            if hashlib.sha256(content).hexdigest() != digest:
                raise DataOwnershipError("backup object digest verification failed")
            plane._objects[digest] = content
        return plane

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from olympus.contracts.commands import TrustLabel


class NodePlatform(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


class NodeKind(StrEnum):
    CONTROL_PLANE_HOST = "control-plane-host"
    WORKSTATION = "workstation"
    CLOUD_WORKER = "cloud-worker"


class NodeState(StrEnum):
    PENDING = "pending"
    ONLINE = "online"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class NodeJobStatus(StrEnum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    TIMED_OUT = "timed-out"


TERMINAL_JOB_STATUSES: frozenset[NodeJobStatus] = frozenset(
    {
        NodeJobStatus.SUCCEEDED,
        NodeJobStatus.FAILED,
        NodeJobStatus.CANCELLED,
        NodeJobStatus.REJECTED,
        NodeJobStatus.TIMED_OUT,
    }
)


def _require_aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware timestamp")


@dataclass(frozen=True)
class DispatchAuthority:
    """Who authorized a dispatch, in the shape the authority slice will populate.

    ``authority_epoch`` stays ``None`` until server-side leases exist. It is
    carried now so admission, audit, and workflow payloads do not change shape
    when leases arrive.
    """

    commander_id: str
    authority_lease_id: str
    authority_epoch: int | None = None

    def __post_init__(self) -> None:
        empty = [
            name
            for name, value in (
                ("commander_id", self.commander_id),
                ("authority_lease_id", self.authority_lease_id),
            )
            if type(value) is not str or not value.strip()
        ]
        if empty:
            raise ValueError(f"dispatch authority contains empty fields: {', '.join(empty)}")
        if self.authority_epoch is not None and self.authority_epoch < 1:
            raise ValueError("authority_epoch must be strictly positive")


@dataclass(frozen=True)
class NodeHealthSnapshot:
    """Last self-reported health. Node-reported, therefore untrusted."""

    reported_at: datetime
    active_jobs: int = 0
    cpu_count: int | None = None
    load_average_1m: float | None = None
    memory_total_mib: int | None = None
    memory_available_mib: int | None = None
    uptime_seconds: int | None = None
    agent_uptime_seconds: int | None = None

    def __post_init__(self) -> None:
        _require_aware("reported_at", self.reported_at)
        if self.active_jobs < 0:
            raise ValueError("active_jobs must not be negative")


@dataclass(frozen=True)
class EnrollmentTokenRecord:
    """One single-use enrollment grant. The secret itself is never stored."""

    token_id: str
    secret_hash: str
    node_name: str
    kind: NodeKind
    platform: NodePlatform
    granted_capabilities: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    issued_by: str
    # Scopes bound to this grant at mint time. A capability whose name alone
    # would authorize too much (fs.read) is refused at dispatch when its scope
    # is missing, so an empty mapping never widens anything.
    capability_scopes: tuple[tuple[str, str], ...] = ()
    consumed_at: datetime | None = None
    consumed_by_node_id: str | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_aware("issued_at", self.issued_at)
        _require_aware("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if not self.node_name.strip():
            raise ValueError("node_name must not be empty")
        if len(self.secret_hash) != 64:
            raise ValueError("secret_hash must be a SHA-256 hex digest")

    @property
    def consumed(self) -> bool:
        return self.consumed_at is not None

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None


@dataclass(frozen=True)
class NodeRecord:
    """Canonical registry record for one enrolled machine."""

    node_id: str
    node_name: str
    kind: NodeKind
    platform: NodePlatform
    architecture: str
    agent_version: str
    public_key: str
    granted_capabilities: tuple[str, ...]
    enrolled_at: datetime
    enrollment_token_id: str
    # Carried verbatim from the enrollment token. A node declares capabilities;
    # it never states or widens their scope.
    capability_scopes: tuple[tuple[str, str], ...] = ()
    declared_capabilities: tuple[str, ...] = ()
    labels: tuple[tuple[str, str], ...] = ()
    session_id: str | None = None
    session_started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    last_health: NodeHealthSnapshot | None = None
    quarantined_at: datetime | None = None
    quarantine_reason: str = ""
    revoked_at: datetime | None = None
    revocation_reason: str = ""

    def __post_init__(self) -> None:
        _require_aware("enrolled_at", self.enrolled_at)
        if not self.node_id.strip():
            raise ValueError("node_id must not be empty")
        if not self.public_key.strip():
            raise ValueError("public_key must not be empty")

    @property
    def connected(self) -> bool:
        return self.session_id is not None


@dataclass(frozen=True)
class NodeView:
    """Derived, presentation-safe projection of a node at one instant."""

    node_id: str
    node_name: str
    kind: NodeKind
    platform: NodePlatform
    architecture: str
    agent_version: str
    state: NodeState
    connected: bool
    granted_capabilities: tuple[str, ...]
    declared_capabilities: tuple[str, ...]
    effective_capabilities: tuple[str, ...]
    enrolled_at: datetime
    last_heartbeat_at: datetime | None
    heartbeat_age_seconds: float | None
    labels: tuple[tuple[str, str], ...]
    health: NodeHealthSnapshot | None
    output_trust_label: TrustLabel = TrustLabel.EXTERNAL_UNTRUSTED
    # What each granted capability is bounded to, so an operator auditing a
    # node sees the bound and not just the capability name.
    capability_scopes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DispatchControlState:
    """The mesh-wide dispatch kill switch.

    Freezing is monotonic within an epoch: it can always be set, and can only be
    cleared by an explicit unfreeze that names the exact current freeze epoch.
    """

    frozen: bool = False
    freeze_epoch: int = 0
    changed_at: datetime | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.freeze_epoch < 0:
            raise ValueError("freeze_epoch must not be negative")
        if self.changed_at is not None:
            _require_aware("changed_at", self.changed_at)


@dataclass(frozen=True)
class NodeJobRecord:
    """Control-plane view of one dispatched node job."""

    job_id: str
    node_id: str
    capability: str
    dedupe_key: str
    status: NodeJobStatus
    attempt: int
    authority: DispatchAuthority
    created_at: datetime
    updated_at: datetime
    progress_events: int = 0
    last_message: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        _require_aware("created_at", self.created_at)
        _require_aware("updated_at", self.updated_at)
        if self.attempt < 1:
            raise ValueError("attempt must be strictly positive")


@dataclass(frozen=True)
class NodeJobOutcome:
    """Terminal outcome returned to the workflow that owns the job."""

    job_id: str
    node_id: str
    capability: str
    dedupe_key: str
    status: NodeJobStatus
    attempt: int
    output: dict[str, Any] = field(default_factory=dict)
    output_truncated: bool = False
    # Whether credential-shaped content was masked on the way in. Reported
    # rather than silent: a consumer comparing returned content against a
    # digest the capability computed needs to know the bytes changed after
    # that digest was taken.
    output_redacted: bool = False
    artifact_ids: tuple[str, ...] = ()
    reason: str = ""
    message: str = ""
    replayed: bool = False
    trust_label: TrustLabel = TrustLabel.EXTERNAL_UNTRUSTED

    def __post_init__(self) -> None:
        if self.attempt < 1:
            raise ValueError("attempt must be strictly positive")
        if self.trust_label is TrustLabel.CONTROL:
            raise ValueError("node output may never carry the control trust label")


def utc_now() -> datetime:
    """Single clock seam so tests can reason about heartbeat and token expiry."""
    return datetime.now(UTC)

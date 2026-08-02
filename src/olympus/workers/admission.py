from dataclasses import dataclass
from enum import IntEnum, StrEnum
from uuid import uuid4


class AdmissionDenied(RuntimeError):
    pass


class WorkerClass(StrEnum):
    CLAUDE = "claude"
    CODEX = "codex"
    CHROMIUM = "chromium"
    VERIFIER = "verifier"


class WorkPriority(IntEnum):
    BACKGROUND = 10
    NORMAL = 20
    INTERACTIVE = 30
    CONTROL = 100


class SystemMode(StrEnum):
    NORMAL = "normal"
    CONSTRAINED = "constrained"
    DEGRADED = "degraded"
    SURVIVAL = "survival"


@dataclass(frozen=True)
class ResourceEnvelope:
    cpu_millicores: int
    memory_mib: int

    def __post_init__(self) -> None:
        if self.cpu_millicores < 0 or self.memory_mib < 0:
            raise ValueError("resource values cannot be negative")


@dataclass(frozen=True)
class WorkerRequest:
    request_id: str
    job_id: str
    worker_class: WorkerClass
    worktree_id: str
    artifact_prefix: str
    cpu_millicores: int
    memory_mib: int
    priority: WorkPriority

    def __post_init__(self) -> None:
        strings = (self.request_id, self.job_id, self.worktree_id, self.artifact_prefix)
        if any(not value.strip() for value in strings):
            raise ValueError("worker identity and isolation boundaries are required")
        if self.cpu_millicores < 1 or self.memory_mib < 1:
            raise ValueError("worker resource requests must be positive")
        if self.artifact_prefix.startswith("/") or ".." in self.artifact_prefix.split("/"):
            raise ValueError("artifact prefix must be a relative contained path")


@dataclass(frozen=True)
class WorkerLease:
    isolation_token: str
    request: WorkerRequest


class AdmissionController:
    def __init__(
        self,
        *,
        capacity: ResourceEnvelope,
        mode: SystemMode,
        concurrency: dict[WorkerClass, int],
    ) -> None:
        if capacity.cpu_millicores < 1 or capacity.memory_mib < 1:
            raise ValueError("admission capacity must be positive")
        if set(concurrency) != set(WorkerClass) or any(value < 1 for value in concurrency.values()):
            raise ValueError("every worker class needs a positive concurrency limit")
        self._capacity = capacity
        self._mode = mode
        self._concurrency = dict(concurrency)
        self._active: dict[str, WorkerLease] = {}

    @property
    def active(self) -> tuple[WorkerLease, ...]:
        return tuple(self._active.values())

    @property
    def used(self) -> ResourceEnvelope:
        return ResourceEnvelope(
            cpu_millicores=sum(item.request.cpu_millicores for item in self._active.values()),
            memory_mib=sum(item.request.memory_mib for item in self._active.values()),
        )

    def set_mode(self, mode: SystemMode) -> None:
        self._mode = mode

    def admit(self, request: WorkerRequest) -> WorkerLease:
        self._require_mode(request)
        if any(
            lease.request.worktree_id == request.worktree_id
            or lease.request.artifact_prefix == request.artifact_prefix
            for lease in self._active.values()
        ):
            raise AdmissionDenied("worker isolation boundary is already active")
        active_for_class = sum(
            lease.request.worker_class is request.worker_class for lease in self._active.values()
        )
        if active_for_class >= self._concurrency[request.worker_class]:
            raise AdmissionDenied("worker class concurrency limit reached")
        used = self.used
        if (
            used.cpu_millicores + request.cpu_millicores > self._capacity.cpu_millicores
            or used.memory_mib + request.memory_mib > self._capacity.memory_mib
        ):
            raise AdmissionDenied("worker resource capacity exhausted")
        lease = WorkerLease(isolation_token=f"worker-{uuid4()}", request=request)
        self._active[lease.isolation_token] = lease
        return lease

    def release(self, isolation_token: str) -> None:
        if self._active.pop(isolation_token, None) is None:
            raise AdmissionDenied("worker lease is not active")

    def _require_mode(self, request: WorkerRequest) -> None:
        if request.priority is WorkPriority.CONTROL:
            return
        if self._mode is SystemMode.SURVIVAL:
            raise AdmissionDenied("survival mode admits control work only")
        if self._mode is SystemMode.DEGRADED and request.priority < WorkPriority.INTERACTIVE:
            raise AdmissionDenied("degraded mode rejects non-interactive work")
        if self._mode is SystemMode.CONSTRAINED and request.priority is WorkPriority.BACKGROUND:
            raise AdmissionDenied("constrained mode rejects background work")

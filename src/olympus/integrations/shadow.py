import hashlib
import json
from dataclasses import dataclass
from typing import Protocol


class ShadowModeViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class IntegrationRequest:
    request_id: str
    adapter: str
    operation: str
    payload: dict[str, object]
    mutation_requested: bool

    def __post_init__(self) -> None:
        if not self.request_id.strip() or not self.adapter.strip() or not self.operation.strip():
            raise ValueError("integration request identity, adapter, and operation are required")


@dataclass(frozen=True)
class ShadowProjection:
    request_id: str
    adapter: str
    operation: str
    mutation_requested: bool
    effect: str
    approval_required: bool
    trust_labels: tuple[str, ...]
    evidence_digest: str


class ReadOnlyAdapter(Protocol):
    def read(self, operation: str, payload: dict[str, object]) -> dict[str, object]: ...


class FakeReadOnlyAdapter:
    def __init__(self, name: str, result: dict[str, object]) -> None:
        self.name = name
        self._result = dict(result)
        self.read_count = 0
        self.mutation_count = 0

    def read(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.read_count += 1
        return dict(self._result)

    def mutate(self, operation: str, payload: dict[str, object]) -> None:
        self.mutation_count += 1
        raise ShadowModeViolation("provider mutation is disabled in shadow mode")


class ShadowModeRunner:
    def __init__(self, adapters: dict[str, ReadOnlyAdapter]) -> None:
        if not adapters:
            raise ValueError("at least one read-only adapter is required")
        self._adapters = dict(adapters)

    def run(self, request: IntegrationRequest) -> ShadowProjection:
        adapter = self._adapters.get(request.adapter)
        if adapter is None:
            raise ShadowModeViolation("integration adapter is not registered")
        evidence = adapter.read(request.operation, dict(request.payload))
        evidence_digest = hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return ShadowProjection(
            request_id=request.request_id,
            adapter=request.adapter,
            operation=request.operation,
            mutation_requested=request.mutation_requested,
            effect="projected-only",
            approval_required=request.mutation_requested,
            trust_labels=("external-untrusted",),
            evidence_digest=evidence_digest,
        )

from dataclasses import dataclass

from olympus.contracts.commands import TrustLabel


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    operation: str
    depends_on: tuple[str, ...]
    side_effecting: bool
    trust_labels: tuple[TrustLabel, ...]
    timeout_seconds: int = 30
    maximum_attempts: int = 3

    def __post_init__(self) -> None:
        if not self.node_id.strip() or not self.operation.strip():
            raise ValueError("graph node identity and operation are required")
        if self.node_id in self.depends_on:
            raise ValueError("graph node cannot depend on itself")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("graph node dependencies must be unique")
        if self.timeout_seconds < 1 or self.timeout_seconds > 3600:
            raise ValueError("node timeout must be between 1 and 3600 seconds")
        if self.maximum_attempts < 1 or self.maximum_attempts > 10:
            raise ValueError("node maximum_attempts must be between 1 and 10")


@dataclass(frozen=True)
class CompiledGraph:
    job_id: str
    nodes: tuple[GraphNode, ...]
    maximum_nodes: int
    maximum_fan_out: int
    digest: str

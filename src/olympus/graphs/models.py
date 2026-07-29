from dataclasses import dataclass

from olympus.contracts.commands import TrustLabel


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    operation: str
    depends_on: tuple[str, ...]
    side_effecting: bool
    trust_labels: tuple[TrustLabel, ...]


@dataclass(frozen=True)
class CompiledGraph:
    job_id: str
    nodes: tuple[GraphNode, ...]
    maximum_nodes: int
    maximum_fan_out: int
    digest: str

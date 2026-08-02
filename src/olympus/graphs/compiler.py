import hashlib
import json

from olympus.contracts.commands import CommandEnvelope
from olympus.graphs.models import CompiledGraph, GraphNode


class GraphCompilationError(ValueError):
    pass


def compile_execution_graph(
    *,
    job_id: str,
    nodes: tuple[GraphNode, ...],
    maximum_nodes: int,
    maximum_fan_out: int,
) -> CompiledGraph:
    if not job_id.strip():
        raise GraphCompilationError("job_id must not be empty")
    if maximum_nodes < 1 or maximum_nodes > 256:
        raise GraphCompilationError("maximum_nodes must be between 1 and 256")
    if maximum_fan_out < 1 or maximum_fan_out > 16:
        raise GraphCompilationError("maximum_fan_out must be between 1 and 16")
    if not nodes or len(nodes) > maximum_nodes:
        raise GraphCompilationError("graph exceeds its node bound")
    by_id = {node.node_id: node for node in nodes}
    if len(by_id) != len(nodes):
        raise GraphCompilationError("graph node identities must be unique")
    unknown = {
        dependency for node in nodes for dependency in node.depends_on if dependency not in by_id
    }
    if unknown:
        raise GraphCompilationError("graph contains an unknown dependency")
    fan_out = {
        node_id: sum(node_id in candidate.depends_on for candidate in nodes) for node_id in by_id
    }
    if any(count > maximum_fan_out for count in fan_out.values()):
        raise GraphCompilationError("graph exceeds its fan-out bound")
    ordered = _topological_order(by_id)
    canonical = {
        "job_id": job_id,
        "maximum_fan_out": maximum_fan_out,
        "maximum_nodes": maximum_nodes,
        "nodes": [_canonical_node(node) for node in ordered],
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return CompiledGraph(
        job_id=job_id,
        nodes=ordered,
        maximum_nodes=maximum_nodes,
        maximum_fan_out=maximum_fan_out,
        digest=digest,
    )


def compile_noop_graph(command: CommandEnvelope) -> CompiledGraph:
    node = GraphNode(
        node_id="acknowledge-command",
        operation="record-command-without-side-effects",
        depends_on=(),
        side_effecting=False,
        trust_labels=(command.trust_label,),
    )
    graph = compile_execution_graph(
        job_id=command.job_id,
        nodes=(node,),
        maximum_nodes=command.max_nodes,
        maximum_fan_out=command.max_fan_out,
    )
    authority_binding = hashlib.sha256(
        json.dumps(
            {
                "authority_lease_id": command.authority_lease_id,
                "command_text": command.command_text,
                "graph_digest": graph.digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return CompiledGraph(
        job_id=graph.job_id,
        nodes=graph.nodes,
        maximum_nodes=graph.maximum_nodes,
        maximum_fan_out=graph.maximum_fan_out,
        digest=authority_binding,
    )


def _topological_order(by_id: dict[str, GraphNode]) -> tuple[GraphNode, ...]:
    remaining = {node_id: set(node.depends_on) for node_id, node in by_id.items()}
    ordered: list[GraphNode] = []
    while remaining:
        ready = sorted(node_id for node_id, dependencies in remaining.items() if not dependencies)
        if not ready:
            raise GraphCompilationError("graph contains a dependency cycle")
        for node_id in ready:
            ordered.append(by_id[node_id])
            del remaining[node_id]
        for dependencies in remaining.values():
            dependencies.difference_update(ready)
    return tuple(ordered)


def _canonical_node(node: GraphNode) -> dict[str, object]:
    return {
        "depends_on": list(node.depends_on),
        "maximum_attempts": node.maximum_attempts,
        "node_id": node.node_id,
        "operation": node.operation,
        "side_effecting": node.side_effecting,
        "timeout_seconds": node.timeout_seconds,
        "trust_labels": [label.value for label in node.trust_labels],
    }

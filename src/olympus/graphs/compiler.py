import hashlib
import json

from olympus.contracts.commands import CommandEnvelope
from olympus.graphs.models import CompiledGraph, GraphNode


def compile_noop_graph(command: CommandEnvelope) -> CompiledGraph:
    node = GraphNode(
        node_id="acknowledge-command",
        operation="record-command-without-side-effects",
        depends_on=(),
        side_effecting=False,
        trust_labels=(command.trust_label,),
    )
    canonical = {
        "job_id": command.job_id,
        "command_text": command.command_text,
        "authority_lease_id": command.authority_lease_id,
        "nodes": [
            {
                "node_id": node.node_id,
                "operation": node.operation,
                "depends_on": list(node.depends_on),
                "side_effecting": node.side_effecting,
                "trust_labels": [label.value for label in node.trust_labels],
            }
        ],
        "maximum_nodes": command.max_nodes,
        "maximum_fan_out": command.max_fan_out,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return CompiledGraph(
        job_id=command.job_id,
        nodes=(node,),
        maximum_nodes=command.max_nodes,
        maximum_fan_out=command.max_fan_out,
        digest=digest,
    )

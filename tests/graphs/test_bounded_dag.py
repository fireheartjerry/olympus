from dataclasses import replace

import pytest

from olympus.contracts.commands import TrustLabel
from olympus.graphs.compiler import GraphCompilationError, compile_execution_graph
from olympus.graphs.models import GraphNode


def node(
    node_id: str,
    *,
    depends_on: tuple[str, ...] = (),
    operation: str = "worker.local",
) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        operation=operation,
        depends_on=depends_on,
        side_effecting=False,
        trust_labels=(TrustLabel.USER_AUTHORIZED,),
        timeout_seconds=30,
        maximum_attempts=3,
    )


def test_compiles_typed_inspectable_parallel_dag_deterministically() -> None:
    nodes = (
        node("plan", operation="langgraph.activity.reason"),
        node("codex", depends_on=("plan",)),
        node("claude", depends_on=("plan",)),
        node("verify", depends_on=("codex", "claude"), operation="verifier.local"),
    )

    first = compile_execution_graph(
        job_id="job-1",
        nodes=nodes,
        maximum_nodes=8,
        maximum_fan_out=2,
    )
    second = compile_execution_graph(
        job_id="job-1",
        nodes=nodes,
        maximum_nodes=8,
        maximum_fan_out=2,
    )

    assert first.digest == second.digest
    assert [item.node_id for item in first.nodes] == ["plan", "claude", "codex", "verify"]
    assert first.maximum_fan_out == 2


@pytest.mark.parametrize(
    ("nodes", "error"),
    [
        ((node("a", depends_on=("missing",)),), "unknown"),
        ((node("a", depends_on=("b",)), node("b", depends_on=("a",))), "cycle"),
        ((node("a"), node("b", depends_on=("a",)), node("c", depends_on=("a",))), "fan-out"),
    ],
)
def test_rejects_unknown_dependencies_cycles_and_excess_fanout(
    nodes: tuple[GraphNode, ...],
    error: str,
) -> None:
    with pytest.raises(GraphCompilationError, match=error):
        compile_execution_graph(
            job_id="job-1",
            nodes=nodes,
            maximum_nodes=8,
            maximum_fan_out=1,
        )


def test_rejects_unbounded_node_retry_or_timeout() -> None:
    with pytest.raises(ValueError, match="maximum_attempts"):
        replace(node("bad"), maximum_attempts=0)
    with pytest.raises(ValueError, match="timeout"):
        replace(node("bad"), timeout_seconds=0)

from datetime import UTC, datetime

from olympus.contracts.commands import CommandEnvelope, TrustLabel
from olympus.graphs.compiler import compile_noop_graph


def make_command(**overrides: object) -> CommandEnvelope:
    values: dict[str, object] = {
        "job_id": "job-123",
        "commander_id": "discord-user-123",
        "authority_lease_id": "lease-456",
        "command_text": "inspect the active graph",
        "received_at": datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    }
    values.update(overrides)
    return CommandEnvelope(**values)  # type: ignore[arg-type]


def test_noop_graph_is_bounded_and_non_mutating() -> None:
    graph = compile_noop_graph(make_command())

    assert graph.job_id == "job-123"
    assert len(graph.nodes) == 1
    assert graph.nodes[0].side_effecting is False
    assert graph.nodes[0].trust_labels == (TrustLabel.USER_AUTHORIZED,)
    assert graph.maximum_nodes == 32
    assert graph.maximum_fan_out == 4


def test_graph_digest_is_stable_for_identical_input() -> None:
    first = compile_noop_graph(make_command())
    second = compile_noop_graph(make_command())

    assert first.digest == second.digest


def test_graph_digest_changes_when_command_or_lease_changes() -> None:
    graph = compile_noop_graph(make_command())
    changed_command = compile_noop_graph(make_command(command_text="inspect the policy release"))
    changed_lease = compile_noop_graph(make_command(authority_lease_id="lease-789"))

    assert changed_command.digest != graph.digest
    assert changed_lease.digest != graph.digest

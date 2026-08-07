from datetime import UTC, datetime

import pytest

from olympus.takeover import (
    TakeoverEndReason,
    TakeoverRequest,
    TakeoverSession,
    TakeoverState,
)


def test_takeover_request_needs_context_or_explicit_objective() -> None:
    with pytest.raises(ValueError, match="context"):
        TakeoverRequest(
            request_id="r1",
            owner_id="jerry",
            requested_at=datetime.now(UTC),
            context_refs=(),
        )


def test_terminal_takeover_requires_reason_and_time() -> None:
    with pytest.raises(ValueError, match="terminal"):
        TakeoverSession(
            session_id="s1",
            request_id="r1",
            objective_contract_id="o1",
            state=TakeoverState.COMPLETED,
            started_at=datetime.now(UTC),
            active_node_ids=("windows",),
            active_graph_ids=("g1",),
            authority_lease_id="lease-1",
        )


def test_active_takeover_cannot_pretend_to_be_ended() -> None:
    with pytest.raises(ValueError, match="non-terminal"):
        TakeoverSession(
            session_id="s1",
            request_id="r1",
            objective_contract_id="o1",
            state=TakeoverState.ACTIVE,
            started_at=datetime.now(UTC),
            active_node_ids=("windows",),
            active_graph_ids=("g1",),
            authority_lease_id="lease-1",
            end_reason=TakeoverEndReason.OWNER_STOPPED,
            ended_at=datetime.now(UTC),
        )

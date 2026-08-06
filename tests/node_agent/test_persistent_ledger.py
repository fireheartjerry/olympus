from pathlib import Path

import pytest

from olympus.node_agent.agent import _ResultLedger
from olympus.nodes.protocol import JobResultFrame


def result(dedupe_key: str) -> JobResultFrame:
    return JobResultFrame(
        job_id="job-1",
        attempt=1,
        dedupe_key=dedupe_key,
        status="succeeded",
        output={"bounded": True},
    )


def test_completed_result_survives_agent_restart(tmp_path: Path) -> None:
    path = tmp_path / "result-ledger.json"
    key = "a" * 64
    first = _ResultLedger(path=path, node_id="node-1")
    first.put(key, result(key))

    restarted = _ResultLedger(path=path, node_id="node-1")

    assert restarted.keys() == (key,)
    assert restarted.get(key) == result(key)


def test_corrupt_result_ledger_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "result-ledger.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(RuntimeError, match="refusing unsafe replay"):
        _ResultLedger(path=path, node_id="node-1")


def test_new_node_identity_cannot_replay_the_revoked_identitys_results(tmp_path: Path) -> None:
    path = tmp_path / "result-ledger.json"
    key = "b" * 64
    old = _ResultLedger(path=path, node_id="node-revoked")
    old.put(key, result(key))

    replacement = _ResultLedger(path=path, node_id="node-replacement")

    assert replacement.keys() == ()
    persisted = _ResultLedger(path=path, node_id="node-replacement")
    assert persisted.keys() == ()

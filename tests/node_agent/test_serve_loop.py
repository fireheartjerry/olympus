import asyncio
import contextlib
from pathlib import Path
from typing import Any

import pytest

from olympus.node_agent import __main__ as entrypoint
from olympus.node_agent.config import CONFIG_VERSION, NodeAgentConfig
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.channel import ChannelClosed
from olympus.nodes.crypto import generate_node_keypair


def build_config() -> NodeAgentConfig:
    return NodeAgentConfig(
        version=CONFIG_VERSION,
        control_plane_url="http://127.0.0.1:8080",
        node_id="node-1",
        node_name="jerry-windows",
        private_key=generate_node_keypair().private_key,
        control_plane_public_key=generate_node_keypair().public_key,
        control_plane_key_id="olympus-control-plane-test",
        capabilities=(SYSTEM_INSPECT.name,),
    )


async def test_the_serve_loop_keeps_one_agent_so_its_dedupe_ledger_survives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Rebuilding the agent per attempt would silently discard replay safety."""
    built: list[object] = []
    original = entrypoint.NodeAgent

    class CountingAgent(original):  # type: ignore[misc, valid-type]
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            built.append(self)

    attempts = 0

    @contextlib.asynccontextmanager
    async def refusing_channel(url: str) -> Any:
        nonlocal attempts
        attempts += 1
        if attempts >= 3:
            raise KeyboardInterrupt
        raise ChannelClosed("control plane unreachable")
        yield  # pragma: no cover - unreachable, keeps this an async generator

    monkeypatch.setattr(entrypoint, "NodeAgent", CountingAgent)
    monkeypatch.setattr(entrypoint, "open_session_channel", refusing_channel)
    monkeypatch.setattr(entrypoint, "MIN_BACKOFF_SECONDS", 0)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda _seconds: real_sleep(0))

    with contextlib.suppress(KeyboardInterrupt):
        await entrypoint._serve(build_config(), state_directory=tmp_path, once=False)

    assert attempts == 3
    assert len(built) == 1

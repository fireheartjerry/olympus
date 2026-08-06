from unittest.mock import ANY, AsyncMock, Mock

import pytest
from temporalio.client import Client

from olympus.gateway.settings import GatewaySettings

TEST_COMMAND_TOKEN = "test-token-with-at-least-32-bytes"


def node_settings(**overrides: object) -> GatewaySettings:
    values: dict[str, object] = {
        "environment": "test",
        "dev_command_token": TEST_COMMAND_TOKEN,
        "node_mesh_enabled": True,
        "node_attach_control_plane_host": False,
    }
    values.update(overrides)
    return GatewaySettings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_node_edge_refuses_implicit_volatile_state() -> None:
    from olympus.runtime.node_edge import open_node_mesh_store

    with pytest.raises(RuntimeError, match="requires FIRE_DATABASE_URL"):
        await open_node_mesh_store(node_settings())


def test_node_edge_refuses_implicit_ephemeral_signing_key() -> None:
    from olympus.runtime.node_edge import resolve_control_plane_keys

    with pytest.raises(RuntimeError, match="requires FIRE_NODE_CONTROL_PLANE_PRIVATE_KEY"):
        resolve_control_plane_keys(node_settings())


@pytest.mark.asyncio
async def test_disposable_harness_must_explicitly_allow_both_fallbacks() -> None:
    from olympus.runtime.node_edge import open_node_mesh_store, resolve_control_plane_keys

    settings = node_settings(
        node_allow_volatile_state=True,
        node_allow_ephemeral_control_plane_key=True,
    )
    store, description = await open_node_mesh_store(settings)
    private_key, public_key = resolve_control_plane_keys(settings)

    assert store is None
    assert description.startswith("in-process")
    assert private_key
    assert public_key


@pytest.mark.asyncio
async def test_gateway_runtime_wires_temporal_starter_and_loopback_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from olympus.runtime import gateway

    settings = GatewaySettings(
        environment="test",
        dev_command_token=TEST_COMMAND_TOKEN,
        temporal_address="temporal.example:7233",
        temporal_task_queue="runtime-test-queue",
    )
    client = AsyncMock(spec=Client)
    server = Mock()
    server.serve = AsyncMock()
    config = Mock()

    monkeypatch.setattr(gateway, "GatewaySettings", lambda: settings)
    monkeypatch.setattr(gateway.Client, "connect", AsyncMock(return_value=client))
    monkeypatch.setattr(gateway.uvicorn, "Config", Mock(return_value=config))
    monkeypatch.setattr(gateway.uvicorn, "Server", Mock(return_value=server))

    await gateway.run()

    gateway.Client.connect.assert_awaited_once_with("temporal.example:7233")
    gateway.uvicorn.Config.assert_called_once_with(
        app=ANY,
        host="127.0.0.1",
        port=8080,
        log_level="info",
    )
    gateway.uvicorn.Server.assert_called_once_with(config)
    server.serve.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_worker_runtime_registers_command_workflow_and_graph_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from olympus.runtime import worker

    settings = GatewaySettings(
        environment="test",
        dev_command_token=TEST_COMMAND_TOKEN,
        temporal_address="temporal.example:7233",
        temporal_task_queue="runtime-test-queue",
    )
    client = AsyncMock(spec=Client)
    temporal_worker = Mock()
    temporal_worker.run = AsyncMock()

    monkeypatch.setattr(worker, "GatewaySettings", lambda: settings)
    monkeypatch.setattr(worker.Client, "connect", AsyncMock(return_value=client))
    monkeypatch.setattr(worker, "Worker", Mock(return_value=temporal_worker))

    await worker.run()

    worker.Client.connect.assert_awaited_once_with("temporal.example:7233")
    worker.Worker.assert_called_once_with(
        client,
        task_queue="runtime-test-queue",
        workflows=[worker.CommandWorkflow],
        activities=[worker.compile_graph_activity],
    )
    temporal_worker.run.assert_awaited_once_with()

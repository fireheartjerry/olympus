import json
import stat
from pathlib import Path
from typing import Any

import pytest

from olympus.node_agent.__main__ import build_parser, command_status
from olympus.node_agent.capabilities import (
    INSPECT_SECTIONS,
    CapabilityRequest,
    SystemInspectProvider,
)
from olympus.node_agent.config import (
    CONFIG_VERSION,
    NodeAgentConfig,
    NodeAgentConfigError,
    load_config,
    save_config,
)
from olympus.node_agent.enroll import EnrollmentError, enroll
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair


class FakeProbe:
    """Deterministic host measurements so inspection output is assertable."""

    def __init__(self) -> None:
        self.disk_paths: list[Path] = []

    def operating_system(self) -> dict[str, Any]:
        return {
            "system": "Windows",
            "release": "11",
            "machine": "AMD64",
            "python_version": "3.13.13",
        }

    def cpu(self) -> dict[str, Any]:
        return {"logical_cores": 16, "load_average": None}

    def memory(self) -> dict[str, Any]:
        return {"total_mib": 32768, "available_mib": 20480}

    def disk(self, path: Path) -> dict[str, Any]:
        self.disk_paths.append(path)
        return {"path": str(path), "total_mib": 500_000, "free_mib": 120_000}

    def uptime_seconds(self) -> int | None:
        return 86_400


def build_provider(tmp_path: Path) -> tuple[SystemInspectProvider, FakeProbe]:
    probe = FakeProbe()
    return (
        SystemInspectProvider(
            probe=probe, state_directory=tmp_path, agent_version="0.1.0", started_at=0.0
        ),
        probe,
    )


async def collect(provider: SystemInspectProvider, parameters: dict[str, Any]) -> Any:
    messages: list[str] = []

    async def report(message: str, percent: int | None) -> None:
        messages.append(message)

    result = await provider.execute(
        CapabilityRequest(
            job_id="job-1",
            capability=SYSTEM_INSPECT.name,
            parameters=parameters,
            deadline_seconds=15,
            max_output_bytes=16_384,
        ),
        report,
    )
    return result, messages


async def test_system_inspection_returns_only_the_requested_sections(tmp_path: Path) -> None:
    provider, probe = build_provider(tmp_path)
    result, messages = await collect(provider, {"sections": ["os", "disk"]})

    assert result.status == "succeeded"
    assert sorted(result.output["sections"]) == ["disk", "os"]
    assert result.output["section_names"] == ["os", "disk"]
    assert probe.disk_paths == [tmp_path]
    assert messages[0] == "collecting host inventory"
    assert len(messages) == 3


async def test_system_inspection_defaults_to_every_section(tmp_path: Path) -> None:
    provider, _ = build_provider(tmp_path)
    result, _ = await collect(provider, {})
    assert sorted(result.output["sections"]) == sorted(INSPECT_SECTIONS)


async def test_system_inspection_rejects_unknown_sections(tmp_path: Path) -> None:
    provider, _ = build_provider(tmp_path)
    result, _ = await collect(provider, {"sections": ["/etc/shadow", "environment"]})

    assert result.status == "rejected"
    assert result.reason == "capability-parameters-invalid"
    assert result.output == {}


async def test_system_inspection_never_reports_secrets_or_process_state(tmp_path: Path) -> None:
    provider, _ = build_provider(tmp_path)
    result, _ = await collect(provider, {})
    rendered = json.dumps(result.output)

    for forbidden in ["environ", "PATH", "process", "cmdline", "token", "password"]:
        assert forbidden not in rendered


async def test_the_agent_section_reports_its_own_identity(tmp_path: Path) -> None:
    provider, _ = build_provider(tmp_path)
    result, _ = await collect(provider, {"sections": ["agent"]})
    assert result.output["sections"]["agent"]["agent_version"] == "0.1.0"
    assert result.output["sections"]["agent"]["agent_uptime_seconds"] >= 0


def build_config(tmp_path: Path) -> NodeAgentConfig:
    keys = generate_node_keypair()
    return NodeAgentConfig(
        version=CONFIG_VERSION,
        control_plane_url="https://vps.example.ts.net",
        node_id="node-1",
        node_name="jerry-windows",
        private_key=keys.private_key,
        control_plane_public_key=generate_node_keypair().public_key,
        control_plane_key_id="olympus-control-plane-v1",
        capabilities=(SYSTEM_INSPECT.name,),
    )


def test_configuration_round_trips_with_owner_only_permissions(tmp_path: Path) -> None:
    path = tmp_path / "node.json"
    config = build_config(tmp_path)
    save_config(path, config)

    assert load_config(path) == config
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_session_url_follows_the_control_plane_scheme(tmp_path: Path) -> None:
    config = build_config(tmp_path)
    assert config.session_url == "wss://vps.example.ts.net/v1/nodes/session"

    from dataclasses import replace

    plain = replace(config, control_plane_url="http://127.0.0.1:8080")
    assert plain.session_url == "ws://127.0.0.1:8080/v1/nodes/session"


def test_the_redacted_summary_hides_the_node_private_key(tmp_path: Path) -> None:
    config = build_config(tmp_path)
    summary = config.redacted()
    assert summary["private_key"] == "[redacted]"
    assert config.private_key not in json.dumps(summary)


@pytest.mark.parametrize(
    "mutation",
    [
        {"control_plane_url": "ftp://elsewhere"},
        {"control_plane_url": "not-a-url"},
        {"node_id": "  "},
        {"version": 99},
    ],
)
def test_unusable_configuration_fails_closed(tmp_path: Path, mutation: dict[str, Any]) -> None:
    from dataclasses import replace

    with pytest.raises(NodeAgentConfigError):
        replace(build_config(tmp_path), **mutation)


def test_missing_or_corrupt_configuration_is_reported(tmp_path: Path) -> None:
    with pytest.raises(NodeAgentConfigError):
        load_config(tmp_path / "absent.json")

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    with pytest.raises(NodeAgentConfigError):
        load_config(corrupt)

    unexpected = tmp_path / "unexpected.json"
    unexpected.write_text(json.dumps({"version": 1, "surprise": True}), encoding="utf-8")
    with pytest.raises(NodeAgentConfigError, match="unknown configuration keys"):
        load_config(unexpected)


def test_enrollment_refuses_a_non_absolute_control_plane_url() -> None:
    with pytest.raises(EnrollmentError):
        enroll(
            control_plane_url="vps.example.ts.net",
            enrollment_token="olynode_a_b",  # noqa: S106 - deliberately rejected before use
            public_key=generate_node_keypair().public_key,
            node_name="jerry-windows",
            kind="workstation",
            node_platform="windows",
            architecture="AMD64",
            agent_version="0.1.0",
            declared_capabilities=(SYSTEM_INSPECT.name,),
        )


def test_the_cli_requires_exactly_one_way_to_supply_the_enrollment_credential() -> None:
    parser = build_parser()
    arguments = parser.parse_args(
        [
            "enroll",
            "--control-plane-url",
            "https://vps.example.ts.net",
            "--enrollment-token-stdin",
            "--node-name",
            "jerry-windows",
            "--config",
            "node.json",
        ]
    )
    assert arguments.enrollment_token_stdin is True
    assert arguments.enrollment_token is None

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "enroll",
                "--control-plane-url",
                "https://x.ts.net",
                "--node-name",
                "n",
                "--config",
                "c",
            ]
        )


def test_status_prints_a_redacted_configuration(tmp_path: Path, capsys: Any) -> None:
    path = tmp_path / "node.json"
    config = build_config(tmp_path)
    save_config(path, config)

    exit_code = command_status(build_parser().parse_args(["status", "--config", str(path)]))
    printed = capsys.readouterr().out

    assert exit_code == 0
    assert config.private_key not in printed
    assert "[redacted]" in printed

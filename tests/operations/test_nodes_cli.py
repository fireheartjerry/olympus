"""Tests for the node-mesh operator CLI.

The CLI exists so that the request an operator makes under pressure — revoking
a node they believe is compromised — is well formed. So these check the shape
of what it sends and that it refuses rather than sending something wrong.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from olympus.operations.nodes_cli import (
    OperatorError,
    _parse_scope,
    build_parser,
    main,
)


class Recorder:
    """Captures the request instead of making it."""

    def __init__(self, response: Any = None) -> None:
        self.response = response if response is not None else {}
        self.calls: list[dict[str, Any]] = []

    def __call__(self, args, method, path, body=None):  # noqa: ANN001 - test double
        self.calls.append({"method": method, "path": path, "body": body})
        return self.response


@pytest.fixture
def base_argv() -> list[str]:
    return ["--commander", "628053765181800448", "--lease", "lease-1", "--token", "t" * 32]


# --- scope parsing ------------------------------------------------------------------


def test_a_scope_is_expressible_on_the_command_line() -> None:
    """A scope is the difference between granting a capability and handing over
    a machine, so it must not require a JSON file nobody will write."""
    scopes = _parse_scope(["fs.read@1=/srv/data,/var/log:65536"])

    assert scopes == {"fs.read@1": {"roots": ["/srv/data", "/var/log"], "max_bytes": 65536}}


def test_a_scope_without_a_byte_ceiling_is_accepted() -> None:
    assert _parse_scope(["fs.read@1=/srv/data"]) == {"fs.read@1": {"roots": ["/srv/data"]}}


@pytest.mark.parametrize("raw", ["fs.read@1", "=/srv/data", "fs.read@1=", "fs.read@1=:100"])
def test_a_malformed_scope_is_refused_rather_than_guessed(raw: str) -> None:
    # Guessing at a malformed scope would mean granting a bound the operator
    # did not write.
    with pytest.raises(OperatorError):
        _parse_scope([raw])


def test_a_non_numeric_suffix_is_treated_as_part_of_the_path() -> None:
    """Only digits after the last colon mean a byte ceiling.

    Anything else is path: a Windows root carries a colon in its drive letter,
    and splitting unconditionally turned C:\\olympus\\share into the root "C".
    """
    assert _parse_scope(["fs.read@1=/srv/data:lots"]) == {
        "fs.read@1": {"roots": ["/srv/data:lots"]}
    }


def test_a_windows_root_with_a_byte_ceiling_still_parses() -> None:
    assert _parse_scope(["fs.read@1=C:\\olympus\\share:4096"]) == {
        "fs.read@1": {"roots": ["C:\\olympus\\share"], "max_bytes": 4096}
    }


def test_a_windows_path_survives_parsing() -> None:
    scopes = _parse_scope(["fs.read@1=C:\\olympus\\share"])

    assert scopes["fs.read@1"]["roots"] == ["C:\\olympus\\share"]


# --- refusing to send a request that cannot succeed -----------------------------------


def test_authority_is_required_before_anything_is_sent(capsys) -> None:
    """Refused locally rather than by the gateway.

    A rejected request looks like the mesh is down; a local refusal says what
    is actually missing.
    """
    assert main(["list"]) == 2
    assert "commander id and authority lease are required" in capsys.readouterr().err


def test_a_missing_token_is_refused_with_a_usable_message(monkeypatch, capsys) -> None:
    monkeypatch.delenv("OLYMPUS_COMMAND_TOKEN", raising=False)

    code = main(["--commander", "628053765181800448", "--lease", "lease-1", "list"])

    assert code == 1
    assert "OLYMPUS_COMMAND_TOKEN" in capsys.readouterr().err


# --- the requests themselves -----------------------------------------------------------


def test_grant_sends_the_capability_and_its_scope_together(monkeypatch, base_argv, capsys) -> None:
    recorder = Recorder(
        {
            "node_name": "jerry-windows",
            "enrollment_token": "olynode_secret",
            "expires_at": "2026-08-02T12:00:00Z",
            "granted_capabilities": ["fs.read@1"],
            "capability_scopes": {"fs.read@1": {"roots": ["C:\\olympus\\share"]}},
        }
    )
    monkeypatch.setattr("olympus.operations.nodes_cli._call", recorder)

    code = main(
        [
            *base_argv,
            "grant",
            "jerry-windows",
            "--capability",
            "fs.read@1",
            "--scope",
            "fs.read@1=C:\\olympus\\share:4096",
        ]
    )

    assert code == 0
    body = recorder.calls[0]["body"]
    assert body["capabilities"] == ["fs.read@1"]
    assert body["capability_scopes"]["fs.read@1"]["roots"] == ["C:\\olympus\\share"]
    output = capsys.readouterr().out
    # The operator is about to paste this somewhere; say what it is.
    assert "single use" in output


def test_revoke_names_the_node_and_carries_a_reason(monkeypatch, base_argv, capsys) -> None:
    recorder = Recorder()
    monkeypatch.setattr("olympus.operations.nodes_cli._call", recorder)

    code = main([*base_argv, "revoke", "node-1", "--reason", "suspected-compromise"])

    assert code == 0
    assert recorder.calls[0]["path"] == "/v1/nodes/node-1/revoke"
    assert recorder.calls[0]["body"] == {"reason": "suspected-compromise"}
    assert "in-flight work cancelled" in capsys.readouterr().out


def test_revoking_requires_a_reason() -> None:
    # An unexplained revocation is an incident nobody can reconstruct later.
    with pytest.raises(SystemExit):
        build_parser().parse_args(["revoke", "node-1"])


def test_list_prints_each_grant_next_to_its_bound(monkeypatch, base_argv, capsys) -> None:
    recorder = Recorder(
        {
            "nodes": [
                {
                    "node_id": "node-1",
                    "node_name": "jerry-windows",
                    "state": "online",
                    "connected": True,
                    "granted_capabilities": ["fs.read@1"],
                    "capability_scopes": {
                        "fs.read@1": {"roots": ["C:\\olympus\\share"], "max_bytes": 4096}
                    },
                }
            ]
        }
    )
    monkeypatch.setattr("olympus.operations.nodes_cli._call", recorder)

    assert main([*base_argv, "list"]) == 0

    output = capsys.readouterr().out
    # A capability name without its bound is the least useful half.
    assert "fs.read@1 -> C:\\olympus\\share" in output
    assert "max_bytes=4096" in output


def test_list_reports_an_empty_mesh_plainly(monkeypatch, base_argv, capsys) -> None:
    monkeypatch.setattr("olympus.operations.nodes_cli._call", Recorder({"nodes": []}))

    assert main([*base_argv, "list"]) == 0
    assert "no nodes enrolled" in capsys.readouterr().out


def test_json_output_is_available_for_scripting(monkeypatch, base_argv, capsys) -> None:
    monkeypatch.setattr("olympus.operations.nodes_cli._call", Recorder({"nodes": []}))

    assert main([*base_argv, "--json", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == {"nodes": []}


def test_a_gateway_failure_is_reported_not_raised(monkeypatch, base_argv, capsys) -> None:
    def explode(args, method, path, body=None):  # noqa: ANN001 - test double
        raise OperatorError("cannot reach http://127.0.0.1:8080: refused")

    monkeypatch.setattr("olympus.operations.nodes_cli._call", explode)

    assert main([*base_argv, "list"]) == 1
    assert "cannot reach" in capsys.readouterr().err


def test_the_cli_uses_only_the_standard_library() -> None:
    """An operator tool that cannot run because a dependency is missing is
    worse than no tool, and this one runs on a host where something already
    went wrong."""
    import inspect

    from olympus.operations import nodes_cli

    source = inspect.getsource(nodes_cli)
    for third_party in ("import httpx", "import requests", "import boto3", "import aiohttp"):
        assert third_party not in source

from typing import Any

import pytest
from fastapi.testclient import TestClient

from olympus.contracts.commands import CommandAccepted, CommandEnvelope
from olympus.gateway.app import create_app
from olympus.gateway.nodes_api import NodeMeshRuntime
from olympus.gateway.settings import GatewaySettings
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.protocol import PROTOCOL_ID
from olympus.nodes.registry import NodeRegistry

TEST_COMMAND_TOKEN = "test-token-with-at-least-32-bytes"
RESERVED_CAPABILITY = "shell.powershell@1"
HEADERS = {
    "Authorization": f"Bearer {TEST_COMMAND_TOKEN}",
    "X-Olympus-Commander": "local-jerry",
    "X-Olympus-Authority-Lease": "development-lease",
}


class FakeCommandStarter:
    async def start(self, command: CommandEnvelope) -> CommandAccepted:
        return CommandAccepted(job_id=command.job_id)


class FakeJobStarter:
    def __init__(self) -> None:
        self.started: list[NodeJobRequest] = []
        self.cancelled: list[str] = []
        self.refuse_cancel: NodeReason | None = None

    async def start(self, request: NodeJobRequest) -> str:
        self.started.append(request)
        return request.job_id

    async def cancel(self, job_id: str) -> None:
        if self.refuse_cancel is not None:
            raise NodeMeshError(self.refuse_cancel, "unknown node job")
        self.cancelled.append(job_id)


def build_client() -> tuple[TestClient, NodeMeshRuntime, FakeJobStarter]:
    settings = GatewaySettings(
        environment="test",
        dev_command_token=TEST_COMMAND_TOKEN,  # type: ignore[arg-type]
    )
    control_keys = generate_node_keypair()
    registry = NodeRegistry()
    starter = FakeJobStarter()
    runtime = NodeMeshRuntime(
        registry=registry,
        dispatch=NodeDispatchService(registry=registry),
        control_plane_private_key=control_keys.private_key,
        control_plane_public_key=control_keys.public_key,
        control_plane_key_id="olympus-control-plane-test",
        job_starter=starter,
    )
    app = create_app(settings, FakeCommandStarter(), runtime)
    return TestClient(app), runtime, starter


def issue(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "node_name": "jerry-windows",
        "kind": "workstation",
        "platform": "windows",
        "capabilities": [SYSTEM_INSPECT.name],
    }
    payload.update(overrides)
    response = client.post("/v1/nodes/enrollments", json=payload, headers=HEADERS)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def enroll(client: TestClient, presented: str, public_key: str, **overrides: Any) -> Any:
    payload: dict[str, Any] = {
        "enrollment_token": presented,
        "public_key": public_key,
        "node_name": "jerry-windows",
        "kind": "workstation",
        "platform": "windows",
        "architecture": "AMD64",
        "agent_version": "0.1.0",
        "declared_capabilities": [SYSTEM_INSPECT.name],
    }
    payload.update(overrides)
    return client.post("/v1/nodes/enroll", json=payload)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/nodes",
        "/v1/nodes/capabilities",
        "/v1/nodes/jobs",
        "/v1/nodes/control",
        "/v1/nodes/audit",
    ],
)
def test_node_reads_require_the_operator_credential(path: str) -> None:
    client, _, _ = build_client()
    assert client.get(path).status_code == 422
    without_credential = {k: v for k, v in HEADERS.items() if k != "Authorization"}
    assert client.get(path, headers=without_credential).status_code == 401
    assert client.get(path, headers={**HEADERS, "Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(path, headers=HEADERS).status_code == 200


def test_node_writes_require_the_operator_credential() -> None:
    client, _, _ = build_client()
    for path, body in [
        ("/v1/nodes/enrollments", {"node_name": "x", "capabilities": [SYSTEM_INSPECT.name]}),
        ("/v1/nodes/control/freeze", {"reason": "no"}),
        ("/v1/nodes/jobs", {"capability": SYSTEM_INSPECT.name}),
    ]:
        response = client.post(path, json=body, headers={**HEADERS, "Authorization": "Bearer no"})
        assert response.status_code == 401


def test_malformed_authority_headers_are_refused() -> None:
    client, _, _ = build_client()
    response = client.get("/v1/nodes", headers={**HEADERS, "X-Olympus-Commander": "bad id!"})
    assert response.status_code == 422


def test_issuing_an_enrollment_grant_returns_the_secret_exactly_once() -> None:
    client, runtime, _ = build_client()
    body = issue(client)

    assert body["enrollment_token"].startswith("olynode_")
    assert body["granted_capabilities"] == [SYSTEM_INSPECT.name]
    assert body["protocol"] == PROTOCOL_ID
    listed = client.get("/v1/nodes/audit", headers=HEADERS).json()
    assert listed["chain_valid"] is True
    assert body["enrollment_token"] not in str(listed)


def test_reserved_capabilities_cannot_be_granted_over_the_api() -> None:
    client, _, _ = build_client()
    response = client.post(
        "/v1/nodes/enrollments",
        json={"node_name": "jerry-windows", "capabilities": [RESERVED_CAPABILITY]},
        headers=HEADERS,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "capability-reserved"


def test_enrollment_redeems_once_and_then_refuses_replay() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    keys = generate_node_keypair()

    first = enroll(client, grant["enrollment_token"], keys.public_key)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["session_path"] == "/v1/nodes/session"
    assert body["control_plane_public_key"]
    assert body["protocol"] == PROTOCOL_ID

    replayed = enroll(client, grant["enrollment_token"], generate_node_keypair().public_key)
    assert replayed.status_code == 403
    assert replayed.json()["detail"] == "enrollment-token-consumed"


def test_enrollment_refuses_a_scope_it_was_not_issued_for() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    response = enroll(
        client, grant["enrollment_token"], generate_node_keypair().public_key, node_name="other-pc"
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "enrollment-scope-mismatch"


def test_enrollment_refuses_a_malformed_key() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    response = enroll(client, grant["enrollment_token"], "x" * 40)
    assert response.status_code == 400


def test_a_revoked_grant_cannot_be_redeemed() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    revoked = client.delete(f"/v1/nodes/enrollments/{grant['token_id']}", headers=HEADERS)
    assert revoked.status_code == 204

    response = enroll(client, grant["enrollment_token"], generate_node_keypair().public_key)
    assert response.status_code == 403
    assert response.json()["detail"] == "enrollment-token-revoked"


def test_the_node_list_reports_state_capabilities_and_trust() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    enroll(client, grant["enrollment_token"], generate_node_keypair().public_key)

    body = client.get("/v1/nodes", headers=HEADERS).json()
    assert body["dispatch_frozen"] is False
    node = body["nodes"][0]
    assert node["node_name"] == "jerry-windows"
    assert node["state"] == "pending"
    assert node["connected"] is False
    assert node["effective_capabilities"] == [SYSTEM_INSPECT.name]
    assert node["output_trust_label"] == "external-untrusted"


def test_the_capability_catalog_marks_future_work_as_reserved() -> None:
    client, _, _ = build_client()
    catalog = client.get("/v1/nodes/capabilities", headers=HEADERS).json()
    by_name = {entry["name"]: entry for entry in catalog}

    assert by_name[SYSTEM_INSPECT.name]["status"] == "enabled"
    assert by_name[SYSTEM_INSPECT.name]["mutating"] is False
    assert by_name["desktop.takeover@1"]["status"] == "reserved"
    assert by_name["browser.session@1"]["requires_approval"] is True


def test_jobs_are_started_through_temporal_and_never_dispatched_directly() -> None:
    client, _, starter = build_client()
    response = client.post(
        "/v1/nodes/jobs",
        json={"capability": SYSTEM_INSPECT.name, "parameters": {"sections": ["os"]}},
        headers=HEADERS,
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["workflow_id"] == body["job_id"]
    assert starter.started[0].capability == SYSTEM_INSPECT.name
    assert starter.started[0].authority.commander_id == "local-jerry"


def test_reserved_capabilities_are_refused_before_any_workflow_starts() -> None:
    client, _, starter = build_client()
    response = client.post(
        "/v1/nodes/jobs", json={"capability": RESERVED_CAPABILITY}, headers=HEADERS
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "capability-reserved"
    assert starter.started == []


def test_freezing_stops_admission_before_any_workflow_starts() -> None:
    client, _, starter = build_client()
    frozen = client.post(
        "/v1/nodes/control/freeze", json={"reason": "panic"}, headers=HEADERS
    ).json()
    assert frozen["frozen"] is True
    assert frozen["freeze_epoch"] == 1

    refused = client.post(
        "/v1/nodes/jobs", json={"capability": SYSTEM_INSPECT.name}, headers=HEADERS
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == "dispatch-frozen"
    assert starter.started == []

    listed = client.get("/v1/nodes", headers=HEADERS).json()
    assert listed["dispatch_frozen"] is True


def test_unfreezing_requires_the_current_freeze_epoch() -> None:
    client, _, _ = build_client()
    client.post("/v1/nodes/control/freeze", json={"reason": "panic"}, headers=HEADERS)

    mismatch = client.post(
        "/v1/nodes/control/unfreeze",
        json={"expected_freeze_epoch": 7, "reason": "guessing"},
        headers=HEADERS,
    )
    assert mismatch.status_code == 409
    assert mismatch.json()["detail"] == "freeze-epoch-mismatch"
    assert client.get("/v1/nodes/control", headers=HEADERS).json()["frozen"] is True

    cleared = client.post(
        "/v1/nodes/control/unfreeze",
        json={"expected_freeze_epoch": 1, "reason": "resolved"},
        headers=HEADERS,
    )
    assert cleared.status_code == 200
    assert cleared.json()["frozen"] is False


def test_node_lifecycle_endpoints_change_dispatch_eligibility() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    enrolled = enroll(client, grant["enrollment_token"], generate_node_keypair().public_key)
    node_id = enrolled.json()["node_id"]

    quarantined = client.post(
        f"/v1/nodes/{node_id}/quarantine", json={"reason": "odd behaviour"}, headers=HEADERS
    )
    assert quarantined.status_code == 200
    assert quarantined.json()["state"] == "quarantined"

    restored = client.post(f"/v1/nodes/{node_id}/restore", json={}, headers=HEADERS)
    assert restored.json()["state"] == "pending"

    revoked = client.post(f"/v1/nodes/{node_id}/revoke", json={"reason": "stolen"}, headers=HEADERS)
    assert revoked.json()["state"] == "revoked"

    again = client.post(f"/v1/nodes/{node_id}/restore", json={}, headers=HEADERS)
    assert again.status_code == 409


def test_unknown_nodes_return_not_found() -> None:
    client, _, _ = build_client()
    response = client.post("/v1/nodes/node-missing/quarantine", json={}, headers=HEADERS)
    assert response.status_code == 404


def test_cancelling_signals_the_owning_workflow() -> None:
    client, _, starter = build_client()
    response = client.post("/v1/nodes/jobs/job-42/cancel", json={}, headers=HEADERS)
    assert response.status_code == 202
    assert starter.cancelled == ["job-42"]
    # The frame that actually reaches a live node session is covered by
    # tests/nodes/test_session_dispatch.py::
    # test_cancellation_reaches_the_node_and_produces_a_cancelled_outcome.


def test_cancelling_a_closed_job_is_a_not_found_rather_than_a_server_error() -> None:
    client, _, starter = build_client()
    starter.refuse_cancel = NodeReason.JOB_UNKNOWN

    response = client.post("/v1/nodes/jobs/already-done/cancel", json={}, headers=HEADERS)
    assert response.status_code == 404
    assert response.json()["detail"] == "job-unknown"


def test_the_console_shell_carries_no_data_and_no_credential() -> None:
    client, _, _ = build_client()
    grant = issue(client)
    enroll(client, grant["enrollment_token"], generate_node_keypair().public_key)

    page = client.get("/ui/nodes")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "jerry-windows" not in page.text
    assert TEST_COMMAND_TOKEN not in page.text
    assert grant["enrollment_token"] not in page.text
    # No third-party asset may be pulled into the console.
    assert "http://" not in page.text
    assert "https://" not in page.text


def test_the_audit_endpoint_exposes_a_verifiable_chain() -> None:
    client, _, _ = build_client()
    issue(client)
    body = client.get("/v1/nodes/audit", headers=HEADERS).json()

    assert body["chain_valid"] is True
    assert body["events"][0]["action"] == "enrollment-token-issued"
    assert body["events"][0]["previous_hash"] == "0" * 64
    assert body["head"] == body["events"][-1]["event_hash"]


def test_the_session_endpoint_refuses_a_malformed_handshake() -> None:
    client, _, _ = build_client()
    with client.websocket_connect("/v1/nodes/session") as socket:
        socket.send_text('{"type":"heartbeat","sequence":1}')
        frame = socket.receive_json()
    assert frame["type"] == "session-close"
    assert frame["reason"] == "handshake-frame-unexpected"


def test_the_command_path_still_works_without_a_node_mesh() -> None:
    settings = GatewaySettings(
        environment="test",
        dev_command_token=TEST_COMMAND_TOKEN,  # type: ignore[arg-type]
    )
    client = TestClient(create_app(settings, FakeCommandStarter()))
    assert client.get("/health/live").status_code == 200
    assert client.get("/v1/nodes", headers=HEADERS).status_code == 404


# --- scoped capabilities must be grantable through the operator surface -------------


def test_a_scoped_capability_can_be_granted_through_the_api() -> None:
    client, _runtime, _starter = build_client()
    """Without this the scoped capabilities were ungrantable.

    Every one of them refuses a grant carrying no scope, so an enrollment
    request with no scope field could express only the single capability that
    happens to need none.
    """
    body = issue(
        client,
        capabilities=[SYSTEM_INSPECT.name, "fs.read@1"],
        capability_scopes={"fs.read@1": {"roots": ["C:\\olympus\\share"], "max_bytes": 4096}},
    )

    assert "fs.read@1" in body["granted_capabilities"]
    # Echoed back so the operator sees the bound that was stored, not the one
    # they typed: normalization and clamping happen at mint time.
    assert body["capability_scopes"]["fs.read@1"]["roots"] == ["C:\\olympus\\share"]
    assert body["capability_scopes"]["fs.read@1"]["max_bytes"] == 4096


def test_granting_a_scoped_capability_without_a_scope_is_refused() -> None:
    client, _runtime, _starter = build_client()
    response = client.post(
        "/v1/nodes/enrollments",
        json={
            "node_name": "jerry-windows",
            "kind": "workstation",
            "platform": "windows",
            "capabilities": ["fs.read@1"],
        },
        headers=HEADERS,
    )

    assert response.status_code >= 400
    assert "fs.read@1" not in response.text or "scope" in response.text.lower()


def test_a_scope_naming_the_whole_disk_is_refused_by_the_api() -> None:
    client, _runtime, _starter = build_client()
    response = client.post(
        "/v1/nodes/enrollments",
        json={
            "node_name": "jerry-windows",
            "kind": "workstation",
            "platform": "windows",
            "capabilities": ["fs.read@1"],
            "capability_scopes": {"fs.read@1": {"roots": ["C:\\"]}},
        },
        headers=HEADERS,
    )

    assert response.status_code >= 400


def test_the_node_list_shows_what_each_grant_is_bounded_to() -> None:
    client, _runtime, _starter = build_client()
    # An operator auditing a node should see the bound, not just the name.
    keys = generate_node_keypair()
    issued = issue(
        client,
        capabilities=[SYSTEM_INSPECT.name, "fs.read@1"],
        capability_scopes={"fs.read@1": {"roots": ["C:\\olympus\\share"], "max_bytes": 2048}},
    )
    enroll(client, issued["enrollment_token"], keys.public_key)

    nodes = client.get("/v1/nodes", headers=HEADERS).json()["nodes"]

    assert nodes[0]["capability_scopes"]["fs.read@1"]["roots"] == ["C:\\olympus\\share"]

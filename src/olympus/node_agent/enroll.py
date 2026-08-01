import http.client
import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

ENROLLMENT_PATH = "/v1/nodes/enroll"
_REQUEST_TIMEOUT_SECONDS = 30
_MAX_RESPONSE_BYTES = 65_536


class EnrollmentError(RuntimeError):
    """Raised when the control plane refuses or cannot complete enrollment."""


@dataclass(frozen=True)
class EnrollmentOutcome:
    """What the control plane returns once a node redeems its enrollment token."""

    node_id: str
    node_name: str
    granted_capabilities: tuple[str, ...]
    control_plane_public_key: str
    control_plane_key_id: str
    session_path: str
    protocol: str


def request_json(
    base_url: str,
    path: str,
    *,
    method: str = "POST",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """Exchange JSON over the standard library so nodes need no HTTP client dependency."""
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise EnrollmentError("control plane URL must be an absolute http(s) URL")
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    request_headers.update(headers or {})
    connection: http.client.HTTPConnection
    if parts.scheme == "https":
        connection = http.client.HTTPSConnection(
            parts.hostname,
            parts.port,
            timeout=_REQUEST_TIMEOUT_SECONDS,
            context=ssl_context or ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            parts.hostname, parts.port, timeout=_REQUEST_TIMEOUT_SECONDS
        )
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        raw = response.read(_MAX_RESPONSE_BYTES)
        if response.status >= 400:
            raise EnrollmentError(
                f"control plane refused the request with status {response.status}"
            )
        if response.status == 204 or not raw:
            return {}
        decoded = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError, http.client.HTTPException) as exc:
        raise EnrollmentError("control plane request failed") from exc
    finally:
        connection.close()
    if not isinstance(decoded, dict):
        raise EnrollmentError("control plane returned an unexpected response")
    return decoded


def enroll(
    *,
    control_plane_url: str,
    enrollment_token: str,
    public_key: str,
    node_name: str,
    kind: str,
    node_platform: str,
    architecture: str,
    agent_version: str,
    declared_capabilities: tuple[str, ...],
    ssl_context: ssl.SSLContext | None = None,
) -> EnrollmentOutcome:
    """Redeem a single-use enrollment token and learn the control plane's public key."""
    response = request_json(
        control_plane_url,
        ENROLLMENT_PATH,
        payload={
            "enrollment_token": enrollment_token,
            "public_key": public_key,
            "node_name": node_name,
            "kind": kind,
            "platform": node_platform,
            "architecture": architecture,
            "agent_version": agent_version,
            "declared_capabilities": list(declared_capabilities),
        },
        ssl_context=ssl_context,
    )
    try:
        return EnrollmentOutcome(
            node_id=str(response["node_id"]),
            node_name=str(response["node_name"]),
            granted_capabilities=tuple(str(name) for name in response["granted_capabilities"]),
            control_plane_public_key=str(response["control_plane_public_key"]),
            control_plane_key_id=str(response["control_plane_key_id"]),
            session_path=str(response["session_path"]),
            protocol=str(response["protocol"]),
        )
    except (KeyError, TypeError) as exc:
        raise EnrollmentError("control plane enrollment response was incomplete") from exc

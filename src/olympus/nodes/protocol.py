from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError

from olympus.nodes.errors import NodeMeshError, NodeReason

PROTOCOL_NAME = "olympus-node"
PROTOCOL_VERSION = 1
PROTOCOL_ID = f"{PROTOCOL_NAME}/{PROTOCOL_VERSION}"
SUPPORTED_PROTOCOL_IDS: frozenset[str] = frozenset({PROTOCOL_ID})

MAX_FRAME_BYTES = 262_144
MAX_DECLARED_CAPABILITIES = 32
MAX_PROGRESS_EVENTS_PER_JOB = 200
MAX_ARTIFACTS_PER_JOB = 8
# Base64 payload ceiling, chosen to leave room for the rest of the frame
# inside MAX_FRAME_BYTES. Roughly 144 KiB of raw artifact bytes.
MAX_ARTIFACT_BYTES = 196_608
MAX_CONCURRENT_JOBS_PER_NODE = 4
MAX_RESUME_KEYS = 64

DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 15
DEFAULT_HEARTBEAT_EXPIRY_SECONDS = 45
DEFAULT_HANDSHAKE_TIMEOUT_SECONDS = 10

type Identifier = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
]
type ShortText = Annotated[str, StringConstraints(max_length=512)]
type EncodedBytes = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,512}$")]
type CapabilityName = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+@[1-9][0-9]{0,2}$")
]
type HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class _Frame(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NodeHealthReport(_Frame):
    """Self-reported node health. Untrusted: a node can lie about its own state."""

    active_jobs: int = Field(default=0, ge=0, le=1024)
    cpu_count: int | None = Field(default=None, ge=0, le=4096)
    load_average_1m: float | None = Field(default=None, ge=0, le=10_000)
    memory_total_mib: int | None = Field(default=None, ge=0, le=1 << 24)
    memory_available_mib: int | None = Field(default=None, ge=0, le=1 << 24)
    uptime_seconds: int | None = Field(default=None, ge=0, le=1 << 34)
    agent_uptime_seconds: int | None = Field(default=None, ge=0, le=1 << 34)


class ResumeState(_Frame):
    """Dedupe keys whose terminal results the reconnecting node still holds."""

    completed_dedupe_keys: tuple[HexDigest, ...] = Field(default=(), max_length=MAX_RESUME_KEYS)
    running_dedupe_keys: tuple[HexDigest, ...] = Field(default=(), max_length=MAX_RESUME_KEYS)


class HelloFrame(_Frame):
    type: Literal["hello"] = "hello"
    protocol: ShortText
    node_id: Identifier
    agent_version: ShortText
    platform: ShortText
    architecture: ShortText
    declared_capabilities: tuple[ShortText, ...] = Field(
        default=(), max_length=MAX_DECLARED_CAPABILITIES
    )
    node_nonce: EncodedBytes
    resume: ResumeState = ResumeState()


class ChallengeFrame(_Frame):
    type: Literal["challenge"] = "challenge"
    protocol: ShortText
    session_id: Identifier
    server_nonce: EncodedBytes
    control_plane_key_id: Identifier
    server_proof: EncodedBytes


class AttestFrame(_Frame):
    type: Literal["attest"] = "attest"
    session_id: Identifier
    node_proof: EncodedBytes


class SessionReadyFrame(_Frame):
    type: Literal["session-ready"] = "session-ready"
    session_id: Identifier
    granted_capabilities: tuple[CapabilityName, ...] = Field(
        default=(), max_length=MAX_DECLARED_CAPABILITIES
    )
    # The bounds attached to those grants, delivered over the authenticated
    # session rather than configured on the node. A node that decided its own
    # scope would be answering the one question the control plane exists to
    # answer, and a scope read from local config drifts from the grant silently.
    capability_scopes: dict[CapabilityName, dict[str, Any]] = Field(default_factory=dict)
    heartbeat_interval_seconds: int = Field(ge=1, le=3600)
    heartbeat_expiry_seconds: int = Field(ge=2, le=7200)
    max_frame_bytes: int = Field(ge=1024, le=MAX_FRAME_BYTES)
    max_concurrent_jobs: int = Field(ge=1, le=MAX_CONCURRENT_JOBS_PER_NODE)
    server_time: ShortText


class HeartbeatFrame(_Frame):
    type: Literal["heartbeat"] = "heartbeat"
    sequence: int = Field(ge=0, le=1 << 40)
    health: NodeHealthReport = NodeHealthReport()


class HeartbeatAckFrame(_Frame):
    type: Literal["heartbeat-ack"] = "heartbeat-ack"
    sequence: int = Field(ge=0, le=1 << 40)
    server_time: ShortText


class JobDispatchFrame(_Frame):
    type: Literal["job-dispatch"] = "job-dispatch"
    job_id: Identifier
    attempt: int = Field(ge=1, le=64)
    dedupe_key: HexDigest
    capability: CapabilityName
    parameters: dict[str, Any] = Field(default_factory=dict)
    deadline_seconds: int = Field(ge=1, le=3600)
    max_output_bytes: int = Field(ge=256, le=MAX_FRAME_BYTES)
    max_progress_events: int = Field(default=MAX_PROGRESS_EVENTS_PER_JOB, ge=1, le=10_000)
    issued_at: ShortText


class JobAckFrame(_Frame):
    type: Literal["job-ack"] = "job-ack"
    job_id: Identifier
    attempt: int = Field(ge=1, le=64)
    accepted: bool
    duplicate: bool = False
    reason: ShortText = ""


class JobProgressFrame(_Frame):
    type: Literal["job-progress"] = "job-progress"
    job_id: Identifier
    attempt: int = Field(ge=1, le=64)
    sequence: int = Field(ge=0, le=MAX_PROGRESS_EVENTS_PER_JOB)
    percent: int | None = Field(default=None, ge=0, le=100)
    message: ShortText = ""


class JobArtifactFrame(_Frame):
    type: Literal["job-artifact"] = "job-artifact"
    job_id: Identifier
    attempt: int = Field(ge=1, le=64)
    artifact_id: Identifier
    kind: ShortText
    media_type: ShortText
    sha256: HexDigest
    encoding: Literal["base64"] = "base64"
    data: Annotated[str, StringConstraints(max_length=MAX_ARTIFACT_BYTES)]


class JobResultFrame(_Frame):
    type: Literal["job-result"] = "job-result"
    job_id: Identifier
    attempt: int = Field(ge=1, le=64)
    dedupe_key: HexDigest
    status: Literal["succeeded", "failed", "cancelled", "rejected"]
    output: dict[str, Any] = Field(default_factory=dict)
    output_truncated: bool = False
    artifact_ids: tuple[Identifier, ...] = Field(default=(), max_length=MAX_ARTIFACTS_PER_JOB)
    reason: ShortText = ""
    message: ShortText = ""
    started_at: ShortText = ""
    finished_at: ShortText = ""
    replayed: bool = False


class JobCancelFrame(_Frame):
    type: Literal["job-cancel"] = "job-cancel"
    job_id: Identifier
    attempt: int = Field(ge=1, le=64)
    reason: ShortText = ""


class SessionCloseFrame(_Frame):
    type: Literal["session-close"] = "session-close"
    reason: ShortText
    message: ShortText = ""


type ClientFrame = (
    HelloFrame
    | AttestFrame
    | HeartbeatFrame
    | JobAckFrame
    | JobProgressFrame
    | JobArtifactFrame
    | JobResultFrame
)
type ServerFrame = (
    ChallengeFrame
    | SessionReadyFrame
    | HeartbeatAckFrame
    | JobDispatchFrame
    | JobCancelFrame
    | SessionCloseFrame
)

_CLIENT_ADAPTER: TypeAdapter[ClientFrame] = TypeAdapter(
    Annotated[ClientFrame, Field(discriminator="type")]
)
_SERVER_ADAPTER: TypeAdapter[ServerFrame] = TypeAdapter(
    Annotated[ServerFrame, Field(discriminator="type")]
)


def encode_frame(frame: ClientFrame | ServerFrame) -> str:
    """Serialize a frame and enforce the wire size bound before it is sent."""
    payload = frame.model_dump_json()
    if len(payload.encode("utf-8")) > MAX_FRAME_BYTES:
        raise NodeMeshError(NodeReason.FRAME_TOO_LARGE, "outbound frame exceeds the size bound")
    return payload


def _parse(adapter: TypeAdapter[Any], payload: str) -> Any:
    if len(payload.encode("utf-8")) > MAX_FRAME_BYTES:
        raise NodeMeshError(NodeReason.FRAME_TOO_LARGE, "inbound frame exceeds the size bound")
    try:
        return adapter.validate_json(payload)
    except ValidationError as exc:
        raise NodeMeshError(NodeReason.FRAME_MALFORMED, "inbound frame failed validation") from exc


def parse_client_frame(payload: str) -> ClientFrame:
    """Parse and validate one node-to-control-plane frame."""
    frame: ClientFrame = _parse(_CLIENT_ADAPTER, payload)
    return frame


def parse_server_frame(payload: str) -> ServerFrame:
    """Parse and validate one control-plane-to-node frame."""
    frame: ServerFrame = _parse(_SERVER_ADAPTER, payload)
    return frame


def server_proof_payload(
    *, protocol: str, session_id: str, node_id: str, node_nonce: str
) -> dict[str, str]:
    """Canonical payload the control plane signs to prove its identity to a node."""
    return {
        "purpose": f"{PROTOCOL_NAME}/server-proof",
        "protocol": protocol,
        "session_id": session_id,
        "node_id": node_id,
        "node_nonce": node_nonce,
    }


def node_proof_payload(
    *,
    protocol: str,
    session_id: str,
    node_id: str,
    server_nonce: str,
    capabilities_digest: str,
) -> dict[str, str]:
    """Canonical payload a node signs to prove its identity to the control plane."""
    return {
        "purpose": f"{PROTOCOL_NAME}/node-proof",
        "protocol": protocol,
        "session_id": session_id,
        "node_id": node_id,
        "server_nonce": server_nonce,
        "capabilities_digest": capabilities_digest,
    }

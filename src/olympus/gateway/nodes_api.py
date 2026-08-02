from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal, Protocol
from uuid import uuid4

from fastapi import APIRouter, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi import status as http_status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from olympus.gateway.auth import require_operator
from olympus.gateway.settings import GatewaySettings
from olympus.gateway.ui import render_node_console
from olympus.nodes.audit import AuditAction, AuditDecision, AuditDraft, NodeAuditEvent
from olympus.nodes.capabilities import (
    CAPABILITY_CATALOG,
    CapabilityDescriptor,
    require_dispatchable_capability,
)
from olympus.nodes.channel import CLOSE_NORMAL, ChannelClosed
from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import (
    DispatchAuthority,
    DispatchControlState,
    NodeJobRecord,
    NodeKind,
    NodePlatform,
    NodeView,
)
from olympus.nodes.protocol import PROTOCOL_ID
from olympus.nodes.registry import NodeDescription, NodeRegistry
from olympus.nodes.session import NodeSession

SESSION_PATH = "/v1/nodes/session"
ENROLL_PATH = "/v1/nodes/enroll"

_PERMANENT_REFUSALS: frozenset[NodeReason] = frozenset(
    {
        NodeReason.CAPABILITY_UNKNOWN,
        NodeReason.CAPABILITY_RESERVED,
        NodeReason.CAPABILITY_NOT_GRANTED,
        NodeReason.NODE_UNKNOWN,
        NodeReason.NODE_REVOKED,
        NodeReason.DISPATCH_FROZEN,
    }
)

_STATUS_FOR_REASON: dict[NodeReason, int] = {
    NodeReason.NODE_UNKNOWN: http_status.HTTP_404_NOT_FOUND,
    NodeReason.JOB_UNKNOWN: http_status.HTTP_404_NOT_FOUND,
    NodeReason.ENROLLMENT_UNKNOWN: http_status.HTTP_403_FORBIDDEN,
    NodeReason.ENROLLMENT_MALFORMED: http_status.HTTP_403_FORBIDDEN,
    NodeReason.ENROLLMENT_EXPIRED: http_status.HTTP_403_FORBIDDEN,
    NodeReason.ENROLLMENT_CONSUMED: http_status.HTTP_403_FORBIDDEN,
    NodeReason.ENROLLMENT_REVOKED: http_status.HTTP_403_FORBIDDEN,
    NodeReason.ENROLLMENT_SCOPE_MISMATCH: http_status.HTTP_403_FORBIDDEN,
    NodeReason.ENROLLMENT_KEY_INVALID: http_status.HTTP_400_BAD_REQUEST,
    NodeReason.ENROLLMENT_DESCRIPTION_INVALID: http_status.HTTP_400_BAD_REQUEST,
    NodeReason.DISPATCH_FROZEN: http_status.HTTP_409_CONFLICT,
    NodeReason.NOT_FROZEN: http_status.HTTP_409_CONFLICT,
    NodeReason.FREEZE_EPOCH_MISMATCH: http_status.HTTP_409_CONFLICT,
    NodeReason.NODE_QUARANTINED: http_status.HTTP_409_CONFLICT,
    NodeReason.NODE_REVOKED: http_status.HTTP_409_CONFLICT,
    NodeReason.NODE_OFFLINE: http_status.HTTP_409_CONFLICT,
    NodeReason.DISPATCH_NO_ELIGIBLE_NODE: http_status.HTTP_409_CONFLICT,
    NodeReason.CAPABILITY_UNKNOWN: http_status.HTTP_400_BAD_REQUEST,
    NodeReason.CAPABILITY_RESERVED: http_status.HTTP_403_FORBIDDEN,
    NodeReason.CAPABILITY_NOT_GRANTED: http_status.HTTP_403_FORBIDDEN,
    NodeReason.CAPABILITY_NOT_DECLARED: http_status.HTTP_409_CONFLICT,
}

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)]


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IssueEnrollmentRequest(_Payload):
    node_name: Name
    kind: NodeKind = NodeKind.WORKSTATION
    platform: NodePlatform = NodePlatform.WINDOWS
    capabilities: tuple[Name, ...] = Field(min_length=1, max_length=32)
    ttl_seconds: int | None = Field(default=None, ge=60, le=3600)


class IssuedEnrollmentResponse(_Payload):
    token_id: str
    enrollment_token: str
    node_name: str
    kind: NodeKind
    platform: NodePlatform
    granted_capabilities: tuple[str, ...]
    expires_at: datetime
    protocol: str = PROTOCOL_ID


class EnrollRequest(_Payload):
    enrollment_token: Annotated[str, StringConstraints(min_length=16, max_length=256)]
    public_key: Annotated[str, StringConstraints(min_length=16, max_length=128)]
    node_name: Name
    kind: NodeKind = NodeKind.WORKSTATION
    platform: NodePlatform = NodePlatform.WINDOWS
    architecture: Name = "unknown"
    agent_version: Name = "unknown"
    declared_capabilities: tuple[Name, ...] = Field(default=(), max_length=32)


class EnrollResponse(_Payload):
    node_id: str
    node_name: str
    granted_capabilities: tuple[str, ...]
    control_plane_public_key: str
    control_plane_key_id: str
    session_path: str = SESSION_PATH
    protocol: str = PROTOCOL_ID
    heartbeat_interval_seconds: int


class HealthResponse(_Payload):
    reported_at: datetime
    active_jobs: int
    cpu_count: int | None
    load_average_1m: float | None
    memory_total_mib: int | None
    memory_available_mib: int | None
    uptime_seconds: int | None
    agent_uptime_seconds: int | None


class NodeResponse(_Payload):
    node_id: str
    node_name: str
    kind: NodeKind
    platform: NodePlatform
    architecture: str
    agent_version: str
    state: str
    connected: bool
    granted_capabilities: tuple[str, ...]
    declared_capabilities: tuple[str, ...]
    effective_capabilities: tuple[str, ...]
    enrolled_at: datetime
    last_heartbeat_at: datetime | None
    heartbeat_age_seconds: float | None
    labels: dict[str, str]
    output_trust_label: str
    health: HealthResponse | None

    @classmethod
    def of(cls, view: NodeView) -> "NodeResponse":
        return cls(
            node_id=view.node_id,
            node_name=view.node_name,
            kind=view.kind,
            platform=view.platform,
            architecture=view.architecture,
            agent_version=view.agent_version,
            state=view.state.value,
            connected=view.connected,
            granted_capabilities=view.granted_capabilities,
            declared_capabilities=view.declared_capabilities,
            effective_capabilities=view.effective_capabilities,
            enrolled_at=view.enrolled_at,
            last_heartbeat_at=view.last_heartbeat_at,
            heartbeat_age_seconds=view.heartbeat_age_seconds,
            labels=dict(view.labels),
            output_trust_label=view.output_trust_label.value,
            health=None
            if view.health is None
            else HealthResponse(
                reported_at=view.health.reported_at,
                active_jobs=view.health.active_jobs,
                cpu_count=view.health.cpu_count,
                load_average_1m=view.health.load_average_1m,
                memory_total_mib=view.health.memory_total_mib,
                memory_available_mib=view.health.memory_available_mib,
                uptime_seconds=view.health.uptime_seconds,
                agent_uptime_seconds=view.health.agent_uptime_seconds,
            ),
        )


class NodeListResponse(_Payload):
    nodes: tuple[NodeResponse, ...]
    dispatch_frozen: bool
    freeze_epoch: int


class CapabilityResponse(_Payload):
    name: str
    title: str
    summary: str
    status: str
    risk: str
    mutating: bool
    requires_approval: bool
    output_trust_label: str
    max_runtime_seconds: int
    max_output_bytes: int

    @classmethod
    def of(cls, descriptor: CapabilityDescriptor) -> "CapabilityResponse":
        return cls(
            name=descriptor.name,
            title=descriptor.title,
            summary=descriptor.summary,
            status=descriptor.status.value,
            risk=descriptor.risk.value,
            mutating=descriptor.mutating,
            requires_approval=descriptor.requires_approval,
            output_trust_label=descriptor.output_trust_label.value,
            max_runtime_seconds=descriptor.max_runtime_seconds,
            max_output_bytes=descriptor.max_output_bytes,
        )


class StartJobRequest(_Payload):
    capability: Name
    parameters: dict[str, Any] = Field(default_factory=dict)
    node_id: Annotated[str, StringConstraints(max_length=128)] | None = None


class JobAcceptedResponse(_Payload):
    job_id: str
    workflow_id: str
    capability: str
    status: Literal["accepted"] = "accepted"


class JobResponse(_Payload):
    job_id: str
    node_id: str
    capability: str
    status: str
    attempt: int
    progress_events: int
    last_message: str
    reason: str
    created_at: datetime
    updated_at: datetime
    commander_id: str

    @classmethod
    def of(cls, record: NodeJobRecord) -> "JobResponse":
        return cls(
            job_id=record.job_id,
            node_id=record.node_id,
            capability=record.capability,
            status=record.status.value,
            attempt=record.attempt,
            progress_events=record.progress_events,
            last_message=record.last_message,
            reason=record.reason,
            created_at=record.created_at,
            updated_at=record.updated_at,
            commander_id=record.authority.commander_id,
        )


class JobListResponse(_Payload):
    jobs: tuple[JobResponse, ...]


class ControlResponse(_Payload):
    frozen: bool
    freeze_epoch: int
    changed_at: datetime | None
    reason: str

    @classmethod
    def of(cls, state: DispatchControlState) -> "ControlResponse":
        return cls(
            frozen=state.frozen,
            freeze_epoch=state.freeze_epoch,
            changed_at=state.changed_at,
            reason=state.reason,
        )


class FreezeRequest(_Payload):
    reason: Reason = "operator freeze"


class UnfreezeRequest(_Payload):
    expected_freeze_epoch: int = Field(ge=1)
    reason: Reason = ""


class LifecycleRequest(_Payload):
    reason: Reason = ""


class AuditEventResponse(_Payload):
    sequence: int
    recorded_at: str
    actor: str
    action: str
    decision: str
    reason: str
    node_id: str | None
    job_id: str | None
    payload_digest: str
    previous_hash: str
    event_hash: str

    @classmethod
    def of(cls, event: NodeAuditEvent) -> "AuditEventResponse":
        return cls(
            sequence=event.sequence,
            recorded_at=event.recorded_at,
            actor=event.actor,
            action=event.action.value,
            decision=event.decision.value,
            reason=event.reason,
            node_id=event.node_id,
            job_id=event.job_id,
            payload_digest=event.payload_digest,
            previous_hash=event.previous_hash,
            event_hash=event.event_hash,
        )


class AuditResponse(_Payload):
    chain_valid: bool
    head: str
    events: tuple[AuditEventResponse, ...]


class NodeJobStarter(Protocol):
    """Seam over Temporal so the gateway starts jobs without owning their state."""

    async def start(self, request: NodeJobRequest) -> str: ...

    async def cancel(self, job_id: str) -> None: ...


@dataclass
class NodeMeshRuntime:
    """Everything the gateway needs to serve the mesh, injected at construction."""

    registry: NodeRegistry
    dispatch: NodeDispatchService
    control_plane_private_key: str
    control_plane_public_key: str
    control_plane_key_id: str
    job_starter: NodeJobStarter


class WebSocketServerChannel:
    """Control-plane channel over an inbound-from-node WebSocket connection."""

    def __init__(self, websocket: WebSocket) -> None:
        self._websocket = websocket
        self._closed = False

    async def send(self, payload: str) -> None:
        if self._closed:
            raise ChannelClosed("send on a closed channel")
        try:
            await self._websocket.send_text(payload)
        except (WebSocketDisconnect, RuntimeError) as exc:
            self._closed = True
            raise ChannelClosed("node closed the connection") from exc

    async def receive(self) -> str:
        if self._closed:
            raise ChannelClosed("receive on a closed channel")
        try:
            return await self._websocket.receive_text()
        except (WebSocketDisconnect, RuntimeError, KeyError) as exc:
            self._closed = True
            raise ChannelClosed("node closed the connection") from exc

    async def close(self, *, code: int = CLOSE_NORMAL, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._websocket.close(code=code, reason=reason[:120])
        except (WebSocketDisconnect, RuntimeError):
            return


def _refuse(exc: NodeMeshError) -> HTTPException:
    """Map a typed refusal to a status code, exposing only the stable reason code."""
    return HTTPException(
        status_code=_STATUS_FOR_REASON.get(exc.reason, http_status.HTTP_400_BAD_REQUEST),
        detail=exc.reason.value,
    )


def is_permanent_refusal(reason: NodeReason) -> bool:
    """Refusals that will not become allowable by retrying the same request."""
    return reason in _PERMANENT_REFUSALS


def register_node_routes(
    app: FastAPI, *, settings: GatewaySettings, runtime: NodeMeshRuntime
) -> None:
    """Mount the node-mesh surface on the existing gateway application."""
    router = APIRouter()
    registry = runtime.registry
    dispatch = runtime.dispatch

    def operator(
        commander_ids: list[str], authority_lease_ids: list[str], authorization: list[str] | None
    ) -> DispatchAuthority:
        return require_operator(
            settings=settings,
            authorization=authorization,
            commander_ids=commander_ids,
            authority_lease_ids=authority_lease_ids,
        )

    @router.post(
        "/v1/nodes/enrollments",
        response_model=IssuedEnrollmentResponse,
        status_code=http_status.HTTP_201_CREATED,
    )
    async def issue_enrollment(
        request: IssueEnrollmentRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> IssuedEnrollmentResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        try:
            issued = await registry.issue_enrollment_token(
                node_name=request.node_name,
                kind=request.kind,
                platform=request.platform,
                granted_capabilities=request.capabilities,
                issued_by=authority.commander_id,
                ttl_seconds=request.ttl_seconds or settings.node_enrollment_ttl_seconds,
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc
        return IssuedEnrollmentResponse(
            token_id=issued.token_id,
            enrollment_token=issued.presented,
            node_name=issued.node_name,
            kind=issued.kind,
            platform=issued.platform,
            granted_capabilities=issued.granted_capabilities,
            expires_at=issued.expires_at,
        )

    @router.delete("/v1/nodes/enrollments/{token_id}", status_code=http_status.HTTP_204_NO_CONTENT)
    async def revoke_enrollment(
        token_id: str,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> None:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        try:
            await registry.revoke_enrollment_token(
                token_id, actor=authority.commander_id, reason="operator revocation"
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc

    @router.post(ENROLL_PATH, response_model=EnrollResponse, status_code=http_status.HTTP_200_OK)
    async def enroll_node(request: EnrollRequest) -> EnrollResponse:
        """Redeem a single-use enrollment token. Authenticated by the token alone."""
        try:
            record = await registry.redeem_enrollment_token(
                presented=request.enrollment_token,
                description=NodeDescription(
                    node_name=request.node_name,
                    kind=request.kind,
                    platform=request.platform,
                    architecture=request.architecture,
                    agent_version=request.agent_version,
                    declared_capabilities=request.declared_capabilities,
                ),
                public_key=request.public_key,
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc
        return EnrollResponse(
            node_id=record.node_id,
            node_name=record.node_name,
            granted_capabilities=record.granted_capabilities,
            control_plane_public_key=runtime.control_plane_public_key,
            control_plane_key_id=runtime.control_plane_key_id,
            heartbeat_interval_seconds=registry.heartbeat_interval_seconds,
        )

    @router.get("/v1/nodes", response_model=NodeListResponse)
    async def list_nodes(
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> NodeListResponse:
        operator(commander_ids, authority_lease_ids, authorization)
        await registry.sweep_expired_heartbeats()
        control = await registry.dispatch_control()
        return NodeListResponse(
            nodes=tuple(NodeResponse.of(view) for view in await registry.list_views()),
            dispatch_frozen=control.frozen,
            freeze_epoch=control.freeze_epoch,
        )

    @router.get("/v1/nodes/capabilities", response_model=tuple[CapabilityResponse, ...])
    async def list_capabilities(
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> tuple[CapabilityResponse, ...]:
        operator(commander_ids, authority_lease_ids, authorization)
        return tuple(
            CapabilityResponse.of(descriptor)
            for descriptor in sorted(CAPABILITY_CATALOG.values(), key=lambda item: item.name)
        )

    @router.post("/v1/nodes/{node_id}/quarantine", response_model=NodeResponse)
    async def quarantine(
        node_id: str,
        request: LifecycleRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> NodeResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        try:
            record = await registry.quarantine_node(
                node_id, actor=authority.commander_id, reason=request.reason or "operator request"
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc
        return NodeResponse.of(registry.view_of(record, registry.now()))

    @router.post("/v1/nodes/{node_id}/restore", response_model=NodeResponse)
    async def restore(
        node_id: str,
        request: LifecycleRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> NodeResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        try:
            record = await registry.restore_node(
                node_id, actor=authority.commander_id, reason=request.reason
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc
        return NodeResponse.of(registry.view_of(record, registry.now()))

    @router.post("/v1/nodes/{node_id}/revoke", response_model=NodeResponse)
    async def revoke(
        node_id: str,
        request: LifecycleRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> NodeResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        try:
            record = await registry.revoke_node(
                node_id, actor=authority.commander_id, reason=request.reason or "operator request"
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc
        session = dispatch.session_for(node_id)
        if session is not None:
            await session.shutdown(reason=NodeReason.NODE_REVOKED.value)
        return NodeResponse.of(registry.view_of(record, registry.now()))

    @router.post(
        "/v1/nodes/jobs",
        response_model=JobAcceptedResponse,
        status_code=http_status.HTTP_202_ACCEPTED,
    )
    async def start_job(
        request: StartJobRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> JobAcceptedResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        job_request = NodeJobRequest(
            job_id=f"node-job-{_new_identifier()}",
            capability=request.capability,
            authority=authority,
            parameters=dict(request.parameters),
            node_id=request.node_id,
        )
        try:
            # Admission refuses before any durable state exists. The dispatch
            # activity checks the same conditions again immediately before the
            # frame is written, so a freeze that lands mid-flight still wins.
            require_dispatchable_capability(request.capability)
            control = await registry.dispatch_control()
            if control.frozen:
                raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")
            workflow_id = await runtime.job_starter.start(job_request)
        except NodeMeshError as exc:
            await registry.record_audit(
                AuditDraft(
                    actor=authority.commander_id,
                    action=AuditAction.DISPATCH_REFUSED,
                    decision=AuditDecision.DENY,
                    reason=exc.reason.value,
                    job_id=job_request.job_id,
                    payload={"capability": request.capability},
                )
            )
            raise _refuse(exc) from exc
        return JobAcceptedResponse(
            job_id=job_request.job_id,
            workflow_id=workflow_id,
            capability=job_request.capability,
        )

    @router.get("/v1/nodes/jobs", response_model=JobListResponse)
    async def list_jobs(
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> JobListResponse:
        operator(commander_ids, authority_lease_ids, authorization)
        return JobListResponse(jobs=tuple(JobResponse.of(job) for job in dispatch.jobs()))

    @router.post("/v1/nodes/jobs/{job_id}/cancel", status_code=http_status.HTTP_202_ACCEPTED)
    async def cancel_job(
        job_id: str,
        request: LifecycleRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> dict[str, str]:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        # Signal the workflow first, but a job whose workflow has already closed
        # must still reach the node: a stale cancel is a 404, never a 500, and
        # never a reason to skip the session-level cancel frame.
        signalled = True
        try:
            await runtime.job_starter.cancel(job_id)
        except NodeMeshError as exc:
            signalled = False
            refusal = _refuse(exc)
        cancelled = await dispatch.cancel_job(
            job_id,
            reason=request.reason or NodeReason.JOB_CANCELLED.value,
            actor=authority.commander_id,
        )
        if not signalled and not cancelled:
            raise refusal
        return {"job_id": job_id, "status": "cancelling"}

    @router.get("/v1/nodes/control", response_model=ControlResponse)
    async def read_control(
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> ControlResponse:
        operator(commander_ids, authority_lease_ids, authorization)
        return ControlResponse.of(await registry.dispatch_control())

    @router.post("/v1/nodes/control/freeze", response_model=ControlResponse)
    async def freeze(
        request: FreezeRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> ControlResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        return ControlResponse.of(
            await dispatch.freeze(actor=authority.commander_id, reason=request.reason)
        )

    @router.post("/v1/nodes/control/unfreeze", response_model=ControlResponse)
    async def unfreeze(
        request: UnfreezeRequest,
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> ControlResponse:
        authority = operator(commander_ids, authority_lease_ids, authorization)
        try:
            state = await dispatch.unfreeze(
                actor=authority.commander_id,
                expected_freeze_epoch=request.expected_freeze_epoch,
                reason=request.reason,
            )
        except NodeMeshError as exc:
            raise _refuse(exc) from exc
        return ControlResponse.of(state)

    @router.get("/v1/nodes/audit", response_model=AuditResponse)
    async def read_audit(
        commander_ids: Annotated[list[str], Header(alias="X-Olympus-Commander")],
        authority_lease_ids: Annotated[list[str], Header(alias="X-Olympus-Authority-Lease")],
        authorization: Annotated[list[str] | None, Header()] = None,
        limit: int = 100,
    ) -> AuditResponse:
        operator(commander_ids, authority_lease_ids, authorization)
        events = await registry.audit_events()
        selected = events[-max(min(limit, 500), 1) :]
        return AuditResponse(
            chain_valid=await registry.verify_audit(),
            head=await registry.audit_head(),
            events=tuple(AuditEventResponse.of(event) for event in selected),
        )

    @router.get("/ui/nodes", response_class=HTMLResponse, include_in_schema=False)
    async def node_console() -> HTMLResponse:
        """Serve the operator console shell.

        The shell carries no node data and no credential. Every data endpoint it
        calls still requires the operator credential, which the browser holds only
        in session storage.
        """
        return HTMLResponse(render_node_console())

    app.include_router(router)

    @app.websocket(SESSION_PATH)
    async def node_session(websocket: WebSocket) -> None:
        await websocket.accept()
        session = NodeSession(
            channel=WebSocketServerChannel(websocket),
            registry=registry,
            control_plane_private_key=runtime.control_plane_private_key,
            control_plane_key_id=runtime.control_plane_key_id,
        )
        try:
            await session.handshake()
        except (NodeMeshError, ChannelClosed):
            return
        await dispatch.attach_session(session)
        try:
            await session.pump()
        finally:
            await dispatch.detach_session(session)


def _new_identifier() -> str:
    return str(uuid4())

from datetime import UTC, datetime, timedelta

import pytest

from olympus.nodes.audit import AuditAction, AuditDecision
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import NodeHealthSnapshot, NodeKind, NodePlatform, NodeState
from olympus.nodes.registry import NodeDescription, NodeRegistry

RESERVED_CAPABILITY = "shell.powershell@1"
UNKNOWN_CAPABILITY = "does.not@9"


class Clock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 8, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def build_registry(clock: Clock) -> NodeRegistry:
    return NodeRegistry(
        clock=clock,
        heartbeat_interval_seconds=5,
        heartbeat_expiry_seconds=15,
    )


def description(
    *,
    node_name: str = "jerry-windows",
    kind: NodeKind = NodeKind.WORKSTATION,
    platform: NodePlatform = NodePlatform.WINDOWS,
    capabilities: tuple[str, ...] = (SYSTEM_INSPECT.name,),
) -> NodeDescription:
    return NodeDescription(
        node_name=node_name,
        kind=kind,
        platform=platform,
        architecture="AMD64",
        agent_version="0.1.0",
        declared_capabilities=capabilities,
    )


async def enroll(registry: NodeRegistry, **overrides: object) -> tuple[str, str]:
    issued = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="local-jerry",
    )
    keys = generate_node_keypair()
    record = await registry.redeem_enrollment_token(
        presented=issued.presented,
        description=description(**overrides),  # type: ignore[arg-type]
        public_key=keys.public_key,
    )
    return record.node_id, issued.presented


async def test_enrollment_issues_a_single_use_token_and_never_stores_the_secret() -> None:
    clock = Clock()
    registry = build_registry(clock)
    issued = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="local-jerry",
    )

    stored = (await registry.enrollment_tokens())[0]
    assert issued.presented.startswith("olynode_")
    assert issued.presented not in stored.secret_hash
    assert len(stored.secret_hash) == 64
    assert stored.consumed is False
    assert issued.expires_at == clock.now + timedelta(seconds=registry.enrollment_ttl_seconds)


async def test_reserved_capabilities_cannot_be_granted() -> None:
    registry = build_registry(Clock())
    with pytest.raises(NodeMeshError) as failure:
        await registry.issue_enrollment_token(
            node_name="jerry-windows",
            kind=NodeKind.WORKSTATION,
            platform=NodePlatform.WINDOWS,
            granted_capabilities=[RESERVED_CAPABILITY],
            issued_by="local-jerry",
        )
    assert failure.value.reason is NodeReason.CAPABILITY_RESERVED


async def test_expired_enrollment_token_is_refused() -> None:
    clock = Clock()
    registry = build_registry(clock)
    issued = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="local-jerry",
        ttl_seconds=60,
    )
    clock.advance(61)

    with pytest.raises(NodeMeshError) as failure:
        await registry.redeem_enrollment_token(
            presented=issued.presented,
            description=description(),
            public_key=generate_node_keypair().public_key,
        )
    assert failure.value.reason is NodeReason.ENROLLMENT_EXPIRED
    rejected = [
        event
        for event in await registry.audit_events()
        if event.action is AuditAction.ENROLLMENT_REJECTED
    ]
    assert rejected and rejected[-1].decision is AuditDecision.DENY


async def test_replaying_a_consumed_token_with_a_different_key_is_refused() -> None:
    registry = build_registry(Clock())
    _, presented = await enroll(registry)

    with pytest.raises(NodeMeshError) as failure:
        await registry.redeem_enrollment_token(
            presented=presented,
            description=description(),
            public_key=generate_node_keypair().public_key,
        )
    assert failure.value.reason is NodeReason.ENROLLMENT_CONSUMED


async def test_retrying_enrollment_with_the_same_key_returns_the_same_node() -> None:
    registry = build_registry(Clock())
    issued = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="local-jerry",
    )
    keys = generate_node_keypair()
    first = await registry.redeem_enrollment_token(
        presented=issued.presented, description=description(), public_key=keys.public_key
    )
    second = await registry.redeem_enrollment_token(
        presented=issued.presented, description=description(), public_key=keys.public_key
    )
    assert first.node_id == second.node_id


async def test_revoked_enrollment_token_cannot_be_redeemed() -> None:
    registry = build_registry(Clock())
    issued = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="local-jerry",
    )
    await registry.revoke_enrollment_token(issued.token_id, actor="local-jerry", reason="lost")

    with pytest.raises(NodeMeshError) as failure:
        await registry.redeem_enrollment_token(
            presented=issued.presented,
            description=description(),
            public_key=generate_node_keypair().public_key,
        )
    assert failure.value.reason is NodeReason.ENROLLMENT_REVOKED


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"node_name": "other-machine"}, NodeReason.ENROLLMENT_SCOPE_MISMATCH),
        ({"platform": NodePlatform.LINUX}, NodeReason.ENROLLMENT_SCOPE_MISMATCH),
        ({"kind": NodeKind.CLOUD_WORKER}, NodeReason.ENROLLMENT_SCOPE_MISMATCH),
    ],
)
async def test_enrollment_scope_is_enforced(
    overrides: dict[str, object], reason: NodeReason
) -> None:
    registry = build_registry(Clock())
    issued = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="local-jerry",
    )
    with pytest.raises(NodeMeshError) as failure:
        await registry.redeem_enrollment_token(
            presented=issued.presented,
            description=description(**overrides),  # type: ignore[arg-type]
            public_key=generate_node_keypair().public_key,
        )
    assert failure.value.reason is reason


async def test_malformed_enrollment_token_is_refused() -> None:
    registry = build_registry(Clock())
    with pytest.raises(NodeMeshError) as failure:
        await registry.redeem_enrollment_token(
            presented="not-a-real-grant",
            description=description(),
            public_key=generate_node_keypair().public_key,
        )
    assert failure.value.reason is NodeReason.ENROLLMENT_MALFORMED


async def test_a_node_declaration_cannot_widen_its_grant() -> None:
    registry = build_registry(Clock())
    node_id, _ = await enroll(
        registry, capabilities=(SYSTEM_INSPECT.name, RESERVED_CAPABILITY, UNKNOWN_CAPABILITY)
    )
    record = await registry.get_node(node_id)

    assert record.granted_capabilities == (SYSTEM_INSPECT.name,)
    assert RESERVED_CAPABILITY in record.declared_capabilities
    assert registry.effective_capabilities(record) == (SYSTEM_INSPECT.name,)


async def test_heartbeat_expiry_takes_a_node_offline_and_is_audited() -> None:
    clock = Clock()
    registry = build_registry(clock)
    node_id, _ = await enroll(registry)
    await registry.attach_session(
        node_id=node_id,
        session_id="nsx-1",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="AMD64",
    )
    record = await registry.get_node(node_id)
    assert registry.state_of(record, clock.now) is NodeState.ONLINE

    clock.advance(16)
    record = await registry.get_node(node_id)
    assert registry.state_of(record, clock.now) is NodeState.OFFLINE

    expired = await registry.sweep_expired_heartbeats()
    assert expired == (node_id,)
    assert (await registry.get_node(node_id)).session_id is None
    assert any(
        event.action is AuditAction.HEARTBEAT_EXPIRED for event in await registry.audit_events()
    )


async def test_heartbeat_from_a_replaced_session_is_refused() -> None:
    clock = Clock()
    registry = build_registry(clock)
    node_id, _ = await enroll(registry)
    await registry.attach_session(
        node_id=node_id,
        session_id="nsx-1",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="AMD64",
    )
    await registry.attach_session(
        node_id=node_id,
        session_id="nsx-2",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="AMD64",
    )

    with pytest.raises(NodeMeshError) as failure:
        await registry.record_heartbeat(
            node_id=node_id,
            session_id="nsx-1",
            health=NodeHealthSnapshot(reported_at=clock.now),
        )
    assert failure.value.reason is NodeReason.NODE_SESSION_REPLACED


async def test_a_stale_session_cannot_detach_the_current_one() -> None:
    registry = build_registry(Clock())
    node_id, _ = await enroll(registry)
    await registry.attach_session(
        node_id=node_id,
        session_id="nsx-1",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="AMD64",
    )
    await registry.attach_session(
        node_id=node_id,
        session_id="nsx-2",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="AMD64",
    )
    await registry.detach_session(node_id=node_id, session_id="nsx-1")
    assert (await registry.get_node(node_id)).session_id == "nsx-2"


async def online_node(registry: NodeRegistry) -> str:
    node_id, _ = await enroll(registry)
    await registry.attach_session(
        node_id=node_id,
        session_id="nsx-1",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="AMD64",
    )
    return node_id


async def test_dispatch_admission_matrix() -> None:
    clock = Clock()
    registry = build_registry(clock)
    node_id = await online_node(registry)

    assert (
        await registry.assert_dispatchable(node_id=node_id, capability=SYSTEM_INSPECT.name)
    ).node_id == node_id

    with pytest.raises(NodeMeshError) as reserved:
        await registry.assert_dispatchable(node_id=node_id, capability=RESERVED_CAPABILITY)
    assert reserved.value.reason is NodeReason.CAPABILITY_RESERVED

    with pytest.raises(NodeMeshError) as unknown_node:
        await registry.assert_dispatchable(node_id="node-nope", capability=SYSTEM_INSPECT.name)
    assert unknown_node.value.reason is NodeReason.NODE_UNKNOWN

    await registry.quarantine_node(node_id, actor="local-jerry", reason="suspicious")
    with pytest.raises(NodeMeshError) as quarantined:
        await registry.assert_dispatchable(node_id=node_id, capability=SYSTEM_INSPECT.name)
    assert quarantined.value.reason is NodeReason.NODE_QUARANTINED

    await registry.restore_node(node_id, actor="local-jerry")
    await registry.revoke_node(node_id, actor="local-jerry", reason="decommissioned")
    with pytest.raises(NodeMeshError) as revoked:
        await registry.assert_dispatchable(node_id=node_id, capability=SYSTEM_INSPECT.name)
    assert revoked.value.reason is NodeReason.NODE_REVOKED


async def test_offline_nodes_are_not_dispatchable() -> None:
    clock = Clock()
    registry = build_registry(clock)
    node_id = await online_node(registry)
    clock.advance(60)

    with pytest.raises(NodeMeshError) as failure:
        await registry.assert_dispatchable(node_id=node_id, capability=SYSTEM_INSPECT.name)
    assert failure.value.reason is NodeReason.NODE_OFFLINE


async def test_selection_refuses_when_no_online_node_offers_the_capability() -> None:
    registry = build_registry(Clock())
    await enroll(registry)

    with pytest.raises(NodeMeshError) as failure:
        await registry.select_node(capability=SYSTEM_INSPECT.name)
    assert failure.value.reason is NodeReason.DISPATCH_NO_ELIGIBLE_NODE


async def test_freeze_is_idempotent_and_blocks_admission_and_enrollment() -> None:
    registry = build_registry(Clock())
    node_id = await online_node(registry)

    first = await registry.freeze_dispatch(actor="local-jerry", reason="panic")
    second = await registry.freeze_dispatch(actor="local-jerry", reason="panic again")
    assert first.freeze_epoch == second.freeze_epoch == 1

    with pytest.raises(NodeMeshError) as dispatch_failure:
        await registry.assert_dispatchable(node_id=node_id, capability=SYSTEM_INSPECT.name)
    assert dispatch_failure.value.reason is NodeReason.DISPATCH_FROZEN

    with pytest.raises(NodeMeshError) as enrollment_failure:
        await registry.issue_enrollment_token(
            node_name="another",
            kind=NodeKind.WORKSTATION,
            platform=NodePlatform.WINDOWS,
            granted_capabilities=[SYSTEM_INSPECT.name],
            issued_by="local-jerry",
        )
    assert enrollment_failure.value.reason is NodeReason.DISPATCH_FROZEN


async def test_unfreeze_requires_the_exact_freeze_epoch() -> None:
    registry = build_registry(Clock())
    frozen = await registry.freeze_dispatch(actor="local-jerry", reason="panic")

    with pytest.raises(NodeMeshError) as mismatch:
        await registry.unfreeze_dispatch(actor="local-jerry", expected_freeze_epoch=99)
    assert mismatch.value.reason is NodeReason.FREEZE_EPOCH_MISMATCH
    assert (await registry.dispatch_control()).frozen is True

    thawed = await registry.unfreeze_dispatch(
        actor="local-jerry", expected_freeze_epoch=frozen.freeze_epoch
    )
    assert thawed.frozen is False

    with pytest.raises(NodeMeshError) as not_frozen:
        await registry.unfreeze_dispatch(actor="local-jerry", expected_freeze_epoch=1)
    assert not_frozen.value.reason is NodeReason.NOT_FROZEN


async def test_freeze_epochs_advance_monotonically() -> None:
    registry = build_registry(Clock())
    first = await registry.freeze_dispatch(actor="local-jerry", reason="one")
    await registry.unfreeze_dispatch(actor="local-jerry", expected_freeze_epoch=first.freeze_epoch)
    second = await registry.freeze_dispatch(actor="local-jerry", reason="two")
    assert second.freeze_epoch == first.freeze_epoch + 1


async def test_revocation_is_irreversible() -> None:
    registry = build_registry(Clock())
    node_id = await online_node(registry)
    await registry.revoke_node(node_id, actor="local-jerry", reason="stolen laptop")

    with pytest.raises(NodeMeshError) as failure:
        await registry.restore_node(node_id, actor="local-jerry")
    assert failure.value.reason is NodeReason.NODE_REVOKED

    with pytest.raises(NodeMeshError) as attach_failure:
        await registry.attach_session(
            node_id=node_id,
            session_id="nsx-2",
            declared_capabilities=[SYSTEM_INSPECT.name],
            agent_version="0.1.0",
            architecture="AMD64",
        )
    assert attach_failure.value.reason is NodeReason.NODE_REVOKED

"""Adversarial tests for issuing and spending node-mutation approvals.

An approval is the only thing standing between a signed dispatch and a changed
machine, so these are written from the position of someone holding *an*
approval and trying to make it authorize something else.
"""

from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from olympus.authority.node_approvals import (
    MAX_APPROVAL_TTL,
    ApprovalDenied,
    NodeApprovalIssuer,
    NodeApprovalVerifier,
    node_write_action_digest_from_content,
)
from olympus.authority.repository import AuthorityLease

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


def lease(**overrides) -> AuthorityLease:
    fields = {
        "lease_id": "lease-1",
        "authority_epoch": 2,
        "commander_id": "628053765181800448",
        "guild_id": "100000000000000001",
        "channel_scope_digest": b"c" * 32,
        "credential_id": b"credential-1",
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(hours=1),
    }
    fields.update(overrides)
    return AuthorityLease(**fields)  # type: ignore[arg-type]


def issuer(**kwargs) -> NodeApprovalIssuer:
    return NodeApprovalIssuer(signing_key=bytes(SigningKey.generate()), **kwargs)


def pair() -> tuple[NodeApprovalIssuer, NodeApprovalVerifier]:
    minted = issuer()
    return minted, NodeApprovalVerifier(
        verification_keys={minted.signer_id: minted.verification_key}
    )


# --- issuance requires live authority ---------------------------------------------


def test_an_approval_requires_a_lease() -> None:
    """The signing key alone must not be a standing permission to mutate."""
    with pytest.raises(ApprovalDenied, match="Face ID lease is required"):
        issuer().issue(action_digest=DIGEST, lease=None, now=NOW)


def test_an_expired_lease_cannot_approve_anything() -> None:
    with pytest.raises(ApprovalDenied, match="not currently valid"):
        issuer().issue(
            action_digest=DIGEST, lease=lease(expires_at=NOW - timedelta(seconds=1)), now=NOW
        )


def test_a_revoked_lease_cannot_approve_anything() -> None:
    with pytest.raises(ApprovalDenied, match="revoked"):
        issuer().issue(action_digest=DIGEST, lease=lease(revoked_at=NOW), now=NOW)


def test_a_frozen_system_refuses_to_approve_a_mutation() -> None:
    """The emergency latch outranks a valid lease.

    A commander who froze the system and then approved a mutation is
    contradicting themselves; the freeze is the instruction to honour.
    """
    with pytest.raises(ApprovalDenied, match="frozen"):
        issuer().issue(action_digest=DIGEST, lease=lease(), now=NOW, frozen=True)


def test_an_approval_never_outlives_the_lease_behind_it() -> None:
    """Otherwise a mutation could run after the commander's authority ended."""
    minted = issuer(ttl=timedelta(minutes=10))

    issued = minted.issue(
        action_digest=DIGEST,
        lease=lease(expires_at=NOW + timedelta(minutes=2)),
        now=NOW,
    )

    assert issued.approval.expires_at == NOW + timedelta(minutes=2)


def test_a_lease_that_has_just_expired_cannot_approve_at_all() -> None:
    # The boundary is exclusive: a lease expiring exactly now has no authority
    # left to lend, so there is no window in which it can still approve.
    with pytest.raises(ApprovalDenied, match="not currently valid"):
        issuer().issue(action_digest=DIGEST, lease=lease(expires_at=NOW), now=NOW)


def test_an_approval_against_a_nearly_expired_lease_is_clamped_not_refused() -> None:
    issued = issuer(ttl=timedelta(minutes=10)).issue(
        action_digest=DIGEST, lease=lease(expires_at=NOW + timedelta(seconds=1)), now=NOW
    )

    assert issued.approval.expires_at == NOW + timedelta(seconds=1)


def test_the_approval_ttl_is_bounded() -> None:
    with pytest.raises(ValueError):
        issuer(ttl=MAX_APPROVAL_TTL + timedelta(seconds=1))
    with pytest.raises(ValueError):
        issuer(ttl=timedelta(0))


def test_an_issued_approval_carries_the_lease_it_came_from() -> None:
    issued = issuer().issue(action_digest=DIGEST, lease=lease(), now=NOW)

    assert issued.lease_id == "lease-1"
    assert issued.authority_epoch == 2
    assert issued.approval.action_digest == DIGEST


# --- verification ------------------------------------------------------------------


def test_a_freshly_issued_approval_verifies() -> None:
    minted, verifier = pair()
    issued = minted.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    verifier.verify(action_digest=DIGEST, approval=issued.approval, now=NOW)


def test_an_approval_for_another_action_is_refused() -> None:
    minted, verifier = pair()
    issued = minted.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    with pytest.raises(ApprovalDenied, match="does not match this action"):
        verifier.verify(action_digest=OTHER_DIGEST, approval=issued.approval, now=NOW)


def test_a_mismatched_approval_is_not_consumed() -> None:
    """A replay attempt must not burn a good approval.

    Spending on failure would let anyone destroy a commander's approval by
    replaying it once against the wrong action.
    """
    minted, verifier = pair()
    issued = minted.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    with pytest.raises(ApprovalDenied):
        verifier.verify(action_digest=OTHER_DIGEST, approval=issued.approval, now=NOW)

    verifier.verify(action_digest=DIGEST, approval=issued.approval, now=NOW)


def test_an_approval_is_spent_exactly_once() -> None:
    minted, verifier = pair()
    issued = minted.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    verifier.verify(action_digest=DIGEST, approval=issued.approval, now=NOW)
    with pytest.raises(ApprovalDenied, match="already used"):
        verifier.verify(action_digest=DIGEST, approval=issued.approval, now=NOW)


def test_an_expired_approval_is_refused() -> None:
    minted, verifier = pair()
    issued = minted.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    with pytest.raises(ApprovalDenied, match="not currently valid"):
        verifier.verify(
            action_digest=DIGEST, approval=issued.approval, now=NOW + timedelta(hours=1)
        )


def test_an_approval_from_an_unknown_signer_is_refused() -> None:
    stranger = NodeApprovalIssuer(
        signing_key=bytes(SigningKey.generate()), signer_id="somebody-else-v1"
    )
    _, verifier = pair()
    issued = stranger.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    with pytest.raises(ApprovalDenied, match="not a trusted approval signer"):
        verifier.verify(action_digest=DIGEST, approval=issued.approval, now=NOW)


def test_a_forged_signature_is_refused() -> None:
    """Same signer id, different key. Identity is not authority."""
    minted, verifier = pair()
    impostor = NodeApprovalIssuer(
        signing_key=bytes(SigningKey.generate()), signer_id=minted.signer_id
    )
    issued = impostor.issue(action_digest=DIGEST, lease=lease(), now=NOW)

    with pytest.raises(ApprovalDenied, match="signature is invalid"):
        verifier.verify(action_digest=DIGEST, approval=issued.approval, now=NOW)


def test_a_tampered_expiry_invalidates_the_signature() -> None:
    from dataclasses import replace

    minted, verifier = pair()
    issued = minted.issue(action_digest=DIGEST, lease=lease(), now=NOW)
    extended = replace(issued.approval, expires_at=NOW + timedelta(days=7))

    with pytest.raises(ApprovalDenied, match="signature is invalid"):
        verifier.verify(action_digest=DIGEST, approval=extended, now=NOW + timedelta(hours=2))


def test_something_that_is_not_an_approval_is_refused() -> None:
    _, verifier = pair()

    with pytest.raises(ApprovalDenied, match="not an approval"):
        verifier.verify(action_digest=DIGEST, approval=object(), now=NOW)


def test_the_private_key_is_never_exposed() -> None:
    minted = issuer()

    assert len(minted.verification_key) == 32
    assert not hasattr(minted, "signing_key")


# --- the digest an operator actually approves ---------------------------------------


def test_the_digest_is_derived_from_the_real_payload() -> None:
    """What is approved must come from the bytes, not from an adjacent claim.

    Deriving the digest from a value handed over alongside the content would
    let the two disagree, which is exactly what binding is meant to prevent.
    """
    from olympus.nodes.scopes import WriteMode, file_write_action_digest

    content = b'{"setting": true}'
    derived = node_write_action_digest_from_content(
        node_id="node-1", path="/srv/app/config.json", content=content, overwrite=False
    )
    expected = file_write_action_digest(
        node_id="node-1",
        path="/srv/app/config.json",
        content_sha256=__import__("hashlib").sha256(content).hexdigest(),
        content_length=len(content),
        mode=WriteMode.CREATE,
    )

    assert derived == expected
    # And a different payload is a different approval.
    assert derived != node_write_action_digest_from_content(
        node_id="node-1", path="/srv/app/config.json", content=b"other", overwrite=False
    )


# --- the whole path: lease -> approval -> admitted node mutation ---------------------


async def test_a_face_id_lease_authorizes_exactly_one_node_write() -> None:
    """The bridge, end to end.

    Before this existed, fs.write was gated on an approval no code path could
    produce — enabled and unreachable, the same shape as a capability with no
    provider.
    """
    from olympus.nodes.crypto import generate_node_keypair
    from olympus.nodes.models import NodeKind, NodePlatform
    from olympus.nodes.registry import NodeDescription, NodeRegistry

    minted, verifier = pair()
    registry = NodeRegistry(
        heartbeat_interval_seconds=5, heartbeat_expiry_seconds=60, approvals=verifier
    )
    issued_token = await registry.issue_enrollment_token(
        node_name="jerry-windows",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.WINDOWS,
        granted_capabilities=["fs.write@1"],
        issued_by="local-jerry",
        capability_scopes={"fs.write@1": {"roots": ["C:\\olympus\\share"], "max_bytes": 4096}},
    )
    keys = generate_node_keypair()
    node = await registry.redeem_enrollment_token(
        presented=issued_token.presented,
        description=NodeDescription(
            node_name="jerry-windows",
            kind=NodeKind.WORKSTATION,
            platform=NodePlatform.WINDOWS,
            architecture="AMD64",
            agent_version="0.1.0",
            declared_capabilities=("fs.write@1",),
        ),
        public_key=keys.public_key,
    )
    await registry.attach_session(
        node_id=node.node_id,
        session_id="nsx-approval",
        declared_capabilities=["fs.write@1"],
        agent_version="0.1.0",
        architecture="AMD64",
    )

    live_now = datetime.now(UTC)
    live_lease = lease(
        issued_at=live_now - timedelta(minutes=1), expires_at=live_now + timedelta(hours=1)
    )
    content = b'{"enabled": true}'
    digest = node_write_action_digest_from_content(
        node_id=node.node_id,
        path="C:\\olympus\\share\\config.json",
        content=content,
        overwrite=False,
    )
    approval = minted.issue(action_digest=digest, lease=live_lease, now=live_now).approval

    parameters = {
        "path": "C:\\olympus\\share\\config.json",
        "content_sha256": __import__("hashlib").sha256(content).hexdigest(),
        "content_length": len(content),
        "mode": "create",
    }

    admitted = await registry.assert_dispatchable(
        node_id=node.node_id,
        capability="fs.write@1",
        parameters=parameters,
        approval=approval,
    )
    assert admitted.node_id == node.node_id

    # Spent. The same approval cannot authorize the write a second time.
    with pytest.raises(ApprovalDenied, match="already used"):
        await registry.assert_dispatchable(
            node_id=node.node_id,
            capability="fs.write@1",
            parameters=parameters,
            approval=approval,
        )


async def test_an_approval_for_one_node_does_not_authorize_another() -> None:
    """The digest binds the node id, so a captured approval cannot be moved."""
    minted, verifier = pair()
    content = b"payload"
    for_node_a = node_write_action_digest_from_content(
        node_id="node-a", path="/srv/x", content=content, overwrite=False
    )
    approval = minted.issue(action_digest=for_node_a, lease=lease(), now=NOW).approval

    for_node_b = node_write_action_digest_from_content(
        node_id="node-b", path="/srv/x", content=content, overwrite=False
    )
    with pytest.raises(ApprovalDenied, match="does not match this action"):
        verifier.verify(action_digest=for_node_b, approval=approval, now=NOW)

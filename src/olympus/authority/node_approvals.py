"""Issuing approvals for node mutations, bound to a live Face ID lease.

``fs.write@1`` is gated on a signed, payload-bound approval. Verification for
those approvals already existed; nothing could *issue* one, so the first
mutating node capability was gated on something no code path could produce.
This is the bridge, and it is deliberately narrow.

**An approval is not a permission, it is a receipt for one decision.** It names
one action digest, lives for minutes rather than hours, and is spent on first
use. What makes it worth anything is the lease behind it: the commander proved
presence with Face ID, and this mints authority that cannot outlive or exceed
that proof.

Two properties are load-bearing and easy to lose:

* **A lease authorizes, it does not sign.** The approval is signed by a key the
  control plane holds, but it is only *minted* when a valid, unexpired,
  unrevoked lease is presented. Skipping the lease check would turn the signing
  key into a standing permission to mutate any node.
* **An approval may never outlive its lease.** A ten-minute approval issued
  against a lease with one minute left would let a mutation run after the
  commander's authority ended, so the expiry is clamped to whichever comes
  first.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from olympus.authority.repository import AuthorityLease
from olympus.governance.authorization import Approval

# Deliberately short. An approval is a receipt for a decision the commander just
# made, not a window during which mutations are generally permitted.
DEFAULT_APPROVAL_TTL = timedelta(minutes=5)
MAX_APPROVAL_TTL = timedelta(minutes=15)


class ApprovalDenied(Exception):
    """Raised when an approval cannot be issued or cannot be honoured."""


@dataclass(frozen=True)
class IssuedApproval:
    """An approval and the lease whose authority it carries."""

    approval: Approval
    lease_id: str
    authority_epoch: int


class NodeApprovalIssuer:
    """Mints single-use approvals for node mutations from a live lease."""

    def __init__(
        self,
        *,
        signing_key: bytes,
        signer_id: str = "olympus-node-approval-v1",
        ttl: timedelta = DEFAULT_APPROVAL_TTL,
    ) -> None:
        if ttl <= timedelta(0) or ttl > MAX_APPROVAL_TTL:
            raise ValueError(f"approval ttl must be positive and at most {MAX_APPROVAL_TTL}")
        self._signing_key = SigningKey(signing_key)
        self._signer_id = signer_id
        self._ttl = ttl

    @property
    def signer_id(self) -> str:
        return self._signer_id

    @property
    def verification_key(self) -> bytes:
        """The public half, for whoever verifies. The private half never leaves."""
        return bytes(self._signing_key.verify_key)

    def issue(
        self,
        *,
        action_digest: str,
        lease: AuthorityLease | None,
        now: datetime,
        frozen: bool = False,
    ) -> IssuedApproval:
        if len(action_digest) != 64:
            raise ApprovalDenied("action_digest must be a SHA-256 hex digest")
        if frozen:
            # The emergency latch outranks a valid lease. A commander who froze
            # the system and then approved a mutation is contradicting
            # themselves, and the freeze is the instruction to honour.
            raise ApprovalDenied("the system is frozen; no node mutation may be approved")
        if lease is None:
            raise ApprovalDenied("a Face ID lease is required to approve a node mutation")
        if lease.revoked_at is not None:
            raise ApprovalDenied("the lease backing this approval was revoked")
        if now < lease.issued_at or now >= lease.expires_at:
            raise ApprovalDenied("the lease backing this approval is not currently valid")

        # Never outlive the authority that justified it. The check above already
        # established that the lease has time left, so this is always positive;
        # no second guard is needed and an unreachable one would only look like
        # protection.
        expires_at = min(now + self._ttl, lease.expires_at)

        approval_id = f"approval-{uuid4()}"
        unsigned = Approval(
            approval_id=approval_id,
            action_digest=action_digest,
            issued_at=now,
            expires_at=expires_at,
            signer_id=self._signer_id,
            signature=b"\x00",
        )
        signature = self._signing_key.sign(unsigned.canonical_bytes()).signature
        return IssuedApproval(
            approval=Approval(
                approval_id=approval_id,
                action_digest=action_digest,
                issued_at=now,
                expires_at=expires_at,
                signer_id=self._signer_id,
                signature=signature,
            ),
            lease_id=lease.lease_id,
            authority_epoch=lease.authority_epoch,
        )


class NodeApprovalVerifier:
    """Verifies approvals for the node registry, and spends them exactly once.

    Implements the registry's ``ApprovalVerifier`` protocol. It is a separate
    object from the issuer on purpose: the same process may need to verify
    approvals it did not mint, and an object that both signs and accepts its own
    signatures invites the mistake of trusting an approval because it looks
    familiar rather than because it verifies.
    """

    def __init__(self, *, verification_keys: dict[str, bytes]) -> None:
        if not verification_keys:
            raise ValueError("at least one approval verification key is required")
        self._keys = dict(verification_keys)
        self._spent: set[str] = set()

    @property
    def spent(self) -> frozenset[str]:
        return frozenset(self._spent)

    def verify(self, *, action_digest: str, approval: Any, now: datetime) -> None:
        if not isinstance(approval, Approval):
            raise ApprovalDenied("approval is not an approval")
        # Digest first. An approval for a different action is not "invalid
        # later", it is the wrong approval, and saying so before touching
        # single-use state means a replay attempt cannot burn a good approval.
        if approval.action_digest != action_digest:
            raise ApprovalDenied("approval does not match this action")

        key = self._keys.get(approval.signer_id)
        if key is None:
            raise ApprovalDenied(f"{approval.signer_id} is not a trusted approval signer")
        try:
            VerifyKey(key).verify(approval.canonical_bytes(), approval.signature)
        except (ValueError, BadSignatureError) as exc:
            raise ApprovalDenied("approval signature is invalid") from exc

        if now < approval.issued_at or now >= approval.expires_at:
            raise ApprovalDenied("approval is not currently valid")

        # Spend last, so a rejected approval is not consumed. Consuming on
        # failure would let anyone burn a commander's approval by replaying it
        # badly once.
        if approval.approval_id in self._spent:
            raise ApprovalDenied("approval was already used")
        self._spent.add(approval.approval_id)


def node_write_action_digest_from_content(
    *, node_id: str, path: str, content: bytes, overwrite: bool
) -> str:
    """Convenience for callers holding the bytes rather than a digest.

    Kept here rather than in the node package so that the thing an operator
    approves is derived from the actual payload, not from a digest someone
    handed them alongside it.
    """
    from olympus.nodes.scopes import WriteMode, file_write_action_digest

    return file_write_action_digest(
        node_id=node_id,
        path=path,
        content_sha256=hashlib.sha256(content).hexdigest(),
        content_length=len(content),
        mode=WriteMode.OVERWRITE if overwrite else WriteMode.CREATE,
    )


def utc_now() -> datetime:
    return datetime.now(UTC)

import hashlib
import hmac
import json
from datetime import datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from olympus.authority.repository import (
    _GENESIS_HASH,
    AdmissionDenied,
    AdmissionReceipt,
    AdmissionRequest,
    AuditEvent,
    AuthorityLease,
    AuthorityRepositoryError,
    Challenge,
    ChallengeConsumed,
    ChallengeInvalid,
    Credential,
    FreezeReceipt,
    FreezeState,
    InMemoryAuthorityRepository,
    LeaseRequest,
    RecoveryReceipt,
    _audit_hash,
    _require_aware,
)
from olympus.persistence.models import (
    AuthorityLeaseRow,
    AuthorityStateRow,
    DiscordInteractionRow,
    GlobalFreezeRow,
    SecurityAuditEventRow,
    WebAuthnChallengeRow,
    WebAuthnCredentialRow,
)


class SqlAlchemyAuthorityRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def initialize(self, now: datetime) -> None:
        _require_aware(now, "now")
        async with self._sessions.begin() as session:
            authority = await session.get(AuthorityStateRow, 1)
            freeze = await session.get(GlobalFreezeRow, 1)
            if authority is None:
                session.add(AuthorityStateRow(singleton_id=1, authority_epoch=1, updated_at=now))
            if freeze is None:
                session.add(
                    GlobalFreezeRow(
                        singleton_id=1,
                        freeze_epoch=1,
                        frozen=False,
                        updated_at=now,
                    )
                )

    async def create_challenge(self, challenge: Challenge) -> None:
        async with self._sessions.begin() as session:
            session.add(
                WebAuthnChallengeRow(
                    challenge_id=challenge.challenge_id,
                    challenge_value=challenge.challenge_value,
                    challenge_digest=challenge.challenge_digest,
                    purpose=challenge.purpose,
                    commander_id=challenge.commander_id,
                    payload_digest=challenge.payload_digest,
                    payload_json=challenge.payload_json,
                    issued_at=challenge.issued_at,
                    expires_at=challenge.expires_at,
                    consumed_at=challenge.consumed_at,
                )
            )

    async def consume_challenge(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        now: datetime,
    ) -> Challenge:
        _require_aware(now, "now")
        async with self._sessions.begin() as session:
            row = await session.scalar(
                select(WebAuthnChallengeRow)
                .where(WebAuthnChallengeRow.challenge_id == challenge_id)
                .with_for_update()
            )
            if row is None or not hmac.compare_digest(row.challenge_digest, challenge_digest):
                raise ChallengeInvalid("challenge does not match")
            if row.consumed_at is not None:
                raise ChallengeConsumed("challenge was already consumed")
            if now > row.expires_at:
                raise ChallengeInvalid("challenge has expired")
            row.consumed_at = now
            return _challenge_from_row(row)

    async def get_challenge(self, challenge_id: str) -> Challenge:
        async with self._sessions() as session:
            row = await session.get(WebAuthnChallengeRow, challenge_id)
            if row is None:
                raise ChallengeInvalid("challenge does not exist")
            return _challenge_from_row(row)

    async def credential_count(self) -> int:
        async with self._sessions() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(WebAuthnCredentialRow)
                .where(WebAuthnCredentialRow.revoked_at.is_(None))
            )
            return int(count or 0)

    async def get_credential(self, credential_id: bytes) -> Credential:
        async with self._sessions() as session:
            row = await session.get(WebAuthnCredentialRow, credential_id)
            if row is None or row.revoked_at is not None:
                raise AuthorityRepositoryError("credential is unavailable")
            return _credential_from_row(row)

    async def list_credentials(self) -> tuple[Credential, ...]:
        async with self._sessions() as session:
            rows = (
                await session.scalars(
                    select(WebAuthnCredentialRow).where(WebAuthnCredentialRow.revoked_at.is_(None))
                )
            ).all()
            return tuple(_credential_from_row(row) for row in rows)

    async def complete_registration(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        credential: Credential,
        now: datetime,
    ) -> Credential:
        async with self._sessions.begin() as session:
            challenge = await self._consume_challenge_row(
                session,
                challenge_id,
                challenge_digest,
                now,
            )
            if challenge.purpose != "bootstrap-registration":
                raise ChallengeInvalid("challenge purpose does not permit registration")
            existing = await session.get(WebAuthnCredentialRow, credential.credential_id)
            if existing is not None:
                raise AuthorityRepositoryError("credential identity already exists")
            session.add(
                WebAuthnCredentialRow(
                    credential_id=credential.credential_id,
                    commander_id=credential.commander_id,
                    public_key=credential.public_key,
                    sign_count=credential.sign_count,
                    created_at=credential.created_at,
                    revoked_at=credential.revoked_at,
                )
            )
            # Enrollment is the moment authority is created from nothing, so it
            # belongs in the chain more than anything that follows it. Without
            # this the credential row exists but no signed, chained evidence
            # records that it ever appeared — leaving the one event an attacker
            # would most want to forge outside the export subsystem entirely.
            #
            # Fingerprints, not material: the credential ID and public key are
            # what a forger would need, and the audit chain is exported
            # off-host. A hash proves which credential without carrying it.
            await self._append_audit(
                session,
                "credential-enrolled",
                {
                    "commander_id": credential.commander_id,
                    "credential_fingerprint": hashlib.sha256(credential.credential_id).hexdigest(),
                    "public_key_fingerprint": hashlib.sha256(credential.public_key).hexdigest(),
                    "created_at": credential.created_at.isoformat(),
                },
                now,
            )
            return credential

    async def complete_authentication(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        credential_id: bytes,
        new_sign_count: int,
        lease_request: LeaseRequest,
        now: datetime,
    ) -> AuthorityLease:
        async with self._sessions.begin() as session:
            authority, freeze = await self._locked_state(session)
            if freeze.frozen:
                raise AdmissionDenied("authority is frozen")
            challenge = await self._consume_challenge_row(
                session,
                challenge_id,
                challenge_digest,
                now,
            )
            if challenge.purpose != "lease":
                raise ChallengeInvalid("challenge purpose does not permit a lease")
            credential = await session.get(
                WebAuthnCredentialRow,
                credential_id,
                with_for_update=True,
            )
            if credential is None or credential.revoked_at is not None:
                raise AuthorityRepositoryError("credential is unavailable")
            if new_sign_count < credential.sign_count:
                raise AuthorityRepositoryError("credential counter regressed")
            credential.sign_count = new_sign_count
            active_rows = (
                await session.scalars(
                    select(AuthorityLeaseRow)
                    .where(AuthorityLeaseRow.revoked_at.is_(None))
                    .with_for_update()
                )
            ).all()
            for active in active_rows:
                active.revoked_at = now
                active.revocation_reason = "replaced"
            authority.authority_epoch += 1
            authority.updated_at = now
            row = AuthorityLeaseRow(
                lease_id=lease_request.lease_id,
                authority_epoch=authority.authority_epoch,
                commander_id=lease_request.commander_id,
                guild_id=lease_request.guild_id,
                channel_scope_digest=lease_request.channel_scope_digest,
                credential_id=credential_id,
                issued_at=lease_request.issued_at,
                expires_at=lease_request.expires_at,
            )
            session.add(row)
            await self._append_audit(
                session,
                "lease-issued",
                {
                    "authority_epoch": row.authority_epoch,
                    "commander_id": row.commander_id,
                    "guild_id": row.guild_id,
                    "lease_fingerprint": hashlib.sha256(row.lease_id.encode()).hexdigest(),
                },
                now,
            )
            return _lease_from_row(row)

    async def issue_lease(self, request: LeaseRequest) -> AuthorityLease:
        async with self._sessions.begin() as session:
            authority, freeze = await self._locked_state(session)
            if freeze.frozen:
                raise AdmissionDenied("authority is frozen")
            duplicate = await session.get(AuthorityLeaseRow, request.lease_id)
            if duplicate is not None:
                raise AuthorityRepositoryError("lease identity already exists")
            active_rows = (
                await session.scalars(
                    select(AuthorityLeaseRow)
                    .where(AuthorityLeaseRow.revoked_at.is_(None))
                    .with_for_update()
                )
            ).all()
            for active in active_rows:
                active.revoked_at = request.issued_at
                active.revocation_reason = "replaced"
            authority.authority_epoch += 1
            authority.updated_at = request.issued_at
            row = AuthorityLeaseRow(
                lease_id=request.lease_id,
                authority_epoch=authority.authority_epoch,
                commander_id=request.commander_id,
                guild_id=request.guild_id,
                channel_scope_digest=request.channel_scope_digest,
                credential_id=request.credential_id,
                issued_at=request.issued_at,
                expires_at=request.expires_at,
            )
            session.add(row)
            await self._append_audit(
                session,
                "lease-issued",
                {
                    "authority_epoch": row.authority_epoch,
                    "commander_id": row.commander_id,
                    "guild_id": row.guild_id,
                    "lease_fingerprint": hashlib.sha256(row.lease_id.encode()).hexdigest(),
                },
                request.issued_at,
            )
            return _lease_from_row(row)

    async def admit(self, request: AdmissionRequest) -> AdmissionReceipt:
        async with self._sessions.begin() as session:
            authority, freeze = await self._locked_state(session)
            duplicate = await session.get(
                DiscordInteractionRow,
                request.interaction_id,
                with_for_update=True,
            )
            if duplicate is not None:
                if not hmac.compare_digest(duplicate.request_digest, request.request_digest):
                    raise AdmissionDenied("interaction identity was reused with another payload")
                if duplicate.workflow_id is None or duplicate.decision != "allow":
                    raise AdmissionDenied("duplicate interaction has no accepted outcome")
                return AdmissionReceipt(
                    interaction_id=duplicate.interaction_id,
                    authority_epoch=request.authority_epoch,
                    lease_id=request.lease_id,
                    workflow_id=duplicate.workflow_id,
                    duplicate=True,
                )
            if freeze.frozen:
                raise AdmissionDenied("authority is frozen")
            lease = await session.get(
                AuthorityLeaseRow,
                request.lease_id,
                with_for_update=True,
            )
            if (
                lease is None
                or lease.revoked_at is not None
                or lease.authority_epoch != authority.authority_epoch
                or lease.authority_epoch != request.authority_epoch
                or lease.commander_id != request.commander_id
                or lease.guild_id != request.guild_id
                or not hmac.compare_digest(
                    lease.channel_scope_digest,
                    request.channel_scope_digest,
                )
                or request.received_at >= lease.expires_at
            ):
                raise AdmissionDenied("lease does not authorize this interaction")
            workflow_id = f"discord-{request.interaction_id}"
            session.add(
                DiscordInteractionRow(
                    interaction_id=request.interaction_id,
                    request_digest=request.request_digest,
                    decision="allow",
                    workflow_id=workflow_id,
                    received_at=request.received_at,
                    completed_at=request.received_at,
                )
            )
            return AdmissionReceipt(
                interaction_id=request.interaction_id,
                authority_epoch=lease.authority_epoch,
                lease_id=lease.lease_id,
                workflow_id=workflow_id,
            )

    async def freeze(self, request_id: str, reason: str, now: datetime) -> FreezeReceipt:
        _require_aware(now, "now")
        async with self._sessions.begin() as session:
            authority, freeze = await self._locked_state(session)
            if not freeze.frozen:
                authority.authority_epoch += 1
                authority.updated_at = now
                freeze.freeze_epoch += 1
                freeze.frozen = True
                freeze.request_id = request_id
                freeze.reason_code = reason
                freeze.updated_at = now
                active_rows = (
                    await session.scalars(
                        select(AuthorityLeaseRow)
                        .where(AuthorityLeaseRow.revoked_at.is_(None))
                        .with_for_update()
                    )
                ).all()
                for active in active_rows:
                    active.revoked_at = now
                    active.revocation_reason = reason
                await self._append_audit(
                    session,
                    "authority-frozen",
                    {
                        "authority_epoch": authority.authority_epoch,
                        "freeze_epoch": freeze.freeze_epoch,
                        "reason": reason,
                        "request_id": request_id,
                    },
                    now,
                )
            return FreezeReceipt(
                request_id=request_id,
                authority_epoch=authority.authority_epoch,
                freeze_epoch=freeze.freeze_epoch,
                frozen_at=now,
            )

    async def lease_is_revoked(self, lease_id: str) -> bool:
        async with self._sessions() as session:
            lease = await session.get(AuthorityLeaseRow, lease_id)
            if lease is None:
                raise AuthorityRepositoryError("lease does not exist")
            return lease.revoked_at is not None

    async def active_lease(self) -> AuthorityLease | None:
        async with self._sessions() as session:
            rows = (
                await session.scalars(
                    select(AuthorityLeaseRow)
                    .where(AuthorityLeaseRow.revoked_at.is_(None))
                    .order_by(AuthorityLeaseRow.authority_epoch.desc())
                    .limit(2)
                )
            ).all()
            if len(rows) > 1:
                raise AuthorityRepositoryError("multiple active leases violate authority state")
            return None if not rows else _lease_from_row(rows[0])

    async def freeze_state(self) -> FreezeState:
        async with self._sessions() as session:
            authority = await session.get(AuthorityStateRow, 1)
            freeze = await session.get(GlobalFreezeRow, 1)
            if authority is None or freeze is None:
                raise AuthorityRepositoryError("canonical authority state is not initialized")
            return FreezeState(
                frozen=freeze.frozen,
                freeze_epoch=freeze.freeze_epoch,
                authority_epoch=authority.authority_epoch,
            )

    async def complete_recovery(
        self,
        *,
        challenge_id: str,
        challenge_digest: bytes,
        expected_freeze_epoch: int,
        credential_id: bytes,
        new_sign_count: int,
        lease_request: LeaseRequest,
        recovery_id: str,
        now: datetime,
    ) -> RecoveryReceipt:
        async with self._sessions.begin() as session:
            authority, freeze = await self._locked_state(session)
            challenge = await self._consume_challenge_row(
                session,
                challenge_id,
                challenge_digest,
                now,
            )
            if challenge.purpose != "recovery":
                raise ChallengeInvalid("challenge purpose does not permit recovery")
            if not freeze.frozen or freeze.freeze_epoch != expected_freeze_epoch:
                raise AdmissionDenied("freeze epoch changed before recovery")
            credential = await session.get(
                WebAuthnCredentialRow,
                credential_id,
                with_for_update=True,
            )
            if credential is None or credential.revoked_at is not None:
                raise AuthorityRepositoryError("credential is unavailable")
            if new_sign_count < credential.sign_count:
                raise AuthorityRepositoryError("credential counter regressed")
            credential.sign_count = new_sign_count
            active_rows = (
                await session.scalars(
                    select(AuthorityLeaseRow)
                    .where(AuthorityLeaseRow.revoked_at.is_(None))
                    .with_for_update()
                )
            ).all()
            for active in active_rows:
                active.revoked_at = now
                active.revocation_reason = "recovery-replaced"
            freeze.frozen = False
            freeze.request_id = recovery_id
            freeze.reason_code = "face-id-recovery"
            freeze.updated_at = now
            authority.authority_epoch += 1
            authority.updated_at = now
            lease = AuthorityLeaseRow(
                lease_id=lease_request.lease_id,
                authority_epoch=authority.authority_epoch,
                commander_id=lease_request.commander_id,
                guild_id=lease_request.guild_id,
                channel_scope_digest=lease_request.channel_scope_digest,
                credential_id=credential_id,
                issued_at=lease_request.issued_at,
                expires_at=lease_request.expires_at,
            )
            session.add(lease)
            proof = hashlib.sha256(
                json.dumps(
                    {
                        "authority_epoch": lease.authority_epoch,
                        "freeze_epoch": expected_freeze_epoch,
                        "recovery_id": recovery_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).digest()
            await self._append_audit(
                session,
                "authority-recovered",
                {
                    "authority_epoch": lease.authority_epoch,
                    "freeze_epoch": expected_freeze_epoch,
                    "recovery_id": recovery_id,
                },
                now,
            )
            return RecoveryReceipt(
                lease=_lease_from_row(lease),
                freeze_epoch=expected_freeze_epoch,
                repository_proof=proof,
            )

    async def audit_events(self) -> tuple[AuditEvent, ...]:
        async with self._sessions() as session:
            rows = (
                await session.scalars(
                    select(SecurityAuditEventRow).order_by(SecurityAuditEventRow.sequence)
                )
            ).all()
            return tuple(
                AuditEvent(
                    sequence=row.sequence,
                    event_type=row.event_type,
                    body=row.body,
                    previous_hash=row.previous_hash,
                    event_hash=row.event_hash,
                )
                for row in rows
            )

    verify_audit_chain = staticmethod(InMemoryAuthorityRepository.verify_audit_chain)

    async def _locked_state(
        self,
        session: AsyncSession,
    ) -> tuple[AuthorityStateRow, GlobalFreezeRow]:
        authority = await session.get(AuthorityStateRow, 1, with_for_update=True)
        freeze = await session.get(GlobalFreezeRow, 1, with_for_update=True)
        if authority is None or freeze is None:
            raise AuthorityRepositoryError("canonical authority state is not initialized")
        return authority, freeze

    async def _append_audit(
        self,
        session: AsyncSession,
        event_type: str,
        body: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        previous = await session.scalar(
            select(SecurityAuditEventRow)
            .order_by(SecurityAuditEventRow.sequence.desc())
            .limit(1)
            .with_for_update()
        )
        sequence = 1 if previous is None else previous.sequence + 1
        previous_hash = _GENESIS_HASH if previous is None else previous.event_hash
        canonical_body = json.dumps(body, sort_keys=True, separators=(",", ":"))
        event_hash = _audit_hash(sequence, event_type, canonical_body, previous_hash)
        session.add(
            SecurityAuditEventRow(
                event_id=f"audit-{uuid4()}",
                sequence=sequence,
                occurred_at=occurred_at,
                event_type=event_type,
                body=canonical_body,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
        )

    async def _consume_challenge_row(
        self,
        session: AsyncSession,
        challenge_id: str,
        challenge_digest: bytes,
        now: datetime,
    ) -> WebAuthnChallengeRow:
        row = await session.scalar(
            select(WebAuthnChallengeRow)
            .where(WebAuthnChallengeRow.challenge_id == challenge_id)
            .with_for_update()
        )
        if row is None or not hmac.compare_digest(row.challenge_digest, challenge_digest):
            raise ChallengeInvalid("challenge does not match")
        if row.consumed_at is not None:
            raise ChallengeConsumed("challenge was already consumed")
        if now > row.expires_at:
            raise ChallengeInvalid("challenge has expired")
        row.consumed_at = now
        return row


def _challenge_from_row(row: WebAuthnChallengeRow) -> Challenge:
    return Challenge(
        challenge_id=row.challenge_id,
        challenge_value=row.challenge_value,
        challenge_digest=row.challenge_digest,
        purpose=row.purpose,
        commander_id=row.commander_id,
        payload_digest=row.payload_digest,
        payload_json=row.payload_json,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        consumed_at=row.consumed_at,
    )


def _lease_from_row(row: AuthorityLeaseRow) -> AuthorityLease:
    return AuthorityLease(
        lease_id=row.lease_id,
        authority_epoch=row.authority_epoch,
        commander_id=row.commander_id,
        guild_id=row.guild_id,
        channel_scope_digest=row.channel_scope_digest,
        credential_id=row.credential_id,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        revocation_reason=row.revocation_reason,
    )


def _credential_from_row(row: WebAuthnCredentialRow) -> Credential:
    return Credential(
        credential_id=row.credential_id,
        commander_id=row.commander_id,
        public_key=row.public_key,
        sign_count=row.sign_count,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
    )

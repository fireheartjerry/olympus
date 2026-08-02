import asyncio
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Protocol

_GENESIS_HASH = bytes(32)


class AuthorityRepositoryError(RuntimeError):
    """Base class for authority repository failures."""


class ChallengeConsumed(AuthorityRepositoryError):
    pass


class ChallengeInvalid(AuthorityRepositoryError):
    pass


class AdmissionDenied(AuthorityRepositoryError):
    pass


@dataclass(frozen=True)
class Credential:
    credential_id: bytes
    commander_id: str
    public_key: bytes
    sign_count: int
    created_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.credential_id or not self.public_key:
            raise ValueError("credential identity and public key must not be empty")
        if self.sign_count < 0:
            raise ValueError("credential sign_count cannot be negative")
        _require_aware(self.created_at, "created_at")
        if self.revoked_at is not None:
            _require_aware(self.revoked_at, "revoked_at")


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    challenge_value: bytes
    challenge_digest: bytes
    purpose: str
    commander_id: str
    payload_digest: bytes
    payload_json: str | None
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_digest(self.challenge_value, "challenge_value")
        _require_digest(self.challenge_digest, "challenge_digest")
        _require_digest(self.payload_digest, "payload_digest")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("challenge must expire after issuance")
        if self.expires_at - self.issued_at > timedelta(minutes=5):
            raise ValueError("challenge lifetime cannot exceed five minutes")


@dataclass(frozen=True)
class LeaseRequest:
    lease_id: str
    commander_id: str
    guild_id: str
    channel_scope_digest: bytes
    credential_id: bytes
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_digest(self.channel_scope_digest, "channel_scope_digest")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("lease must expire after issuance")
        if self.expires_at - self.issued_at > timedelta(hours=24):
            raise ValueError("lease lifetime cannot exceed 24 hours")


@dataclass(frozen=True)
class AuthorityLease:
    lease_id: str
    authority_epoch: int
    commander_id: str
    guild_id: str
    channel_scope_digest: bytes
    credential_id: bytes
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


@dataclass(frozen=True)
class AdmissionRequest:
    interaction_id: str
    request_digest: bytes
    commander_id: str
    guild_id: str
    channel_scope_digest: bytes
    lease_id: str
    authority_epoch: int
    received_at: datetime

    def __post_init__(self) -> None:
        _require_digest(self.request_digest, "request_digest")
        _require_digest(self.channel_scope_digest, "channel_scope_digest")
        _require_aware(self.received_at, "received_at")


@dataclass(frozen=True)
class AdmissionReceipt:
    interaction_id: str
    authority_epoch: int
    lease_id: str
    workflow_id: str
    duplicate: bool = False


@dataclass(frozen=True)
class FreezeReceipt:
    request_id: str
    authority_epoch: int
    freeze_epoch: int
    frozen_at: datetime


@dataclass(frozen=True)
class FreezeState:
    frozen: bool
    freeze_epoch: int
    authority_epoch: int


@dataclass(frozen=True)
class RecoveryReceipt:
    lease: AuthorityLease
    freeze_epoch: int
    repository_proof: bytes


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_type: str
    body: str
    previous_hash: bytes
    event_hash: bytes


class AuthorityRepository(Protocol):
    async def create_challenge(self, challenge: Challenge) -> None: ...

    async def consume_challenge(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        now: datetime,
    ) -> Challenge: ...

    async def get_challenge(self, challenge_id: str) -> Challenge: ...

    async def credential_count(self) -> int: ...

    async def get_credential(self, credential_id: bytes) -> Credential: ...

    async def list_credentials(self) -> tuple[Credential, ...]: ...

    async def complete_registration(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        credential: Credential,
        now: datetime,
    ) -> Credential: ...

    async def complete_authentication(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        credential_id: bytes,
        new_sign_count: int,
        lease_request: LeaseRequest,
        now: datetime,
    ) -> AuthorityLease: ...

    async def active_lease(self) -> AuthorityLease | None: ...

    async def freeze_state(self) -> FreezeState: ...

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
    ) -> RecoveryReceipt: ...

    async def issue_lease(self, request: LeaseRequest) -> AuthorityLease: ...

    async def admit(self, request: AdmissionRequest) -> AdmissionReceipt: ...

    async def freeze(self, request_id: str, reason: str, now: datetime) -> FreezeReceipt: ...


class InMemoryAuthorityRepository:
    """Deterministic transactional model used by the repository contract suite."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._authority_epoch = 1
        self._freeze_epoch = 1
        self._frozen = False
        self._challenges: dict[str, Challenge] = {}
        self._credentials: dict[bytes, Credential] = {}
        self._leases: dict[str, AuthorityLease] = {}
        self._active_lease_id: str | None = None
        self._interactions: dict[str, tuple[bytes, AdmissionReceipt]] = {}
        self._audit: list[AuditEvent] = []

    async def create_challenge(self, challenge: Challenge) -> None:
        async with self._lock:
            if challenge.challenge_id in self._challenges:
                raise ChallengeInvalid("challenge identity already exists")
            if any(
                stored.challenge_digest == challenge.challenge_digest
                for stored in self._challenges.values()
            ):
                raise ChallengeInvalid("challenge digest already exists")
            self._challenges[challenge.challenge_id] = challenge

    async def consume_challenge(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        now: datetime,
    ) -> Challenge:
        _require_aware(now, "now")
        async with self._lock:
            return self._consume_challenge_locked(challenge_id, challenge_digest, now)

    async def get_challenge(self, challenge_id: str) -> Challenge:
        async with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise ChallengeInvalid("challenge does not exist")
            return challenge

    async def credential_count(self) -> int:
        async with self._lock:
            return sum(credential.revoked_at is None for credential in self._credentials.values())

    async def get_credential(self, credential_id: bytes) -> Credential:
        async with self._lock:
            credential = self._credentials.get(credential_id)
            if credential is None or credential.revoked_at is not None:
                raise AuthorityRepositoryError("credential is unavailable")
            return credential

    async def list_credentials(self) -> tuple[Credential, ...]:
        async with self._lock:
            return tuple(
                credential
                for credential in self._credentials.values()
                if credential.revoked_at is None
            )

    async def replace_credential(self, credential: Credential) -> None:
        async with self._lock:
            if credential.credential_id not in self._credentials:
                raise AuthorityRepositoryError("credential does not exist")
            self._credentials[credential.credential_id] = credential

    async def complete_registration(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        credential: Credential,
        now: datetime,
    ) -> Credential:
        async with self._lock:
            self._consume_challenge_locked(challenge_id, challenge_digest, now)
            if credential.credential_id in self._credentials:
                raise AuthorityRepositoryError("credential identity already exists")
            self._credentials[credential.credential_id] = credential
            # Mirrors the SQLAlchemy repository exactly. If only one of the two
            # recorded enrollment, tests would pass against a chain the
            # production store does not actually produce.
            self._append_audit(
                "credential-enrolled",
                {
                    "commander_id": credential.commander_id,
                    "credential_fingerprint": hashlib.sha256(credential.credential_id).hexdigest(),
                    "public_key_fingerprint": hashlib.sha256(credential.public_key).hexdigest(),
                    "created_at": credential.created_at.isoformat(),
                },
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
        async with self._lock:
            self._consume_challenge_locked(challenge_id, challenge_digest, now)
            credential = self._credentials.get(credential_id)
            if credential is None or credential.revoked_at is not None:
                raise AuthorityRepositoryError("credential is unavailable")
            if new_sign_count < credential.sign_count:
                raise AuthorityRepositoryError("credential counter regressed")
            self._credentials[credential_id] = replace(
                credential,
                sign_count=new_sign_count,
            )
            return self._issue_lease_locked(lease_request)

    async def issue_lease(self, request: LeaseRequest) -> AuthorityLease:
        async with self._lock:
            return self._issue_lease_locked(request)

    async def freeze_state(self) -> FreezeState:
        async with self._lock:
            return FreezeState(
                frozen=self._frozen,
                freeze_epoch=self._freeze_epoch,
                authority_epoch=self._authority_epoch,
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
        async with self._lock:
            challenge = self._consume_challenge_locked(
                challenge_id,
                challenge_digest,
                now,
            )
            if challenge.purpose != "recovery":
                raise ChallengeInvalid("challenge purpose does not permit recovery")
            if not self._frozen or self._freeze_epoch != expected_freeze_epoch:
                raise AdmissionDenied("freeze epoch changed before recovery")
            credential = self._credentials.get(credential_id)
            if credential is None or credential.revoked_at is not None:
                raise AuthorityRepositoryError("credential is unavailable")
            if new_sign_count < credential.sign_count:
                raise AuthorityRepositoryError("credential counter regressed")
            self._credentials[credential_id] = replace(
                credential,
                sign_count=new_sign_count,
            )
            self._frozen = False
            lease = self._issue_lease_locked(lease_request)
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
            self._append_audit(
                "authority-recovered",
                {
                    "authority_epoch": lease.authority_epoch,
                    "freeze_epoch": expected_freeze_epoch,
                    "recovery_id": recovery_id,
                },
            )
            return RecoveryReceipt(
                lease=lease,
                freeze_epoch=expected_freeze_epoch,
                repository_proof=proof,
            )

    async def admit(self, request: AdmissionRequest) -> AdmissionReceipt:
        async with self._lock:
            duplicate = self._interactions.get(request.interaction_id)
            if duplicate is not None:
                digest, receipt = duplicate
                if digest != request.request_digest:
                    raise AdmissionDenied("interaction identity was reused with another payload")
                return replace(receipt, duplicate=True)
            if self._frozen:
                raise AdmissionDenied("authority is frozen")
            lease = self._leases.get(request.lease_id)
            if (
                lease is None
                or lease.revoked_at is not None
                or lease.authority_epoch != self._authority_epoch
                or lease.authority_epoch != request.authority_epoch
                or lease.commander_id != request.commander_id
                or lease.guild_id != request.guild_id
                or lease.channel_scope_digest != request.channel_scope_digest
                or request.received_at >= lease.expires_at
            ):
                raise AdmissionDenied("lease does not authorize this interaction")
            receipt = AdmissionReceipt(
                interaction_id=request.interaction_id,
                authority_epoch=lease.authority_epoch,
                lease_id=lease.lease_id,
                workflow_id=f"discord-{request.interaction_id}",
            )
            self._interactions[request.interaction_id] = (request.request_digest, receipt)
            return receipt

    async def freeze(self, request_id: str, reason: str, now: datetime) -> FreezeReceipt:
        _require_aware(now, "now")
        async with self._lock:
            if not self._frozen:
                self._authority_epoch += 1
                self._freeze_epoch += 1
                self._frozen = True
                self._revoke_active(now, reason)
                self._append_audit(
                    "authority-frozen",
                    {
                        "authority_epoch": self._authority_epoch,
                        "freeze_epoch": self._freeze_epoch,
                        "reason": reason,
                        "request_id": request_id,
                    },
                )
            return FreezeReceipt(
                request_id=request_id,
                authority_epoch=self._authority_epoch,
                freeze_epoch=self._freeze_epoch,
                frozen_at=now,
            )

    async def active_lease(self) -> AuthorityLease | None:
        async with self._lock:
            if self._active_lease_id is None:
                return None
            lease = self._leases[self._active_lease_id]
            return None if lease.revoked_at is not None else lease

    async def lease_is_revoked(self, lease_id: str) -> bool:
        async with self._lock:
            return self._leases[lease_id].revoked_at is not None

    async def audit_events(self) -> tuple[AuditEvent, ...]:
        async with self._lock:
            return tuple(self._audit)

    @staticmethod
    def verify_audit_chain(events: tuple[AuditEvent, ...]) -> bool:
        previous_hash = _GENESIS_HASH
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence or event.previous_hash != previous_hash:
                return False
            expected_hash = _audit_hash(
                event.sequence,
                event.event_type,
                event.body,
                event.previous_hash,
            )
            if event.event_hash != expected_hash:
                return False
            previous_hash = event.event_hash
        return True

    def _revoke_active(self, now: datetime, reason: str) -> None:
        if self._active_lease_id is None:
            return
        active = self._leases[self._active_lease_id]
        if active.revoked_at is None:
            self._leases[active.lease_id] = replace(
                active,
                revoked_at=now,
                revocation_reason=reason,
            )
        self._active_lease_id = None

    def _consume_challenge_locked(
        self,
        challenge_id: str,
        challenge_digest: bytes,
        now: datetime,
    ) -> Challenge:
        challenge = self._challenges.get(challenge_id)
        if challenge is None or challenge.challenge_digest != challenge_digest:
            raise ChallengeInvalid("challenge does not match")
        if challenge.consumed_at is not None:
            raise ChallengeConsumed("challenge was already consumed")
        if now > challenge.expires_at:
            raise ChallengeInvalid("challenge has expired")
        consumed = replace(challenge, consumed_at=now)
        self._challenges[challenge_id] = consumed
        return consumed

    def _issue_lease_locked(self, request: LeaseRequest) -> AuthorityLease:
        if self._frozen:
            raise AdmissionDenied("authority is frozen")
        if request.lease_id in self._leases:
            raise AuthorityRepositoryError("lease identity already exists")
        self._revoke_active(request.issued_at, "replaced")
        self._authority_epoch += 1
        lease = AuthorityLease(
            lease_id=request.lease_id,
            authority_epoch=self._authority_epoch,
            commander_id=request.commander_id,
            guild_id=request.guild_id,
            channel_scope_digest=request.channel_scope_digest,
            credential_id=request.credential_id,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
        )
        self._leases[lease.lease_id] = lease
        self._active_lease_id = lease.lease_id
        self._append_audit(
            "lease-issued",
            {
                "authority_epoch": lease.authority_epoch,
                "commander_id": lease.commander_id,
                "guild_id": lease.guild_id,
                "lease_fingerprint": _secret_fingerprint(lease.lease_id),
            },
        )
        return lease

    def _append_audit(self, event_type: str, body: dict[str, object]) -> None:
        sequence = len(self._audit) + 1
        previous_hash = self._audit[-1].event_hash if self._audit else _GENESIS_HASH
        canonical_body = json.dumps(body, sort_keys=True, separators=(",", ":"))
        event_hash = _audit_hash(sequence, event_type, canonical_body, previous_hash)
        self._audit.append(
            AuditEvent(
                sequence=sequence,
                event_type=event_type,
                body=canonical_body,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
        )

    async def is_frozen(self) -> bool:
        async with self._lock:
            return self._frozen


def _audit_hash(sequence: int, event_type: str, body: str, previous_hash: bytes) -> bytes:
    canonical = json.dumps(
        {
            "body": body,
            "event_type": event_type,
            "previous_hash": previous_hash.hex(),
            "sequence": sequence,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).digest()


def _secret_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _require_digest(value: bytes, field_name: str) -> None:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"{field_name} must be exactly 32 bytes")


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

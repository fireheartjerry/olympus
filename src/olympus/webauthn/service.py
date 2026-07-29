import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import uuid4

from olympus.authority.latch import CanonicalRecoveryProof
from olympus.authority.models import RecoveryPayload
from olympus.authority.repository import (
    AuthorityLease,
    AuthorityRepository,
    Challenge,
    Credential,
    LeaseRequest,
)
from olympus.webauthn.backend import (
    AuthenticationRequest,
    RegistrationRequest,
    WebAuthnBackend,
)


class BootstrapDenied(RuntimeError):
    pass


class AuthenticationAnomaly(RuntimeError):
    pass


class CeremonyPurpose(StrEnum):
    BOOTSTRAP_REGISTRATION = "bootstrap-registration"
    LEASE = "lease"
    RECOVERY = "recovery"


class ChallengeGenerator(Protocol):
    def token(self) -> bytes: ...


class SecureChallenges:
    def token(self) -> bytes:
        return secrets.token_bytes(32)


@dataclass(frozen=True)
class Ceremony:
    challenge_id: str
    options: dict[str, object]


@dataclass(frozen=True)
class RecoveryCeremony:
    ceremony: Ceremony
    payload: RecoveryPayload


@dataclass(frozen=True)
class RecoveryResult:
    lease: AuthorityLease
    proof: CanonicalRecoveryProof


class WebAuthnAuthorityService:
    bootstrap_purpose = CeremonyPurpose.BOOTSTRAP_REGISTRATION

    def __init__(
        self,
        *,
        repository: AuthorityRepository,
        backend: WebAuthnBackend,
        challenges: ChallengeGenerator,
        commander_id: str,
        guild_id: str,
        channel_ids: frozenset[str],
        rp_id: str,
        rp_name: str,
        origin: str,
        challenge_ttl: timedelta,
        lease_ttl: timedelta,
    ) -> None:
        if not channel_ids:
            raise ValueError("channel_ids must not be empty")
        if challenge_ttl <= timedelta(0) or challenge_ttl > timedelta(minutes=5):
            raise ValueError("challenge_ttl must be at most five minutes")
        if lease_ttl <= timedelta(0) or lease_ttl > timedelta(hours=24):
            raise ValueError("lease_ttl must be at most 24 hours")
        self._repository = repository
        self._backend = backend
        self._challenges = challenges
        self._commander_id = commander_id
        self._guild_id = guild_id
        self._channel_ids = channel_ids
        self._rp_id = rp_id
        self._rp_name = rp_name
        self._origin = origin
        self._challenge_ttl = challenge_ttl
        self._lease_ttl = lease_ttl

    async def begin_registration(
        self,
        *,
        purpose: CeremonyPurpose,
        bootstrap_enabled: bool,
        now: datetime,
    ) -> Ceremony:
        if purpose is not CeremonyPurpose.BOOTSTRAP_REGISTRATION:
            raise BootstrapDenied("unsupported registration purpose")
        if not bootstrap_enabled or await self._repository.credential_count() != 0:
            raise BootstrapDenied("bootstrap registration is unavailable")
        existing = await self._repository.list_credentials()
        challenge = await self._store_challenge(purpose, now)
        options = self._backend.registration_options(
            RegistrationRequest(
                rp_id=self._rp_id,
                rp_name=self._rp_name,
                commander_id=self._commander_id,
                challenge=challenge.challenge_value,
                exclude_credentials=tuple(item.credential_id for item in existing),
            )
        )
        return Ceremony(challenge_id=challenge.challenge_id, options=options)

    async def finish_registration(
        self,
        *,
        challenge_id: str,
        response: dict[str, object],
        now: datetime,
    ) -> Credential:
        challenge = await self._repository.get_challenge(challenge_id)
        if challenge.purpose != CeremonyPurpose.BOOTSTRAP_REGISTRATION:
            raise BootstrapDenied("challenge purpose does not permit registration")
        verified = self._backend.verify_registration(
            response=response,
            expected_challenge=challenge.challenge_value,
            expected_rp_id=self._rp_id,
            expected_origin=self._origin,
        )
        credential = Credential(
            credential_id=verified.credential_id,
            commander_id=self._commander_id,
            public_key=verified.public_key,
            sign_count=verified.sign_count,
            created_at=now,
        )
        return await self._repository.complete_registration(
            challenge.challenge_id,
            challenge.challenge_digest,
            credential,
            now,
        )

    async def begin_authentication(self, *, now: datetime) -> Ceremony:
        credentials = await self._repository.list_credentials()
        if not credentials:
            raise AuthenticationAnomaly("no active WebAuthn credential")
        challenge = await self._store_challenge(CeremonyPurpose.LEASE, now)
        options = self._backend.authentication_options(
            AuthenticationRequest(
                rp_id=self._rp_id,
                challenge=challenge.challenge_value,
                allow_credentials=tuple(item.credential_id for item in credentials),
            )
        )
        return Ceremony(challenge_id=challenge.challenge_id, options=options)

    async def finish_authentication(
        self,
        *,
        challenge_id: str,
        credential_id: bytes,
        response: dict[str, object],
        now: datetime,
    ) -> AuthorityLease:
        challenge = await self._repository.get_challenge(challenge_id)
        if challenge.purpose != CeremonyPurpose.LEASE:
            raise AuthenticationAnomaly("challenge purpose does not permit a lease")
        credential = await self._repository.get_credential(credential_id)
        verified = self._backend.verify_authentication(
            response=response,
            expected_challenge=challenge.challenge_value,
            expected_rp_id=self._rp_id,
            expected_origin=self._origin,
            credential=credential,
        )
        if verified.credential_id != credential.credential_id:
            await self._repository.freeze(
                f"anomaly-{uuid4()}",
                "credential-identity-mismatch",
                now,
            )
            raise AuthenticationAnomaly("credential identity mismatch")
        if verified.new_sign_count < credential.sign_count:
            await self._repository.freeze(
                f"anomaly-{uuid4()}",
                "credential-counter-regression",
                now,
            )
            raise AuthenticationAnomaly("credential counter regressed")
        lease_request = LeaseRequest(
            lease_id=f"lease-{uuid4()}",
            commander_id=self._commander_id,
            guild_id=self._guild_id,
            channel_scope_digest=self._channel_scope_digest(),
            credential_id=credential.credential_id,
            issued_at=now,
            expires_at=now + self._lease_ttl,
        )
        return await self._repository.complete_authentication(
            challenge.challenge_id,
            challenge.challenge_digest,
            credential.credential_id,
            verified.new_sign_count,
            lease_request,
            now,
        )

    async def begin_recovery(
        self,
        *,
        request_id: str,
        credential_id: bytes,
        now: datetime,
    ) -> RecoveryCeremony:
        state = await self._repository.freeze_state()
        if not state.frozen:
            raise AuthenticationAnomaly("recovery requires an active freeze")
        credential = await self._repository.get_credential(credential_id)
        payload = RecoveryPayload(
            request_id=request_id,
            action="unfreeze",
            freeze_epoch=state.freeze_epoch,
            commander_id=self._commander_id,
            guild_id=self._guild_id,
            channel_scope_digest=self._channel_scope_digest().hex(),
            issued_at=now.isoformat(),
            expires_at=(now + self._challenge_ttl).isoformat(),
        )
        value = self._challenges.token()
        payload_json = payload.canonical_bytes().decode()
        challenge = Challenge(
            challenge_id=f"challenge-{uuid4()}",
            challenge_value=value,
            challenge_digest=hashlib.sha256(value).digest(),
            purpose=CeremonyPurpose.RECOVERY.value,
            commander_id=self._commander_id,
            payload_digest=hashlib.sha256(payload.canonical_bytes()).digest(),
            payload_json=payload_json,
            issued_at=now,
            expires_at=now + self._challenge_ttl,
        )
        await self._repository.create_challenge(challenge)
        options = self._backend.authentication_options(
            AuthenticationRequest(
                rp_id=self._rp_id,
                challenge=value,
                allow_credentials=(credential.credential_id,),
            )
        )
        return RecoveryCeremony(
            ceremony=Ceremony(challenge_id=challenge.challenge_id, options=options),
            payload=payload,
        )

    async def finish_recovery(
        self,
        *,
        challenge_id: str,
        credential_id: bytes,
        response: dict[str, object],
        now: datetime,
    ) -> RecoveryResult:
        challenge = await self._repository.get_challenge(challenge_id)
        if challenge.purpose != CeremonyPurpose.RECOVERY or challenge.payload_json is None:
            raise AuthenticationAnomaly("challenge purpose does not permit recovery")
        payload_data = json.loads(challenge.payload_json)
        if not isinstance(payload_data, dict):
            raise AuthenticationAnomaly("recovery payload is invalid")
        payload = RecoveryPayload(
            request_id=str(payload_data["request_id"]),
            action="unfreeze",
            freeze_epoch=int(payload_data["freeze_epoch"]),
            commander_id=str(payload_data["commander_id"]),
            guild_id=str(payload_data["guild_id"]),
            channel_scope_digest=str(payload_data["channel_scope_digest"]),
            issued_at=str(payload_data["issued_at"]),
            expires_at=str(payload_data["expires_at"]),
        )
        if hashlib.sha256(payload.canonical_bytes()).digest() != challenge.payload_digest:
            raise AuthenticationAnomaly("recovery payload digest does not match")
        credential = await self._repository.get_credential(credential_id)
        verified = self._backend.verify_authentication(
            response=response,
            expected_challenge=challenge.challenge_value,
            expected_rp_id=self._rp_id,
            expected_origin=self._origin,
            credential=credential,
        )
        if (
            verified.credential_id != credential.credential_id
            or verified.new_sign_count < credential.sign_count
        ):
            await self._repository.freeze(
                f"anomaly-{uuid4()}",
                "recovery-authentication-anomaly",
                now,
            )
            raise AuthenticationAnomaly("recovery authentication anomaly")
        lease_request = LeaseRequest(
            lease_id=f"lease-{uuid4()}",
            commander_id=self._commander_id,
            guild_id=self._guild_id,
            channel_scope_digest=self._channel_scope_digest(),
            credential_id=credential.credential_id,
            issued_at=now,
            expires_at=now + self._lease_ttl,
        )
        receipt = await self._repository.complete_recovery(
            challenge_id=challenge.challenge_id,
            challenge_digest=challenge.challenge_digest,
            expected_freeze_epoch=payload.freeze_epoch,
            credential_id=credential.credential_id,
            new_sign_count=verified.new_sign_count,
            lease_request=lease_request,
            recovery_id=payload.request_id,
            now=now,
        )
        return RecoveryResult(
            lease=receipt.lease,
            proof=CanonicalRecoveryProof(
                recovery_id=payload.request_id,
                authority_epoch=receipt.lease.authority_epoch,
                freeze_epoch=receipt.freeze_epoch,
                repository_proof=receipt.repository_proof,
            ),
        )

    async def _store_challenge(
        self,
        purpose: CeremonyPurpose,
        now: datetime,
    ) -> Challenge:
        value = self._challenges.token()
        challenge = Challenge(
            challenge_id=f"challenge-{uuid4()}",
            challenge_value=value,
            challenge_digest=hashlib.sha256(value).digest(),
            purpose=purpose.value,
            commander_id=self._commander_id,
            payload_digest=self._ceremony_payload_digest(purpose),
            payload_json=None,
            issued_at=now,
            expires_at=now + self._challenge_ttl,
        )
        await self._repository.create_challenge(challenge)
        return challenge

    def _channel_scope_digest(self) -> bytes:
        return hashlib.sha256(
            json.dumps(sorted(self._channel_ids), separators=(",", ":")).encode()
        ).digest()

    def _ceremony_payload_digest(self, purpose: CeremonyPurpose) -> bytes:
        return hashlib.sha256(
            json.dumps(
                {
                    "commander_id": self._commander_id,
                    "guild_id": self._guild_id,
                    "purpose": purpose.value,
                    "rp_id": self._rp_id,
                    "scope": sorted(self._channel_ids),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).digest()

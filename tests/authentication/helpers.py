from datetime import timedelta

from olympus.authority.repository import Credential, InMemoryAuthorityRepository
from olympus.webauthn.backend import (
    AuthenticationRequest,
    RegistrationRequest,
    VerifiedAuthentication,
    VerifiedRegistration,
)
from olympus.webauthn.service import WebAuthnAuthorityService


class FakeBackend:
    def registration_options(self, request: RegistrationRequest) -> dict[str, object]:
        return {"challenge": request.challenge.hex(), "rpId": request.rp_id}

    def verify_registration(
        self,
        *,
        response: dict[str, object],
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> VerifiedRegistration:
        assert response["challenge"] == expected_challenge.hex()
        return VerifiedRegistration(
            credential_id=b"credential-1",
            public_key=b"public-key-1",
            sign_count=0,
        )

    def authentication_options(self, request: AuthenticationRequest) -> dict[str, object]:
        return {"challenge": request.challenge.hex(), "rpId": request.rp_id}

    def verify_authentication(
        self,
        *,
        response: dict[str, object],
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential: Credential,
    ) -> VerifiedAuthentication:
        assert response["challenge"] == expected_challenge.hex()
        return VerifiedAuthentication(
            credential_id=credential.credential_id,
            new_sign_count=credential.sign_count + 1,
        )


class DeterministicChallenges:
    def __init__(self, start: int = 0) -> None:
        self._index = start

    def token(self) -> bytes:
        self._index += 1
        return bytes([self._index]) * 32


def make_service(
    repository: InMemoryAuthorityRepository,
    backend: FakeBackend | None = None,
    challenge_start: int = 0,
) -> WebAuthnAuthorityService:
    return WebAuthnAuthorityService(
        repository=repository,
        backend=backend or FakeBackend(),
        challenges=DeterministicChallenges(challenge_start),
        commander_id="628053765181800448",
        guild_id="100000000000000001",
        channel_ids=frozenset({"100000000000000002"}),
        rp_id="olympus.tail-example.ts.net",
        rp_name="Olympus",
        origin="https://olympus.tail-example.ts.net",
        challenge_ttl=timedelta(minutes=5),
        lease_ttl=timedelta(hours=24),
    )

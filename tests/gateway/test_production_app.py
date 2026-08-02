from datetime import UTC, datetime

from fastapi.testclient import TestClient

from olympus.authority.latch import CanonicalRecoveryProof
from olympus.authority.models import RecoveryPayload
from olympus.authority.repository import AuthorityLease
from olympus.gateway.production import create_production_app
from olympus.webauthn.service import (
    AuthenticationAnomaly,
    BootstrapDenied,
    Ceremony,
    CeremonyPurpose,
    RecoveryCeremony,
    RecoveryResult,
)

ORIGIN = "https://olympus.tail-example.ts.net"
NOW = datetime(2026, 7, 29, tzinfo=UTC)


class FakeWebAuthn:
    async def begin_registration(
        self,
        *,
        purpose: object,
        bootstrap_enabled: bool,
        now: datetime,
    ) -> Ceremony:
        assert bootstrap_enabled
        return Ceremony("challenge-register", {"challenge": "YQ"})

    async def finish_registration(
        self,
        *,
        challenge_id: str,
        response: dict[str, object],
        now: datetime,
    ) -> object:
        assert challenge_id == "challenge-register"
        return object()

    async def begin_authentication(self, *, now: datetime) -> Ceremony:
        return Ceremony("challenge-lease", {"challenge": "Yg"})

    async def finish_authentication(
        self,
        *,
        challenge_id: str,
        credential_id: bytes,
        response: dict[str, object],
        now: datetime,
    ) -> AuthorityLease:
        return AuthorityLease(
            lease_id="secret-lease-id",
            authority_epoch=2,
            commander_id="628053765181800448",
            guild_id="100000000000000001",
            channel_scope_digest=b"c" * 32,
            credential_id=credential_id,
            issued_at=NOW,
            expires_at=NOW.replace(day=30),
        )

    async def begin_recovery(
        self,
        *,
        request_id: str,
        credential_id: bytes,
        now: datetime,
    ) -> RecoveryCeremony:
        return RecoveryCeremony(
            ceremony=Ceremony("challenge-recovery", {"challenge": "Yw"}),
            payload=RecoveryPayload(
                request_id=request_id,
                action="unfreeze",
                freeze_epoch=2,
                commander_id="628053765181800448",
                guild_id="100000000000000001",
                channel_scope_digest="a" * 64,
                issued_at=NOW.isoformat(),
                expires_at=NOW.replace(minute=5).isoformat(),
            ),
        )

    async def finish_recovery(
        self,
        *,
        challenge_id: str,
        credential_id: bytes,
        response: dict[str, object],
        now: datetime,
    ) -> RecoveryResult:
        lease = await self.finish_authentication(
            challenge_id=challenge_id,
            credential_id=credential_id,
            response=response,
            now=now,
        )
        return RecoveryResult(
            lease=lease,
            proof=CanonicalRecoveryProof(
                recovery_id="recovery-1",
                authority_epoch=2,
                freeze_epoch=2,
                repository_proof=b"proof",
            ),
        )


class FakeDiscord:
    async def handle(self, interaction: object, *, raw_body: bytes, now: datetime) -> object:
        return object()


def client() -> TestClient:
    app = create_production_app(
        webauthn=FakeWebAuthn(),
        discord=FakeDiscord(),
        discord_public_key=bytes(32),
        webauthn_origin=ORIGIN,
        webauthn_host="olympus.tail-example.ts.net",
        bootstrap_enabled=True,
        now=lambda: NOW,
        ready=lambda: True,
    )
    return TestClient(app)


def webauthn_headers() -> dict[str, str]:
    return {"Origin": ORIGIN, "Host": "olympus.tail-example.ts.net"}


def test_mobile_page_exposes_face_id_actions_without_secret_material() -> None:
    response = client().get("/", headers={"Host": "olympus.tail-example.ts.net"})

    assert response.status_code == 200
    assert "Register Face ID" in response.text
    assert "Authorize for 24 hours" in response.text
    assert "Recover and unfreeze" in response.text
    assert "secret-lease-id" not in response.text


def test_registration_options_require_exact_private_origin_and_host() -> None:
    accepted = client().post(
        "/v1/webauthn/register/options",
        headers=webauthn_headers(),
        json={},
    )
    wrong_origin = client().post(
        "/v1/webauthn/register/options",
        headers={
            "Origin": "https://evil.example",
            "Host": "olympus.tail-example.ts.net",
        },
        json={},
    )

    assert accepted.status_code == 200
    assert accepted.json()["challenge_id"] == "challenge-register"
    assert wrong_origin.status_code == 403


def test_lease_verification_returns_no_server_side_lease_identifier() -> None:
    response = client().post(
        "/v1/webauthn/lease/verify",
        headers=webauthn_headers(),
        json={
            "challenge_id": "challenge-lease",
            "credential": {"rawId": "Y3JlZGVudGlhbC0x"},
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "authorized",
        "authority_epoch": 2,
        "expires_at": "2026-07-30T00:00:00+00:00",
    }


def test_rejects_oversized_request_before_parsing() -> None:
    response = client().post(
        "/v1/webauthn/lease/verify",
        headers={**webauthn_headers(), "Content-Type": "application/json"},
        content=b"x" * 1_048_577,
    )

    assert response.status_code == 413


class RefusingWebAuthn(FakeWebAuthn):
    """The steady state after enrollment: bootstrap is permanently closed."""

    async def begin_registration(
        self,
        *,
        purpose: CeremonyPurpose,
        bootstrap_enabled: bool,
        now: datetime,
    ) -> Ceremony:
        raise BootstrapDenied("bootstrap registration is unavailable")


class AnomalousWebAuthn(FakeWebAuthn):
    async def begin_authentication(self, *, now: datetime) -> Ceremony:
        raise AuthenticationAnomaly("sign count regressed")


def refusing_client(webauthn: object) -> TestClient:
    app = create_production_app(
        webauthn=webauthn,
        discord=FakeDiscord(),
        discord_public_key=bytes(32),
        webauthn_origin=ORIGIN,
        webauthn_host="olympus.tail-example.ts.net",
        bootstrap_enabled=False,
        now=lambda: NOW,
        ready=lambda: True,
    )
    return TestClient(app, raise_server_exceptions=False)


def test_closed_bootstrap_is_a_refusal_not_a_crash() -> None:
    """Once a credential exists this is the normal path, on every request.

    A 500 here would bury a deliberate authority decision in what looks like a
    malfunction, and would make a real malfunction indistinguishable from
    correct operation.
    """
    response = refusing_client(RefusingWebAuthn()).post(
        "/v1/webauthn/register/options",
        headers=webauthn_headers(),
        json={},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "ceremony unavailable"}


def test_refusal_does_not_disclose_why_the_ceremony_is_unavailable() -> None:
    # Switched off, versus a credential already existing, must look identical.
    body = (
        refusing_client(RefusingWebAuthn())
        .post(
            "/v1/webauthn/register/options",
            headers=webauthn_headers(),
            json={},
        )
        .text
    )

    assert "bootstrap" not in body.lower()
    assert "credential" not in body.lower()


def test_authentication_anomaly_is_refused_without_detail() -> None:
    response = refusing_client(AnomalousWebAuthn()).post(
        "/v1/webauthn/lease/options",
        headers=webauthn_headers(),
        json={},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "request denied"}
    assert "sign count" not in response.text


def test_a_closed_bootstrap_still_refuses_a_wrong_origin_first() -> None:
    # The origin boundary is not bypassed by the ceremony being unavailable.
    response = refusing_client(RefusingWebAuthn()).post(
        "/v1/webauthn/register/options",
        headers={"Origin": "https://evil.example", "Host": "olympus.tail-example.ts.net"},
        json={},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "request denied"}

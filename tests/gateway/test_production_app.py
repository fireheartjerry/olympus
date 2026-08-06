from datetime import UTC, datetime

from fastapi.testclient import TestClient

from olympus.authority.latch import CanonicalRecoveryProof
from olympus.authority.models import RecoveryPayload
from olympus.authority.repository import AuthorityLease
from olympus.gateway.auth import OperatorGrant
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


def test_node_edge_receives_a_signed_operator_grant_not_the_server_lease_id() -> None:
    app = create_production_app(
        webauthn=FakeWebAuthn(),
        discord=FakeDiscord(),
        discord_public_key=bytes(32),
        webauthn_origin=ORIGIN,
        webauthn_host="olympus.tail-example.ts.net",
        bootstrap_enabled=True,
        now=lambda: NOW,
        ready=lambda: True,
        operator_grant_issuer=lambda lease: OperatorGrant(
            token="signed-opaque-grant",  # noqa: S106 - inert test fixture
            grant_id="grant-fingerprint",
            commander_id=lease.commander_id,
        ),
    )

    response = TestClient(app).post(
        "/v1/webauthn/lease/verify",
        headers=webauthn_headers(),
        json={
            "challenge_id": "challenge-lease",
            "credential": {"rawId": "Y3JlZGVudGlhbC0x"},
        },
    )

    assert response.status_code == 200
    assert response.json()["operator_token"] == "signed-opaque-grant"
    assert response.json()["operator_grant_id"] == "grant-fingerprint"
    assert "lease_id" not in response.json()
    assert "secret-lease-id" not in response.text


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


def test_page_surfaces_the_servers_reason_rather_than_a_fixed_string() -> None:
    """The operator must not be told "denied" when the server said something else.

    A hardcoded failure message cost a real ceremony: a closed bootstrap
    reported "Request denied", which reads as an origin or credential problem,
    when the server had actually answered "ceremony unavailable". The page now
    shows what the server said — which is already written to disclose nothing
    about *why* a ceremony is unavailable, so surfacing it leaks nothing.
    """
    page = client().get("/", headers={"Host": "olympus.tail-example.ts.net"}).text

    assert "throw new Error('Request denied')" not in page
    assert ".detail" in page


def closed_page() -> str:
    app = create_production_app(
        webauthn=FakeWebAuthn(),
        discord=FakeDiscord(),
        discord_public_key=bytes(32),
        webauthn_origin=ORIGIN,
        webauthn_host="olympus.tail-example.ts.net",
        bootstrap_enabled=False,
        now=lambda: NOW,
        ready=lambda: True,
    )
    return TestClient(app).get("/", headers={"Host": "olympus.tail-example.ts.net"}).text


def test_closed_enrollment_does_not_offer_a_button_that_can_only_fail() -> None:
    page = closed_page()

    assert "Register Face ID" not in page
    assert "Enrollment is closed" in page
    # The ceremonies that still work must remain.
    assert "Authorize for 24 hours" in page
    assert "Recover and unfreeze" in page


def test_open_enrollment_still_offers_registration() -> None:
    page = client().get("/", headers={"Host": "olympus.tail-example.ts.net"}).text

    assert "Register Face ID" in page
    assert "Enrollment is closed" not in page


def test_the_closed_notice_states_configuration_not_credential_state() -> None:
    """The page says enrollment is off, never that a passkey exists.

    The button follows the operator's own configuration flag rather than the
    credential store, so the page can only restate something the operator
    already set. Claiming "a passkey is registered" would assert credential
    state that the API deliberately refuses to disclose.
    """
    page = closed_page()

    assert "Enrollment is closed" in page
    for leak in ("already registered", "passkey is registered", "a credential exists"):
        assert leak not in page


def test_home_screen_icons_are_served_rather_than_404() -> None:
    """Safari requests these on Add to Home Screen.

    They were 404s, so the shortcut got a blank icon and the access log filled
    with what looked like probing.
    """
    page = client()
    for path in (
        "/favicon.ico",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/apple-touch-icon-120x120.png",
    ):
        response = page.get(path, headers={"Host": "olympus.tail-example.ts.net"})
        assert response.status_code == 200, path
        assert response.content[:8] == b"\x89PNG\r\n\x1a\n", path


def test_the_page_points_at_the_icons_it_serves() -> None:
    page = client().get("/", headers={"Host": "olympus.tail-example.ts.net"}).text

    assert 'rel="apple-touch-icon"' in page
    assert "/apple-touch-icon.png" in page


def test_icons_honour_the_same_host_boundary_as_everything_else() -> None:
    # A new route must not become a hole in the boundary the rest enforces.
    response = client().get("/favicon.ico", headers={"Host": "elsewhere.example"})

    assert response.status_code == 403

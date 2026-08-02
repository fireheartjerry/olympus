from datetime import UTC, datetime, timedelta

import pytest

from olympus.authority.repository import InMemoryAuthorityRepository
from olympus.webauthn.backend import (
    AuthenticationRequest,
    PyWebAuthnBackend,
    RegistrationRequest,
)
from olympus.webauthn.service import (
    BootstrapDenied,
    CeremonyPurpose,
)

from .helpers import make_service

NOW = datetime(2026, 7, 29, tzinfo=UTC)


async def test_bootstrap_registration_is_allowed_only_when_store_is_empty() -> None:
    repository = InMemoryAuthorityRepository()
    service = make_service(repository)

    ceremony = await service.begin_registration(
        purpose=CeremonyPurpose.BOOTSTRAP_REGISTRATION,
        bootstrap_enabled=True,
        now=NOW,
    )
    await service.finish_registration(
        challenge_id=ceremony.challenge_id,
        response={"challenge": ceremony.options["challenge"]},
        now=NOW,
    )

    assert await repository.credential_count() == 1
    with pytest.raises(BootstrapDenied):
        await service.begin_registration(
            purpose=CeremonyPurpose.BOOTSTRAP_REGISTRATION,
            bootstrap_enabled=True,
            now=NOW,
        )


async def test_authentication_issues_one_24_hour_server_side_lease() -> None:
    repository = InMemoryAuthorityRepository()
    service = make_service(repository)
    registration = await service.begin_registration(
        purpose=CeremonyPurpose.BOOTSTRAP_REGISTRATION,
        bootstrap_enabled=True,
        now=NOW,
    )
    await service.finish_registration(
        challenge_id=registration.challenge_id,
        response={"challenge": registration.options["challenge"]},
        now=NOW,
    )

    authentication = await service.begin_authentication(now=NOW)
    lease = await service.finish_authentication(
        challenge_id=authentication.challenge_id,
        credential_id=b"credential-1",
        response={"challenge": authentication.options["challenge"]},
        now=NOW,
    )

    assert lease.commander_id == "628053765181800448"
    assert lease.expires_at - lease.issued_at == timedelta(hours=24)
    assert await repository.active_lease() == lease


def test_real_backend_requires_user_verification_in_both_ceremonies() -> None:
    backend = PyWebAuthnBackend()

    registration = backend.registration_options(
        RegistrationRequest(
            rp_id="olympus.tail-example.ts.net",
            rp_name="Olympus",
            commander_id="628053765181800448",
            challenge=b"a" * 32,
            exclude_credentials=(),
        )
    )
    authentication = backend.authentication_options(
        AuthenticationRequest(
            rp_id="olympus.tail-example.ts.net",
            challenge=b"b" * 32,
            allow_credentials=(b"credential-1",),
        )
    )

    selection = registration["authenticatorSelection"]
    assert isinstance(selection, dict)
    assert selection["userVerification"] == "required"
    assert authentication["userVerification"] == "required"

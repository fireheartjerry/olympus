from dataclasses import replace
from datetime import UTC, datetime

import pytest

from olympus.authority.repository import Credential, InMemoryAuthorityRepository
from olympus.webauthn.backend import VerifiedAuthentication
from olympus.webauthn.service import AuthenticationAnomaly

from .helpers import FakeBackend, make_service

NOW = datetime(2026, 7, 29, tzinfo=UTC)


class CounterRegressionBackend(FakeBackend):
    def verify_authentication(self, **kwargs: object) -> VerifiedAuthentication:
        credential = kwargs["credential"]
        assert isinstance(credential, Credential)
        return VerifiedAuthentication(
            credential_id=credential.credential_id,
            new_sign_count=max(0, credential.sign_count - 1),
        )


async def test_counter_regression_freezes_authority() -> None:
    repository = InMemoryAuthorityRepository()
    service = make_service(repository)
    registration = await service.begin_registration(
        purpose=service.bootstrap_purpose,
        bootstrap_enabled=True,
        now=NOW,
    )
    credential = await service.finish_registration(
        challenge_id=registration.challenge_id,
        response={"challenge": registration.options["challenge"]},
        now=NOW,
    )
    await repository.replace_credential(replace(credential, sign_count=5))
    service = make_service(repository, CounterRegressionBackend(), challenge_start=10)
    authentication = await service.begin_authentication(now=NOW)

    with pytest.raises(AuthenticationAnomaly, match="counter"):
        await service.finish_authentication(
            challenge_id=authentication.challenge_id,
            credential_id=credential.credential_id,
            response={"challenge": authentication.options["challenge"]},
            now=NOW,
        )

    assert await repository.is_frozen()


async def test_fresh_face_id_recovery_clears_exact_freeze_epoch_and_issues_new_lease() -> None:
    repository = InMemoryAuthorityRepository()
    service = make_service(repository)
    registration = await service.begin_registration(
        purpose=service.bootstrap_purpose,
        bootstrap_enabled=True,
        now=NOW,
    )
    credential = await service.finish_registration(
        challenge_id=registration.challenge_id,
        response={"challenge": registration.options["challenge"]},
        now=NOW,
    )
    await repository.freeze("freeze-1", "operator-request", NOW)

    recovery = await service.begin_recovery(
        request_id="recovery-1",
        credential_id=credential.credential_id,
        now=NOW,
    )
    result = await service.finish_recovery(
        challenge_id=recovery.ceremony.challenge_id,
        credential_id=credential.credential_id,
        response={"challenge": recovery.ceremony.options["challenge"]},
        now=NOW,
    )

    assert recovery.payload.action == "unfreeze"
    assert recovery.payload.freeze_epoch == 2
    assert not await repository.is_frozen()
    assert result.lease.authority_epoch == 3
    assert result.proof.freeze_epoch == 2
    assert await repository.active_lease() == result.lease

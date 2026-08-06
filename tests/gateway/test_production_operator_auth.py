from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from olympus.authority.repository import AuthorityLease
from olympus.gateway.auth import ProductionLeaseAuthorizer, issue_operator_grant
from olympus.nodes.crypto import generate_node_keypair

NOW = datetime(2026, 8, 6, 12, tzinfo=UTC)
COMMANDER = "628053765181800448"


class LeaseRepository:
    def __init__(self, lease: AuthorityLease | None) -> None:
        self.lease = lease
        self.fail = False

    async def active_lease(self) -> AuthorityLease | None:
        if self.fail:
            raise RuntimeError("database unavailable")
        return self.lease


def lease(*, expires_at: datetime = NOW + timedelta(hours=1)) -> AuthorityLease:
    return AuthorityLease(
        lease_id="server-side-lease",
        authority_epoch=7,
        commander_id=COMMANDER,
        guild_id="111111111111111111",
        channel_scope_digest=b"c" * 32,
        credential_id=b"credential",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=expires_at,
    )


def setup(
    authority_lease: AuthorityLease | None = None,
) -> tuple[ProductionLeaseAuthorizer, LeaseRepository, str, str]:
    authority_lease = authority_lease or lease()
    keys = generate_node_keypair()
    repository = LeaseRepository(authority_lease)
    grant = issue_operator_grant(keys.private_key, authority_lease)
    authorizer = ProductionLeaseAuthorizer(
        repository=repository,  # type: ignore[arg-type]
        commander_id=COMMANDER,
        operator_public_key=keys.public_key,
        now=lambda: NOW,
    )
    return authorizer, repository, grant.token, grant.grant_id


async def authorize(authorizer: ProductionLeaseAuthorizer, token: str, grant_id: str):
    return await authorizer.authorize(
        authorization=[f"Bearer {token}"],
        commander_ids=[COMMANDER],
        authority_lease_ids=[grant_id],
    )


async def test_signed_grant_is_bound_to_the_canonical_active_lease() -> None:
    authorizer, _, token, grant_id = setup()

    authority = await authorize(authorizer, token, grant_id)

    assert authority.commander_id == COMMANDER
    assert authority.authority_lease_id == "server-side-lease"
    assert authority.authority_epoch == 7


@pytest.mark.parametrize("mutation", ["token", "grant_id", "commander"])
async def test_tampered_or_misbound_grants_are_refused(mutation: str) -> None:
    authorizer, _, token, grant_id = setup()
    authorization = [f"Bearer {token}x"] if mutation == "token" else [f"Bearer {token}"]
    ids = [grant_id + "0"] if mutation == "grant_id" else [grant_id]
    commanders = ["628053765181800449"] if mutation == "commander" else [COMMANDER]

    with pytest.raises(HTTPException) as caught:
        await authorizer.authorize(
            authorization=authorization,
            commander_ids=commanders,
            authority_lease_ids=ids,
        )

    assert caught.value.status_code == 401


async def test_revocation_expiry_and_authority_failure_all_fail_closed() -> None:
    authorizer, repository, token, grant_id = setup()
    repository.lease = None
    with pytest.raises(HTTPException) as revoked:
        await authorize(authorizer, token, grant_id)
    assert revoked.value.status_code == 401

    expired_lease = lease(expires_at=NOW)
    expired, _, expired_token, expired_grant_id = setup(expired_lease)
    with pytest.raises(HTTPException) as expired_error:
        await authorize(expired, expired_token, expired_grant_id)
    assert expired_error.value.status_code == 401

    repository.fail = True
    with pytest.raises(HTTPException) as unavailable:
        await authorize(authorizer, token, grant_id)
    assert unavailable.value.status_code == 503


async def test_development_bearer_token_has_no_production_authority() -> None:
    authorizer, _, _, grant_id = setup()

    with pytest.raises(HTTPException) as caught:
        await authorize(authorizer, "test-token-with-at-least-32-bytes", grant_id)

    assert caught.value.status_code == 401

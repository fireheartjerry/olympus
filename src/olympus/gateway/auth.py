import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from fastapi import HTTPException, status

from olympus.authority.repository import AuthorityLease, AuthorityRepository
from olympus.gateway.settings import GatewaySettings
from olympus.nodes.crypto import (
    canonical_json,
    decode_bytes,
    encode_bytes,
    sign_payload,
    verify_payload,
)
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import DispatchAuthority

AUTHORITY_HEADER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class OperatorAuthorizer(Protocol):
    """Authorize an operator request without coupling routes to one credential type."""

    async def authorize(
        self,
        *,
        authorization: list[str] | None,
        commander_ids: list[str],
        authority_lease_ids: list[str],
    ) -> DispatchAuthority: ...


def require_single_authority_header(values: list[str]) -> str:
    """Accept exactly one well-formed authority header value."""
    if len(values) != 1 or AUTHORITY_HEADER_PATTERN.fullmatch(values[0]) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid authority header",
        )
    return values[0]


def matches_development_token(authorization_values: list[str] | None, expected_token: str) -> bool:
    """Constant-time comparison of the development bearer credential."""
    if authorization_values is None or len(authorization_values) != 1:
        return False
    try:
        received = authorization_values[0].encode("ascii")
        expected = f"Bearer {expected_token}".encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(received, expected)


def require_operator(
    *,
    settings: GatewaySettings,
    authorization: list[str] | None,
    commander_ids: list[str],
    authority_lease_ids: list[str],
) -> DispatchAuthority:
    """Authorize one operator request and return its authority context.

    This is the development boundary the foundation slice established. The
    trusted-ingress slice replaces the shared token with a Face-ID-issued
    server-side lease; the returned shape does not change when it does.
    """
    if not matches_development_token(authorization, settings.dev_command_token.get_secret_value()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid development command token",
        )
    return DispatchAuthority(
        commander_id=require_single_authority_header(commander_ids),
        authority_lease_id=require_single_authority_header(authority_lease_ids),
    )


class DevelopmentOperatorAuthorizer:
    """Adapter preserving the explicitly development-only bearer boundary."""

    def __init__(self, settings: GatewaySettings) -> None:
        self._settings = settings

    async def authorize(
        self,
        *,
        authorization: list[str] | None,
        commander_ids: list[str],
        authority_lease_ids: list[str],
    ) -> DispatchAuthority:
        return require_operator(
            settings=self._settings,
            authorization=authorization,
            commander_ids=commander_ids,
            authority_lease_ids=authority_lease_ids,
        )


@dataclass(frozen=True)
class OperatorGrant:
    token: str
    grant_id: str
    commander_id: str


OperatorGrantIssuer = Callable[[AuthorityLease], OperatorGrant]


def issue_operator_grant(private_key: str, lease: AuthorityLease) -> OperatorGrant:
    """Create an Ed25519-signed, lease-bound grant for the node operator API."""
    payload = {
        "domain": "olympus-node-operator-grant-v1",
        "version": 1,
        "scope": "node-mesh",
        "lease_id": lease.lease_id,
        "authority_epoch": lease.authority_epoch,
        "commander_id": lease.commander_id,
        "issued_at": int(lease.issued_at.timestamp()),
        "expires_at": int(lease.expires_at.timestamp()),
    }
    body = encode_bytes(canonical_json(payload))
    signature = sign_payload(private_key, payload)
    token = f"olyauth.{body}.{signature}"
    return OperatorGrant(
        token=token,
        grant_id=hashlib.sha256(token.encode()).hexdigest(),
        commander_id=lease.commander_id,
    )


class ProductionLeaseAuthorizer:
    """Validate the server-side WebAuthn lease for every node operator request.

    A lease identifier is never trusted merely because the client presented it.
    The canonical authority repository must still report that exact lease as
    active, unrevoked, scoped to the configured commander, and inside its time
    bounds. Repository failure is an availability failure, not an authorization
    fallback.
    """

    def __init__(
        self,
        *,
        repository: AuthorityRepository,
        commander_id: str,
        operator_public_key: str,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._commander_id = commander_id
        self._operator_public_key = operator_public_key
        self._now = now

    async def authorize(
        self,
        *,
        authorization: list[str] | None,
        commander_ids: list[str],
        authority_lease_ids: list[str],
    ) -> DispatchAuthority:
        commander_id = require_single_authority_header(commander_ids)
        grant_id = require_single_authority_header(authority_lease_ids)
        if not hmac.compare_digest(commander_id, self._commander_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authority lease is not active",
            )
        payload = self._verify_grant(authorization)
        if not hmac.compare_digest(
            str(payload["commander_id"]), commander_id
        ) or not hmac.compare_digest(
            hashlib.sha256(self._bearer_token(authorization).encode()).hexdigest(), grant_id
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authority lease is not active",
            )
        try:
            lease = await self._repository.active_lease()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authority repository unavailable",
            ) from exc
        current = self._now()
        if (
            lease is None
            or lease.revoked_at is not None
            or not hmac.compare_digest(lease.lease_id, str(payload["lease_id"]))
            or not hmac.compare_digest(lease.commander_id, commander_id)
            or lease.authority_epoch != payload["authority_epoch"]
            or payload["scope"] != "node-mesh"
            or payload["issued_at"] != int(lease.issued_at.timestamp())
            or payload["expires_at"] != int(lease.expires_at.timestamp())
            or int(current.timestamp()) < payload["issued_at"]
            or int(current.timestamp()) >= payload["expires_at"]
            or current < lease.issued_at
            or current >= lease.expires_at
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authority lease is not active",
            )
        return DispatchAuthority(
            commander_id=commander_id,
            authority_lease_id=lease.lease_id,
            authority_epoch=lease.authority_epoch,
        )

    def _verify_grant(self, authorization: list[str] | None) -> dict[str, object]:
        token = self._bearer_token(authorization)
        parts = token.split(".")
        try:
            if len(parts) != 3 or parts[0] != "olyauth":
                raise ValueError("malformed grant")
            payload = json.loads(decode_bytes(parts[1]))
            if not isinstance(payload, dict) or set(payload) != {
                "domain",
                "version",
                "scope",
                "lease_id",
                "authority_epoch",
                "commander_id",
                "issued_at",
                "expires_at",
            }:
                raise ValueError("malformed grant")
            if (
                payload["domain"] != "olympus-node-operator-grant-v1"
                or payload["version"] != 1
                or encode_bytes(canonical_json(payload)) != parts[1]
            ):
                raise ValueError("malformed grant")
            verify_payload(
                self._operator_public_key,
                payload,
                parts[2],
                NodeReason.UNAUTHORIZED,
            )
            if not all(
                isinstance(payload[field], int)
                for field in ("authority_epoch", "issued_at", "expires_at")
            ) or not all(
                isinstance(payload[field], str) for field in ("scope", "lease_id", "commander_id")
            ):
                raise ValueError("malformed grant")
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            NodeMeshError,
            ValueError,
            TypeError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid production operator grant",
            ) from exc
        return payload

    @staticmethod
    def _bearer_token(authorization: list[str] | None) -> str:
        if authorization is None or len(authorization) != 1:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid production operator grant",
            )
        prefix = "Bearer "
        value = authorization[0]
        if not value.startswith(prefix) or not value[len(prefix) :]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid production operator grant",
            )
        return value[len(prefix) :]

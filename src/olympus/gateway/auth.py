import hmac
import re

from fastapi import HTTPException, status

from olympus.gateway.settings import GatewaySettings
from olympus.nodes.models import DispatchAuthority

AUTHORITY_HEADER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


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

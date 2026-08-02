from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from olympus.gateway.production_settings import ProductionGatewaySettings


def valid_settings(**overrides: object) -> ProductionGatewaySettings:
    values: dict[str, object] = {
        "commander_id": "628053765181800448",
        "discord_application_public_key": SecretStr("a" * 64),
        "discord_guild_id": "111111111111111111",
        "discord_channel_ids": frozenset({"222222222222222222"}),
        "webauthn_origin": "https://olympus.tail-example.ts.net",
        "webauthn_rp_id": "olympus.tail-example.ts.net",
        "database_dsn": SecretStr("postgresql+asyncpg://olympus:test@db/olympus"),
        "emergency_latch_path": Path("/var/lib/olympus/emergency-freeze.json"),
        "emergency_latch_verification_key": SecretStr("b" * 64),
    }
    values.update(overrides)
    return ProductionGatewaySettings(**values)  # type: ignore[arg-type]


def test_accepts_exact_single_commander_and_private_https_origin() -> None:
    settings = valid_settings()

    assert settings.commander_id == "628053765181800448"
    assert settings.lease_ttl == timedelta(hours=24)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commander_id", "123"),
        ("discord_guild_id", "guild-name"),
        ("discord_channel_ids", frozenset()),
        ("discord_channel_ids", frozenset({"channel-name"})),
        ("discord_application_public_key", SecretStr("a" * 63)),
        ("webauthn_origin", "http://olympus.tail-example.ts.net"),
        ("webauthn_origin", "https://localhost"),
        ("webauthn_origin", "https://other.tail-example.ts.net"),
        ("webauthn_rp_id", "*.tail-example.ts.net"),
        ("lease_ttl", timedelta(hours=24, microseconds=1)),
        ("emergency_latch_path", Path("relative/latch.json")),
    ],
)
def test_rejects_unsafe_production_settings(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        valid_settings(**{field: value})


def test_rejects_development_authentication_field() -> None:
    with pytest.raises(ValidationError):
        valid_settings(dev_command_token=SecretStr("x" * 32))


def test_explicit_tls_port_in_origin_is_not_part_of_the_rp_id() -> None:
    """A dedicated port is an origin detail, never a relying-party identity.

    WebAuthn scopes a credential to the RP ID, which is a bare domain and
    cannot carry a port; the port belongs to the origin the browser checks
    separately. Olympus binds its own TLS listener on a high port because 443
    and 8443 already belong to other services, so this is the production
    configuration, not a corner case. Validation that folded the port into the
    RP ID comparison would reject the real deployment.
    """
    settings = valid_settings(
        webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
        webauthn_rp_id="vps-41e741fc.tail70f263.ts.net",
    )

    assert str(settings.webauthn_origin).rstrip("/") == (
        "https://vps-41e741fc.tail70f263.ts.net:9443"
    )
    assert settings.webauthn_rp_id == "vps-41e741fc.tail70f263.ts.net"
    assert settings.webauthn_origin.host == settings.webauthn_rp_id


def test_port_bearing_origin_still_requires_the_rp_id_to_equal_the_hostname() -> None:
    # The port must not become a loophole: everything else about the origin and
    # RP ID binding stays exactly as strict as it is without one.
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
            webauthn_rp_id="tail70f263.ts.net",
        )
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
            webauthn_rp_id="vps-41e741fc.tail70f263.ts.net:9443",
        )
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="http://vps-41e741fc.tail70f263.ts.net:9443",
            webauthn_rp_id="vps-41e741fc.tail70f263.ts.net",
        )

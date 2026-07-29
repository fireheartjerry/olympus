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

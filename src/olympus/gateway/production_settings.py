import ipaddress
import re
from datetime import timedelta
from pathlib import Path
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_SNOWFLAKE = re.compile(r"[0-9]{17,20}")
_HEX_32_BYTES = re.compile(r"[0-9a-fA-F]{64}")


class ProductionGatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OLYMPUS_PRODUCTION_",
        env_file=".env.production",
        extra="forbid",
    )

    environment: Literal["production"] = "production"
    commander_id: Literal["628053765181800448"]
    discord_application_public_key: SecretStr
    discord_guild_id: str
    discord_channel_ids: frozenset[str]
    webauthn_origin: AnyHttpUrl
    webauthn_rp_id: str
    webauthn_rp_name: str = "Olympus"
    lease_ttl: timedelta = timedelta(hours=24)
    discord_timestamp_tolerance: timedelta = timedelta(minutes=5)
    database_dsn: SecretStr
    emergency_latch_path: Path
    emergency_latch_verification_key: SecretStr
    temporal_address: str = "127.0.0.1:7233"
    temporal_task_queue: str = "olympus-command-v1"
    http_host: str = "127.0.0.1"
    http_port: int = Field(default=8443, ge=1024, le=65535)

    @field_validator("discord_guild_id")
    @classmethod
    def validate_guild_id(cls, value: str) -> str:
        if _SNOWFLAKE.fullmatch(value) is None:
            raise ValueError("discord_guild_id must be a literal Discord snowflake")
        return value

    @field_validator("discord_channel_ids")
    @classmethod
    def validate_channel_ids(cls, values: frozenset[str]) -> frozenset[str]:
        if not values:
            raise ValueError("discord_channel_ids must not be empty")
        if any(_SNOWFLAKE.fullmatch(value) is None for value in values):
            raise ValueError("discord_channel_ids must contain literal Discord snowflakes")
        return values

    @field_validator(
        "discord_application_public_key",
        "emergency_latch_verification_key",
    )
    @classmethod
    def validate_public_key(cls, value: SecretStr) -> SecretStr:
        if _HEX_32_BYTES.fullmatch(value.get_secret_value()) is None:
            raise ValueError("verification keys must be 32-byte hexadecimal values")
        return value

    @field_validator("emergency_latch_path")
    @classmethod
    def validate_latch_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("emergency_latch_path must be absolute")
        return value

    @field_validator("database_dsn")
    @classmethod
    def validate_database_dsn(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+asyncpg://"):
            raise ValueError("database_dsn must use postgresql+asyncpg")
        return value

    @model_validator(mode="after")
    def validate_authority_boundary(self) -> Self:
        origin = self.webauthn_origin
        host = origin.host
        if origin.scheme != "https" or host is None:
            raise ValueError("webauthn_origin must use private HTTPS")
        if origin.path not in ("", "/") or origin.query is not None or origin.fragment is not None:
            raise ValueError("webauthn_origin must not include path, query, or fragment")
        if host.lower() == "localhost" or _is_ip_address(host):
            raise ValueError("webauthn_origin must use a stable private DNS name")
        if "*" in self.webauthn_rp_id or host.lower() != self.webauthn_rp_id.lower():
            raise ValueError("webauthn origin and relying-party ID must match exactly")
        if self.lease_ttl <= timedelta(0) or self.lease_ttl > timedelta(hours=24):
            raise ValueError("lease_ttl must be positive and at most 24 hours")
        if self.discord_timestamp_tolerance <= timedelta(
            0
        ) or self.discord_timestamp_tolerance > timedelta(minutes=5):
            raise ValueError("discord_timestamp_tolerance must be at most five minutes")
        return self


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

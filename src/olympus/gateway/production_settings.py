import ipaddress
import re
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from olympus.settings_compat import apply_fire_environment_aliases

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

    # The production node edge is intentionally opt-in. When enabled it shares
    # this private TLS listener, but its durable state and signing identity are
    # mandatory; there is no volatile or ephemeral production fallback.
    node_mesh_enabled: bool = False
    node_task_queue: str = "olympus-node-edge-v1"
    node_heartbeat_interval_seconds: int = Field(default=15, ge=1, le=3600)
    node_heartbeat_expiry_seconds: int = Field(default=45, ge=2, le=7200)
    node_enrollment_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    node_control_plane_key_id: str = "olympus-control-plane-v1"
    node_control_plane_private_key: SecretStr | None = None
    node_database_url: SecretStr | None = None
    node_attach_control_plane_host: bool = False
    node_control_plane_host_name: str = "vps-primary"

    # Olympus terminates its own TLS on a dedicated high port bound to a single
    # address. It does not sit behind a shared reverse proxy: the production app
    # rejects any request carrying X-Forwarded-* precisely so that no
    # intermediary can assert an origin on the browser's behalf, and the
    # WebAuthn boundary depends on that. A wildcard bind is refused because the
    # only interface this may be reachable on is the private tailnet.
    http_host: str = "127.0.0.1"
    http_port: int = Field(default=8443, ge=1024, le=65535)
    tls_certificate_path: Path | None = None
    tls_private_key_path: Path | None = None

    # Bootstrap enrollment is the one ceremony that creates authority from
    # nothing, so it stays off unless deliberately switched on for the ceremony.
    bootstrap_enabled: bool = False

    # Off-host audit export. An export subsystem that exists but never runs
    # protects nothing: every event since the last manual run lives only in the
    # database, which is precisely where a compromised control plane can rewrite
    # it. These are optional so a development gateway needs no AWS at all, but
    # when one is set they all must be.
    audit_export_bucket: str | None = None
    audit_export_kms_key_id: str | None = None
    audit_export_chain: str = "authority-production"
    # The node mesh keeps its own hash chain — enrollments, grants,
    # revocations, dispatches, freezes. Exporting only the authority chain
    # would leave every record of what was done *to machines* on the one host
    # that could rewrite it.
    audit_export_node_chain: str = "node-mesh-production"
    audit_export_node_database_url: SecretStr | None = None
    audit_export_region: str = "us-west-2"
    audit_export_profile: str | None = None
    audit_export_retention_days: int = Field(default=30, ge=1)
    audit_export_retention_mode: Literal["GOVERNANCE", "COMPLIANCE"] = "GOVERNANCE"

    def __init__(self, **values: Any) -> None:
        super().__init__(
            **apply_fire_environment_aliases(
                values,
                fields=type(self).model_fields,
                canonical_prefix="FIRE_PRODUCTION_",
                legacy_prefix="OLYMPUS_PRODUCTION_",
            )
        )

    @field_validator("http_host")
    @classmethod
    def validate_bind_address(cls, value: str) -> str:
        if value in ("0.0.0.0", "::", ""):  # noqa: S104 - rejecting, not binding
            raise ValueError("http_host must be a specific private address, never a wildcard")
        return value

    @field_validator("tls_certificate_path", "tls_private_key_path")
    @classmethod
    def validate_tls_path(cls, value: Path | None) -> Path | None:
        if value is not None and not (
            value.is_absolute() or PurePosixPath(str(value).replace("\\", "/")).is_absolute()
        ):
            raise ValueError("TLS material paths must be absolute")
        return value

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
        if not (value.is_absolute() or PurePosixPath(str(value).replace("\\", "/")).is_absolute()):
            raise ValueError("emergency_latch_path must be absolute")
        return value

    @field_validator("database_dsn")
    @classmethod
    def validate_database_dsn(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+asyncpg://"):
            raise ValueError("database_dsn must use postgresql+asyncpg")
        return value

    @field_validator("node_control_plane_private_key", "node_database_url", mode="before")
    @classmethod
    def blank_node_secret_means_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
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
        if self.node_heartbeat_expiry_seconds <= self.node_heartbeat_interval_seconds:
            raise ValueError("node heartbeat expiry must exceed the heartbeat interval")
        if self.node_mesh_enabled and (
            self.node_database_url is None or self.node_control_plane_private_key is None
        ):
            raise ValueError(
                "production node mesh requires durable PostgreSQL state and a persistent "
                "control-plane signing key"
            )

        if (self.tls_certificate_path is None) != (self.tls_private_key_path is None):
            raise ValueError("TLS requires both a certificate and a private key, or neither")

        if (self.audit_export_bucket is None) != (self.audit_export_kms_key_id is None):
            raise ValueError(
                "audit export requires both a bucket and a signing key, or neither; "
                "exporting unsigned segments would produce evidence nobody can attribute"
            )
        if not self.audit_export_chain.strip():
            raise ValueError("audit_export_chain must not be empty")

        # The origin is what the browser will send and what the WebAuthn
        # boundary compares against. A *non-default* port means Olympus is
        # terminating TLS itself on that port, so it has to be the port actually
        # being served — otherwise every ceremony fails the origin check with
        # nothing to indicate why. Port 443 is left alone: pydantic fills it in
        # for an origin that never named a port, so treating it as explicit
        # would invent a constraint the operator did not write.
        if origin.port not in (None, 443) and origin.port != self.http_port:
            raise ValueError(
                f"webauthn_origin names port {origin.port} but the gateway serves {self.http_port}"
            )
        return self

    @property
    def public_host_header(self) -> str:
        """The exact Host header a browser will send for the public origin.

        Not the same as the RP ID. A non-default port belongs in the Host header
        and the origin, and must never appear in the relying-party ID, which is
        a bare domain by specification.
        """
        origin = self.webauthn_origin
        if origin.port is not None and origin.port != 443:
            return f"{origin.host}:{origin.port}"
        return str(origin.host)


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

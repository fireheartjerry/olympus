from typing import Any, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from olympus.settings_compat import apply_fire_environment_aliases


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OLYMPUS_", env_file=".env", extra="forbid")

    environment: Literal["development", "test"]
    dev_command_token: SecretStr = Field(min_length=32, max_length=256)
    temporal_address: str = "127.0.0.1:7233"
    temporal_task_queue: str = "olympus-command-v1"
    http_host: Literal["127.0.0.1"] = "127.0.0.1"
    http_port: int = Field(default=8080, ge=1024, le=65535)

    # Execution-node mesh. Nodes always dial out to this gateway; the gateway
    # never dials a node, and the bind address stays loopback so private reach
    # comes from Tailscale Serve rather than from a wider listener.
    node_mesh_enabled: bool = False
    node_task_queue: str = "olympus-node-edge-v1"
    node_heartbeat_interval_seconds: int = Field(default=15, ge=1, le=3600)
    node_heartbeat_expiry_seconds: int = Field(default=45, ge=2, le=7200)
    node_enrollment_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    node_control_plane_key_id: str = "olympus-control-plane-v1"
    node_control_plane_private_key: SecretStr | None = None
    # The control-plane host is itself an execution node, enrolled through the
    # same flow and granted only the bounded read-only inspection capability.
    node_attach_control_plane_host: bool = True
    node_control_plane_host_name: str = "vps-primary"

    # PostgreSQL is the canonical owner of node-mesh state. When this is unset
    # the mesh falls back to the in-process store, which loses every node,
    # grant, revocation, freeze, and audit event on restart. The runtime says
    # which store it chose at startup so that fallback is never silent.
    database_url: SecretStr | None = None

    def __init__(self, **values: Any) -> None:
        super().__init__(
            **apply_fire_environment_aliases(
                values,
                fields=type(self).model_fields,
                canonical_prefix="FIRE_",
                legacy_prefix="OLYMPUS_",
            )
        )

    @field_validator("database_url", mode="before")
    @classmethod
    def blank_database_url_means_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("dev_command_token")
    @classmethod
    def validate_dev_command_token(cls, token: SecretStr) -> SecretStr:
        if not all(0x21 <= ord(character) <= 0x7E for character in token.get_secret_value()):
            raise ValueError("development command token must contain only visible ASCII characters")
        return token

    @field_validator("node_control_plane_private_key", mode="before")
    @classmethod
    def blank_control_plane_key_means_unset(cls, value: object) -> object:
        # A checked-in placeholder is an empty string. Treat it as absent so the
        # runtime generates an ephemeral development key instead of failing on
        # an unusable one.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def validate_node_mesh_bounds(self) -> Self:
        if self.node_heartbeat_expiry_seconds <= self.node_heartbeat_interval_seconds:
            raise ValueError("node heartbeat expiry must exceed the heartbeat interval")
        return self

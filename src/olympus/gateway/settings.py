from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OLYMPUS_", env_file=".env", extra="forbid")

    environment: Literal["development", "test"]
    dev_command_token: SecretStr = Field(min_length=32, max_length=256)
    temporal_address: str = "127.0.0.1:7233"
    temporal_task_queue: str = "olympus-command-v1"
    http_host: Literal["127.0.0.1"] = "127.0.0.1"
    http_port: int = Field(default=8080, ge=1024, le=65535)

    @field_validator("dev_command_token")
    @classmethod
    def validate_dev_command_token(cls, token: SecretStr) -> SecretStr:
        if not all(0x21 <= ord(character) <= 0x7E for character in token.get_secret_value()):
            raise ValueError("development command token must contain only visible ASCII characters")
        return token

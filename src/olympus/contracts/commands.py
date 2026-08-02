from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

CommandText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=8000),
]


class TrustLabel(StrEnum):
    CONTROL = "control"
    USER_AUTHORIZED = "user-authorized"
    MODEL_DERIVED = "model-derived"
    EXTERNAL_UNTRUSTED = "external-untrusted"


class JobStatus(StrEnum):
    ACCEPTED = "accepted"
    COMPILED = "compiled"
    CANCELLED = "cancelled"
    FROZEN = "frozen"
    FAILED = "failed"


class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: CommandText


class CommandAccepted(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    status: JobStatus = JobStatus.ACCEPTED


@dataclass(frozen=True)
class CommandEnvelope:
    job_id: str
    commander_id: str
    authority_lease_id: str
    command_text: str
    received_at: str
    guild_id: str = "development-guild"
    channel_id: str = "development-channel"
    interaction_id: str = "development-interaction"
    authority_epoch: int = 1
    trust_label: TrustLabel = TrustLabel.USER_AUTHORIZED
    max_nodes: int = 32
    max_fan_out: int = 4
    status: JobStatus = JobStatus.ACCEPTED

    def __post_init__(self) -> None:
        required = {
            "job_id": self.job_id,
            "commander_id": self.commander_id,
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "interaction_id": self.interaction_id,
            "authority_lease_id": self.authority_lease_id,
            "command_text": self.command_text,
            "received_at": self.received_at,
        }
        non_strings = [name for name, value in required.items() if type(value) is not str]
        if non_strings:
            raise TypeError(f"command envelope requires string fields: {', '.join(non_strings)}")

        empty = [name for name, value in required.items() if not value.strip()]
        if empty:
            raise ValueError(f"command envelope contains empty fields: {', '.join(empty)}")
        if len(self.command_text) > 8000:
            raise ValueError("command_text must be at most 8000 characters")
        if type(self.trust_label) is not TrustLabel:
            raise TypeError("trust_label must be a TrustLabel")
        if type(self.status) is not JobStatus:
            raise TypeError("status must be a JobStatus")
        if type(self.max_nodes) is not int:
            raise TypeError("max_nodes must be an int")
        if type(self.max_fan_out) is not int:
            raise TypeError("max_fan_out must be an int")
        if type(self.authority_epoch) is not int:
            raise TypeError("authority_epoch must be an int")
        if self.authority_epoch < 1:
            raise ValueError("authority_epoch must be strictly positive")
        if self.commander_id == "628053765181800448" and any(
            value.startswith("development-")
            for value in (self.guild_id, self.channel_id, self.interaction_id)
        ):
            raise ValueError("production commander requires literal Discord identity evidence")
        if not 1 <= self.max_nodes <= 128:
            raise ValueError("max_nodes must be between 1 and 128")
        if not 1 <= self.max_fan_out <= 16:
            raise ValueError("max_fan_out must be between 1 and 16")
        try:
            parsed_received_at = datetime.fromisoformat(self.received_at)
        except ValueError as exc:
            raise ValueError("received_at must be a canonical ISO-8601 timestamp") from exc
        if (
            parsed_received_at.tzinfo is None
            or parsed_received_at.utcoffset() is None
            or parsed_received_at.isoformat() != self.received_at
        ):
            raise ValueError("received_at must be a canonical ISO-8601 timestamp")


@dataclass(frozen=True)
class CompiledJobReceipt:
    job_id: str
    status: JobStatus
    node_count: int
    graph_digest: str

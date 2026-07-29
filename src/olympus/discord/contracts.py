from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

Snowflake = Annotated[str, StringConstraints(pattern=r"^[0-9]{17,20}$")]


class DiscordUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Snowflake


class DiscordMember(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: DiscordUser


class DiscordCommandData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Snowflake
    name: str
    options: tuple["DiscordCommandOption", ...] = ()


class DiscordCommandOption(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal[3]
    value: str


class DiscordInteraction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Snowflake
    application_id: Snowflake
    type: Literal[2]
    guild_id: Snowflake
    channel_id: Snowflake
    member: DiscordMember
    data: DiscordCommandData

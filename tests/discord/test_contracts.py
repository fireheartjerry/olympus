import pytest
from pydantic import ValidationError

from olympus.discord.contracts import DiscordInteraction


def valid_interaction() -> dict[str, object]:
    return {
        "id": "100000000000000001",
        "application_id": "100000000000000002",
        "type": 2,
        "guild_id": "100000000000000003",
        "channel_id": "100000000000000004",
        "member": {"user": {"id": "628053765181800448"}},
        "data": {"id": "100000000000000005", "name": "olympus"},
    }


def test_parses_literal_discord_scope() -> None:
    interaction = DiscordInteraction.model_validate(valid_interaction())

    assert interaction.id == "100000000000000001"
    assert interaction.member.user.id == "628053765181800448"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("id",), "not-a-snowflake"),
        (("guild_id",), ""),
        (("member", "user", "id"), 628053765181800448),
    ],
)
def test_rejects_nonliteral_discord_identity(path: tuple[str, ...], value: object) -> None:
    body = valid_interaction()
    target = body
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment,index]
    target[path[-1]] = value

    with pytest.raises(ValidationError):
        DiscordInteraction.model_validate(body)


def test_rejects_unknown_interaction_fields() -> None:
    body = valid_interaction()
    body["authority"] = "self-approved"

    with pytest.raises(ValidationError):
        DiscordInteraction.model_validate(body)

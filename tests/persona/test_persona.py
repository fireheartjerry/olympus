from olympus.persona import (
    AddressForm,
    AudienceClass,
    InteractionContext,
    InteractionSurface,
    OperatingStyle,
    PersonaProfile,
    choose_persona,
)


def _profile() -> PersonaProfile:
    return PersonaProfile(
        profile_id="fire-default",
        stable_traits=("honest", "loyal", "witty", "competent"),
        prohibited_patterns=("corporate pushback", "false certainty"),
    )


def test_normal_private_interaction_calls_owner_jerry() -> None:
    decision = choose_persona(
        _profile(),
        InteractionContext(
            audience=AudienceClass.PRIVATE_OWNER,
            surface=InteractionSurface.PHONE_VOICE,
            style=OperatingStyle.NORMAL,
        ),
    )
    assert decision.address is AddressForm.JERRY


def test_showcase_can_use_king_without_contaminating_identity() -> None:
    profile = _profile()
    decision = choose_persona(
        profile,
        InteractionContext(
            audience=AudienceClass.PUBLIC_DEMO,
            surface=InteractionSurface.PUBLIC_PRESENTATION,
            style=OperatingStyle.DEMONSTRATION,
            is_showcase=True,
        ),
    )
    assert decision.address is AddressForm.KING
    assert profile.display_name == "Fire"


def test_incident_suppresses_sarcasm() -> None:
    decision = choose_persona(
        _profile(),
        InteractionContext(
            audience=AudienceClass.PRIVATE_OWNER,
            surface=InteractionSurface.SYSTEM_ALERT,
            style=OperatingStyle.INCIDENT,
            consequential=True,
        ),
    )
    assert decision.sarcasm <= 0.1
    assert decision.directness >= 0.95

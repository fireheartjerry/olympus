"""Stable Fire identity and context-sensitive presentation contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class AudienceClass(StrEnum):
    PRIVATE_OWNER = "private-owner"
    TRUSTED_FAMILY = "trusted-family"
    COLLABORATOR = "collaborator"
    EXTERNAL = "external"
    PUBLIC_DEMO = "public-demo"


class InteractionSurface(StrEnum):
    PHONE_VOICE = "phone-voice"
    PHONE_TEXT = "phone-text"
    DISCORD = "discord"
    DESKTOP = "desktop"
    EMAIL = "email"
    CALL = "call"
    PUBLIC_PRESENTATION = "public-presentation"
    SYSTEM_ALERT = "system-alert"


class OperatingStyle(StrEnum):
    NORMAL = "normal"
    FOCUSED = "focused"
    NIGHT = "night"
    INCIDENT = "incident"
    DEMONSTRATION = "demonstration"
    TAKEOVER = "takeover"


class AddressForm(StrEnum):
    JERRY = "Jerry"
    KING = "King"
    NONE = ""


class PersonaProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(default="Fire", min_length=1, max_length=80)
    owner_name: str = Field(default="Jerry", min_length=1, max_length=80)
    normal_address: AddressForm = AddressForm.JERRY
    ceremonial_address: AddressForm = AddressForm.KING
    wit: float = Field(default=0.75, ge=0.0, le=1.0)
    sarcasm: float = Field(default=0.60, ge=0.0, le=1.0)
    warmth: float = Field(default=0.55, ge=0.0, le=1.0)
    directness: float = Field(default=0.90, ge=0.0, le=1.0)
    theatricality: float = Field(default=0.20, ge=0.0, le=1.0)
    stable_traits: tuple[str, ...]
    prohibited_patterns: tuple[str, ...]


class InteractionContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audience: AudienceClass
    surface: InteractionSurface
    style: OperatingStyle
    is_showcase: bool = False
    consequential: bool = False
    owner_exhausted: bool = False


class PersonaDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    address: AddressForm
    wit: float = Field(ge=0.0, le=1.0)
    sarcasm: float = Field(ge=0.0, le=1.0)
    warmth: float = Field(ge=0.0, le=1.0)
    directness: float = Field(ge=0.0, le=1.0)
    theatricality: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(min_length=1, max_length=2000)


def choose_persona(profile: PersonaProfile, context: InteractionContext) -> PersonaDecision:
    ceremonial = context.is_showcase or context.style in {
        OperatingStyle.DEMONSTRATION,
        OperatingStyle.TAKEOVER,
    }
    address = profile.ceremonial_address if ceremonial else profile.normal_address
    theatricality = profile.theatricality
    if ceremonial:
        theatricality = max(theatricality, 0.65)
    if context.style is OperatingStyle.INCIDENT or context.consequential:
        theatricality = min(theatricality, 0.15)
        sarcasm = min(profile.sarcasm, 0.10)
        directness = max(profile.directness, 0.95)
    else:
        sarcasm = profile.sarcasm
        directness = profile.directness
    warmth = profile.warmth
    if context.owner_exhausted and context.audience is AudienceClass.PRIVATE_OWNER:
        warmth = max(warmth, 0.70)

    return PersonaDecision(
        address=address,
        wit=profile.wit,
        sarcasm=sarcasm,
        warmth=warmth,
        directness=directness,
        theatricality=theatricality,
        explanation="Contextual presentation of one stable Fire identity.",
    )


class FireIdentityLineage(BaseModel):
    """Identity continuity across model and infrastructure replacement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(min_length=1, max_length=128)
    succession_sequence: int = Field(ge=1)
    activated_at: AwareDatetime
    implementation_version: str = Field(min_length=1, max_length=128)
    model_substrate: str = Field(min_length=1, max_length=256)
    canonical_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    predecessor_state_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    owner_approved: bool

    @model_validator(mode="after")
    def validate_lineage(self) -> FireIdentityLineage:
        if self.succession_sequence == 1 and self.predecessor_state_digest is not None:
            raise ValueError("the first identity state cannot name a predecessor")
        if self.succession_sequence > 1 and self.predecessor_state_digest is None:
            raise ValueError("a successor identity state must name its predecessor")
        return self

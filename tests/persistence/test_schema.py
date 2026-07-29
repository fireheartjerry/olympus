from sqlalchemy import CheckConstraint, UniqueConstraint

from olympus.persistence.models import Base

EXPECTED_TABLES = {
    "webauthn_credentials",
    "webauthn_challenges",
    "authority_state",
    "authority_leases",
    "global_freeze",
    "discord_interactions",
    "authority_anomalies",
    "security_audit_events",
}


def test_metadata_contains_exact_slice_one_authority_tables() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_singleton_and_digest_constraints_are_named() -> None:
    authority = Base.metadata.tables["authority_state"]
    freeze = Base.metadata.tables["global_freeze"]
    audit = Base.metadata.tables["security_audit_events"]

    assert {constraint.name for constraint in authority.constraints} >= {
        "pk_authority_state",
        "ck_authority_state_singleton",
        "ck_authority_state_epoch_positive",
    }
    assert {constraint.name for constraint in freeze.constraints} >= {
        "pk_global_freeze",
        "ck_global_freeze_singleton",
        "ck_global_freeze_epoch_positive",
    }
    assert {
        constraint.name
        for constraint in audit.constraints
        if isinstance(constraint, (CheckConstraint, UniqueConstraint))
    } >= {
        "ck_security_audit_events_event_hash_length",
        "uq_security_audit_events_sequence",
        "uq_security_audit_events_event_hash",
    }


def test_interaction_id_and_challenge_digest_are_unique() -> None:
    interactions = Base.metadata.tables["discord_interactions"]
    challenges = Base.metadata.tables["webauthn_challenges"]

    assert interactions.c.interaction_id.unique is True
    assert challenges.c.challenge_digest.unique is True
    assert challenges.c.challenge_value.type.length == 32

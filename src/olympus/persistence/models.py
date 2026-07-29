from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class WebAuthnCredentialRow(Base):
    __tablename__ = "webauthn_credentials"

    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    commander_id: Mapped[str] = mapped_column(String(20), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        PrimaryKeyConstraint("credential_id", name="pk_webauthn_credentials"),
        CheckConstraint("sign_count >= 0", name="ck_webauthn_credentials_sign_count"),
    )


class WebAuthnChallengeRow(Base):
    __tablename__ = "webauthn_challenges"

    challenge_id: Mapped[str] = mapped_column(String(64), nullable=False)
    challenge_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    commander_id: Mapped[str] = mapped_column(String(20), nullable=False)
    payload_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        PrimaryKeyConstraint("challenge_id", name="pk_webauthn_challenges"),
        CheckConstraint(
            "expires_at > issued_at",
            name="ck_webauthn_challenges_expiry",
        ),
    )


class AuthorityStateRow(Base):
    __tablename__ = "authority_state"

    singleton_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    authority_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("singleton_id", name="pk_authority_state"),
        CheckConstraint("singleton_id = 1", name="ck_authority_state_singleton"),
        CheckConstraint("authority_epoch > 0", name="ck_authority_state_epoch_positive"),
    )


class AuthorityLeaseRow(Base):
    __tablename__ = "authority_leases"

    lease_id: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    commander_id: Mapped[str] = mapped_column(String(20), nullable=False)
    guild_id: Mapped[str] = mapped_column(String(20), nullable=False)
    channel_scope_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    credential_id: Mapped[bytes] = mapped_column(
        ForeignKey("webauthn_credentials.credential_id"),
        nullable=False,
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        PrimaryKeyConstraint("lease_id", name="pk_authority_leases"),
        CheckConstraint("authority_epoch > 0", name="ck_authority_leases_epoch_positive"),
        CheckConstraint("expires_at > issued_at", name="ck_authority_leases_expiry"),
        UniqueConstraint("authority_epoch", name="uq_authority_leases_epoch"),
    )


class GlobalFreezeRow(Base):
    __tablename__ = "global_freeze"

    singleton_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    freeze_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    frozen: Mapped[bool] = mapped_column(Boolean, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    reason_code: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("singleton_id", name="pk_global_freeze"),
        CheckConstraint("singleton_id = 1", name="ck_global_freeze_singleton"),
        CheckConstraint("freeze_epoch > 0", name="ck_global_freeze_epoch_positive"),
    )


class DiscordInteractionRow(Base):
    __tablename__ = "discord_interactions"

    interaction_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    request_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(32))
    workflow_id: Mapped[str | None] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (PrimaryKeyConstraint("interaction_id", name="pk_discord_interactions"),)


class AuthorityAnomalyRow(Base):
    __tablename__ = "authority_anomalies"

    anomaly_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    freeze_epoch: Mapped[int | None] = mapped_column(BigInteger)

    __table_args__ = (
        PrimaryKeyConstraint("anomaly_id", name="pk_authority_anomalies"),
        CheckConstraint(
            "freeze_epoch IS NULL OR freeze_epoch > 0",
            name="ck_authority_anomalies_freeze_epoch",
        ),
    )


class SecurityAuditEventRow(Base):
    __tablename__ = "security_audit_events"

    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    event_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("event_id", name="pk_security_audit_events"),
        UniqueConstraint("sequence", name="uq_security_audit_events_sequence"),
        UniqueConstraint("event_hash", name="uq_security_audit_events_event_hash"),
        CheckConstraint("sequence > 0", name="ck_security_audit_events_sequence_positive"),
        CheckConstraint(
            "octet_length(event_hash) = 32",
            name="ck_security_audit_events_event_hash_length",
        ),
        CheckConstraint(
            "octet_length(previous_hash) = 32",
            name="ck_security_audit_events_previous_hash_length",
        ),
    )

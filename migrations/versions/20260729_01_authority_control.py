"""Establish canonical Slice 1 authority state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260729_01"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "authority_anomalies",
        sa.Column("anomaly_id", sa.String(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("evidence_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("freeze_epoch", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "freeze_epoch IS NULL OR freeze_epoch > 0",
            name="ck_authority_anomalies_freeze_epoch",
        ),
        sa.PrimaryKeyConstraint("anomaly_id", name="pk_authority_anomalies"),
    )
    op.create_table(
        "authority_state",
        sa.Column("singleton_id", sa.BigInteger(), nullable=False),
        sa.Column("authority_epoch", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("authority_epoch > 0", name="ck_authority_state_epoch_positive"),
        sa.CheckConstraint("singleton_id = 1", name="ck_authority_state_singleton"),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_authority_state"),
    )
    op.create_table(
        "discord_interactions",
        sa.Column("interaction_id", sa.String(length=20), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("workflow_id", sa.String(length=64), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("interaction_id", name="pk_discord_interactions"),
        sa.UniqueConstraint("interaction_id"),
    )
    op.create_table(
        "global_freeze",
        sa.Column("singleton_id", sa.BigInteger(), nullable=False),
        sa.Column("freeze_epoch", sa.BigInteger(), nullable=False),
        sa.Column("frozen", sa.Boolean(), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("freeze_epoch > 0", name="ck_global_freeze_epoch_positive"),
        sa.CheckConstraint("singleton_id = 1", name="ck_global_freeze_singleton"),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_global_freeze"),
    )
    op.create_table(
        "security_audit_events",
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("event_hash", sa.LargeBinary(length=32), nullable=False),
        sa.CheckConstraint(
            "octet_length(event_hash) = 32",
            name="ck_security_audit_events_event_hash_length",
        ),
        sa.CheckConstraint(
            "octet_length(previous_hash) = 32",
            name="ck_security_audit_events_previous_hash_length",
        ),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_security_audit_events_sequence_positive",
        ),
        sa.PrimaryKeyConstraint("event_id", name="pk_security_audit_events"),
        sa.UniqueConstraint("event_hash", name="uq_security_audit_events_event_hash"),
        sa.UniqueConstraint("sequence", name="uq_security_audit_events_sequence"),
    )
    op.create_table(
        "webauthn_challenges",
        sa.Column("challenge_id", sa.String(length=64), nullable=False),
        sa.Column("challenge_value", sa.LargeBinary(length=32), nullable=False),
        sa.Column("challenge_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("commander_id", sa.String(length=20), nullable=False),
        sa.Column("payload_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "expires_at > issued_at",
            name="ck_webauthn_challenges_expiry",
        ),
        sa.PrimaryKeyConstraint("challenge_id", name="pk_webauthn_challenges"),
        sa.UniqueConstraint("challenge_digest"),
    )
    op.create_table(
        "webauthn_credentials",
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("commander_id", sa.String(length=20), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "sign_count >= 0",
            name="ck_webauthn_credentials_sign_count",
        ),
        sa.PrimaryKeyConstraint("credential_id", name="pk_webauthn_credentials"),
    )
    op.create_table(
        "authority_leases",
        sa.Column("lease_id", sa.String(length=64), nullable=False),
        sa.Column("authority_epoch", sa.BigInteger(), nullable=False),
        sa.Column("commander_id", sa.String(length=20), nullable=False),
        sa.Column("guild_id", sa.String(length=20), nullable=False),
        sa.Column("channel_scope_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "authority_epoch > 0",
            name="ck_authority_leases_epoch_positive",
        ),
        sa.CheckConstraint("expires_at > issued_at", name="ck_authority_leases_expiry"),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["webauthn_credentials.credential_id"],
        ),
        sa.PrimaryKeyConstraint("lease_id", name="pk_authority_leases"),
        sa.UniqueConstraint("authority_epoch", name="uq_authority_leases_epoch"),
    )


def downgrade() -> None:
    for table_name in (
        "authority_leases",
        "webauthn_credentials",
        "webauthn_challenges",
        "security_audit_events",
        "global_freeze",
        "discord_interactions",
        "authority_state",
        "authority_anomalies",
    ):
        op.drop_table(table_name)

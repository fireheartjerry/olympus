-- Node-mesh canonical state. Forward-only; this file is never edited after it
-- has been applied to a database that matters.

CREATE TABLE enrollment_tokens (
    token_id                TEXT PRIMARY KEY,
    secret_hash             TEXT NOT NULL CHECK (char_length(secret_hash) = 64),
    node_name               TEXT NOT NULL CHECK (btrim(node_name) <> ''),
    kind                    TEXT NOT NULL,
    platform                TEXT NOT NULL,
    granted_capabilities    TEXT[] NOT NULL DEFAULT '{}',
    issued_at               TIMESTAMPTZ NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    issued_by               TEXT NOT NULL,
    consumed_at             TIMESTAMPTZ,
    consumed_by_node_id     TEXT,
    revoked_at              TIMESTAMPTZ,
    CONSTRAINT enrollment_expiry_after_issue CHECK (expires_at > issued_at),
    -- A consumed token names exactly the node that consumed it. Storage
    -- cannot represent "consumed by nobody".
    CONSTRAINT enrollment_consumption_complete CHECK (
        (consumed_at IS NULL) = (consumed_by_node_id IS NULL)
    )
);

CREATE TABLE nodes (
    node_id                 TEXT PRIMARY KEY,
    node_name               TEXT NOT NULL,
    kind                    TEXT NOT NULL,
    platform                TEXT NOT NULL,
    architecture            TEXT NOT NULL,
    agent_version           TEXT NOT NULL,
    public_key              TEXT NOT NULL CHECK (btrim(public_key) <> ''),
    granted_capabilities    TEXT[] NOT NULL DEFAULT '{}',
    declared_capabilities   TEXT[] NOT NULL DEFAULT '{}',
    labels                  JSONB NOT NULL DEFAULT '[]'::jsonb,
    enrolled_at             TIMESTAMPTZ NOT NULL,
    enrollment_token_id     TEXT NOT NULL,
    session_id              TEXT,
    session_started_at      TIMESTAMPTZ,
    last_heartbeat_at       TIMESTAMPTZ,
    last_health             JSONB,
    quarantined_at          TIMESTAMPTZ,
    quarantine_reason       TEXT NOT NULL DEFAULT '',
    revoked_at              TIMESTAMPTZ,
    revocation_reason       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX nodes_node_name_idx ON nodes (node_name);

-- Exactly one dispatch kill switch exists for the whole mesh.
CREATE TABLE dispatch_control (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    frozen          BOOLEAN NOT NULL DEFAULT FALSE,
    freeze_epoch    INTEGER NOT NULL DEFAULT 0 CHECK (freeze_epoch >= 0),
    changed_at      TIMESTAMPTZ,
    reason          TEXT NOT NULL DEFAULT ''
);

INSERT INTO dispatch_control (id) VALUES (1);

CREATE TABLE node_jobs (
    job_id                  TEXT PRIMARY KEY,
    node_id                 TEXT NOT NULL,
    capability              TEXT NOT NULL,
    dedupe_key              TEXT NOT NULL,
    status                  TEXT NOT NULL,
    attempt                 INTEGER NOT NULL CHECK (attempt >= 1),
    commander_id            TEXT NOT NULL,
    authority_lease_id      TEXT NOT NULL,
    authority_epoch         INTEGER,
    created_at              TIMESTAMPTZ NOT NULL,
    updated_at              TIMESTAMPTZ NOT NULL,
    progress_events         INTEGER NOT NULL DEFAULT 0,
    last_message            TEXT NOT NULL DEFAULT '',
    reason                  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX node_jobs_status_idx ON node_jobs (status);

-- The audit chain. Application code only ever inserts here.
CREATE TABLE node_audit_events (
    sequence        BIGINT PRIMARY KEY,
    event_id        TEXT NOT NULL UNIQUE,
    version         INTEGER NOT NULL,
    recorded_at     TEXT NOT NULL,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    node_id         TEXT,
    job_id          TEXT,
    payload         JSONB NOT NULL,
    payload_digest  TEXT NOT NULL,
    previous_hash   TEXT NOT NULL,
    event_hash      TEXT NOT NULL UNIQUE,
    CONSTRAINT audit_sequence_positive CHECK (sequence >= 1)
);

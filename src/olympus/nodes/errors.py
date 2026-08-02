from enum import StrEnum


class NodeReason(StrEnum):
    """Stable reason codes for every node-mesh refusal.

    Reason codes are recorded in the audit trail. Callers outside the control
    plane receive a generic failure and the code, never internal detail.
    """

    # Enrollment token lifecycle.
    ENROLLMENT_MALFORMED = "enrollment-token-malformed"
    ENROLLMENT_UNKNOWN = "enrollment-token-unknown"
    ENROLLMENT_CREDENTIAL_MISMATCH = "enrollment-token-secret-mismatch"
    ENROLLMENT_EXPIRED = "enrollment-token-expired"
    ENROLLMENT_CONSUMED = "enrollment-token-consumed"
    ENROLLMENT_REVOKED = "enrollment-token-revoked"
    ENROLLMENT_SCOPE_MISMATCH = "enrollment-scope-mismatch"
    ENROLLMENT_KEY_INVALID = "enrollment-key-invalid"
    ENROLLMENT_DESCRIPTION_INVALID = "enrollment-description-invalid"

    # Node identity and lifecycle.
    NODE_UNKNOWN = "node-unknown"
    NODE_REVOKED = "node-revoked"
    NODE_QUARANTINED = "node-quarantined"
    NODE_OFFLINE = "node-offline"
    NODE_SESSION_REPLACED = "node-session-replaced"
    NODE_HEARTBEAT_EXPIRED = "node-heartbeat-expired"

    # Session handshake.
    PROTOCOL_VERSION_UNSUPPORTED = "protocol-version-unsupported"
    HANDSHAKE_FRAME_UNEXPECTED = "handshake-frame-unexpected"
    HANDSHAKE_MALFORMED = "handshake-malformed"
    HANDSHAKE_TIMEOUT = "handshake-timeout"
    NODE_PROOF_INVALID = "node-proof-invalid"
    SERVER_PROOF_INVALID = "server-proof-invalid"
    NONCE_INVALID = "nonce-invalid"
    SESSION_CLOSED = "session-closed"

    # Capability admission.
    CAPABILITY_UNKNOWN = "capability-unknown"
    CAPABILITY_RESERVED = "capability-reserved"
    CAPABILITY_NOT_GRANTED = "capability-not-granted"
    CAPABILITY_NOT_DECLARED = "capability-not-declared"
    CAPABILITY_PARAMETERS_INVALID = "capability-parameters-invalid"

    # Dispatch admission and execution.
    DISPATCH_FROZEN = "dispatch-frozen"
    DISPATCH_NO_ELIGIBLE_NODE = "dispatch-no-eligible-node"
    DISPATCH_CONCURRENCY_EXCEEDED = "dispatch-concurrency-exceeded"
    DISPATCH_DUPLICATE = "dispatch-duplicate"
    JOB_UNKNOWN = "job-unknown"
    JOB_CANCELLED = "job-cancelled"
    JOB_DEADLINE_EXCEEDED = "job-deadline-exceeded"
    JOB_FAILED = "job-failed"
    JOB_OUTPUT_TOO_LARGE = "job-output-too-large"

    # Frame and payload bounds.
    FRAME_TOO_LARGE = "frame-too-large"
    FRAME_MALFORMED = "frame-malformed"
    FRAME_UNEXPECTED = "frame-unexpected"

    # Control-plane state.
    FREEZE_EPOCH_MISMATCH = "freeze-epoch-mismatch"
    NOT_FROZEN = "not-frozen"
    UNAUTHORIZED = "unauthorized"


class NodeMeshError(Exception):
    """Typed node-mesh failure carrying a stable, auditable reason code."""

    def __init__(self, reason: NodeReason, message: str = "") -> None:
        super().__init__(message or reason.value)
        self.reason = reason
        self.message = message or reason.value


PERMANENT_REFUSALS: frozenset[NodeReason] = frozenset(
    {
        NodeReason.CAPABILITY_UNKNOWN,
        NodeReason.CAPABILITY_RESERVED,
        NodeReason.CAPABILITY_NOT_GRANTED,
        NodeReason.NODE_UNKNOWN,
        NodeReason.NODE_REVOKED,
        NodeReason.DISPATCH_FROZEN,
        NodeReason.UNAUTHORIZED,
    }
)


def is_permanent_refusal(reason: NodeReason) -> bool:
    """Refusals that retrying cannot turn into an allowance."""
    return reason in PERMANENT_REFUSALS

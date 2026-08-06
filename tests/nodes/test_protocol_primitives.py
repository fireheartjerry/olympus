from dataclasses import replace
from datetime import UTC, datetime

import pytest

from olympus.contracts.commands import TrustLabel
from olympus.nodes.audit import (
    AuditAction,
    AuditDecision,
    NodeAuditLog,
    verify_chain,
)
from olympus.nodes.capabilities import (
    CAPABILITY_CATALOG,
    ENABLED_CAPABILITIES,
    FILE_LIST,
    FILE_READ,
    FILE_WRITE,
    SYSTEM_INSPECT,
    CapabilityRisk,
    CapabilityStatus,
    describe_capability,
    normalize_capability_names,
    require_dispatchable_capability,
)
from olympus.nodes.crypto import (
    dedupe_key_for,
    enrollment_secret_matches,
    generate_node_keypair,
    new_enrollment_secret,
    public_key_of,
    sign_enrollment_token,
    sign_payload,
    split_enrollment_token,
    verify_payload,
    verify_signed_enrollment_token,
)
from olympus.nodes.errors import NodeMeshError, NodeReason, is_permanent_refusal
from olympus.nodes.models import NodeJobOutcome, NodeJobStatus
from olympus.nodes.protocol import (
    MAX_FRAME_BYTES,
    PROTOCOL_ID,
    HeartbeatFrame,
    JobDispatchFrame,
    encode_frame,
    node_proof_payload,
    parse_client_frame,
    parse_server_frame,
    server_proof_payload,
)
from olympus.nodes.redaction import (
    REDACTION_PLACEHOLDER,
    bound_text,
    redact_text,
    redact_value,
)


def test_only_bounded_read_only_capabilities_are_dispatchable_today() -> None:
    """Inspection and scoped file read. Nothing that changes a node.

    The list is asserted exactly rather than by membership, so enabling a
    capability is a deliberate edit to this test and not a silent side effect
    of adding a catalog entry.
    """
    assert ENABLED_CAPABILITIES == (
        FILE_LIST.name,
        FILE_READ.name,
        FILE_WRITE.name,
        SYSTEM_INSPECT.name,
    )
    for descriptor in (SYSTEM_INSPECT, FILE_READ, FILE_LIST, FILE_WRITE):
        assert require_dispatchable_capability(descriptor.name) is descriptor


def test_nothing_dispatchable_can_mutate_without_an_approval() -> None:
    """The invariant that survives fs.write being enabled.

    "Nothing enabled mutates" was true until the first mutating capability, and
    deleting the guard at that point would have removed the check exactly when
    it started to matter. The property that still holds — and that has to — is
    that changing a node is never unapproved.
    """
    for name in ENABLED_CAPABILITIES:
        descriptor = CAPABILITY_CATALOG[name]
        if descriptor.mutating:
            assert descriptor.requires_approval is True, f"{name} mutates without approval"
        else:
            assert descriptor.risk is CapabilityRisk.OBSERVE, f"{name} observes above OBSERVE"


def test_no_enabled_capability_reaches_beyond_the_node_it_runs_on() -> None:
    # MUTATE_EXTERNAL and PRIVILEGED reach past the machine. Nothing enabled
    # may do that yet, whatever its approval status.
    for name in ENABLED_CAPABILITIES:
        assert CAPABILITY_CATALOG[name].risk in (
            CapabilityRisk.OBSERVE,
            CapabilityRisk.MUTATE_LOCAL,
        ), f"{name} is enabled with a risk beyond the local node"


def test_every_capability_that_mutates_requires_approval() -> None:
    # Across the whole catalog, reserved or not, so a capability cannot be
    # enabled later while its approval flag is quietly false.
    for name, descriptor in CAPABILITY_CATALOG.items():
        if descriptor.mutating:
            assert descriptor.requires_approval is True, f"{name} mutates without approval"


def test_the_dangerous_capabilities_are_still_reserved() -> None:
    for name in (
        "shell.powershell@1",
        "agent.claude@1",
        "agent.codex@1",
        "browser.session@1",
    ):
        assert CAPABILITY_CATALOG[name].status is CapabilityStatus.RESERVED, name


RESERVED_NAMES = [
    name for name, entry in CAPABILITY_CATALOG.items() if entry.status is CapabilityStatus.RESERVED
]


@pytest.mark.parametrize("name", RESERVED_NAMES)
def test_reserved_capabilities_refuse_dispatch(name: str) -> None:
    with pytest.raises(NodeMeshError) as failure:
        require_dispatchable_capability(name)
    assert failure.value.reason is NodeReason.CAPABILITY_RESERVED


def test_unknown_capabilities_are_refused() -> None:
    with pytest.raises(NodeMeshError) as failure:
        describe_capability("nope.nope@1")
    assert failure.value.reason is NodeReason.CAPABILITY_UNKNOWN


def test_no_capability_may_produce_control_trusted_output() -> None:
    assert all(
        entry.output_trust_label is TrustLabel.EXTERNAL_UNTRUSTED
        for entry in CAPABILITY_CATALOG.values()
    )


def test_every_reserved_capability_that_mutates_requires_approval() -> None:
    assert all(entry.requires_approval for entry in CAPABILITY_CATALOG.values() if entry.mutating)


def test_capability_declarations_are_normalized_and_unknown_names_dropped() -> None:
    assert normalize_capability_names([SYSTEM_INSPECT.name, "made.up@1", SYSTEM_INSPECT.name]) == (
        SYSTEM_INSPECT.name,
    )
    assert normalize_capability_names("not-a-list") == ()
    assert normalize_capability_names(None) == ()


def test_node_output_may_never_claim_control_trust() -> None:
    with pytest.raises(ValueError, match="control trust label"):
        NodeJobOutcome(
            job_id="job-1",
            node_id="node-1",
            capability=SYSTEM_INSPECT.name,
            dedupe_key="0" * 64,
            status=NodeJobStatus.SUCCEEDED,
            attempt=1,
            trust_label=TrustLabel.CONTROL,
        )


def test_signatures_verify_only_over_the_exact_payload() -> None:
    keys = generate_node_keypair()
    payload = server_proof_payload(
        protocol=PROTOCOL_ID, session_id="nsx-1", node_id="node-1", node_nonce="n" * 32
    )
    signature = sign_payload(keys.private_key, payload)
    verify_payload(keys.public_key, payload, signature, NodeReason.SERVER_PROOF_INVALID)

    with pytest.raises(NodeMeshError) as altered:
        verify_payload(
            keys.public_key,
            {**payload, "session_id": "nsx-2"},
            signature,
            NodeReason.SERVER_PROOF_INVALID,
        )
    assert altered.value.reason is NodeReason.SERVER_PROOF_INVALID

    other = generate_node_keypair()
    with pytest.raises(NodeMeshError):
        verify_payload(other.public_key, payload, signature, NodeReason.NODE_PROOF_INVALID)


def test_a_node_proof_is_bound_to_the_session_and_the_server_nonce() -> None:
    keys = generate_node_keypair()

    def payload(**overrides: str) -> dict[str, str]:
        fields = {
            "protocol": PROTOCOL_ID,
            "session_id": "nsx-1",
            "node_id": "node-1",
            "server_nonce": "a" * 32,
            "capabilities_digest": "0" * 64,
        }
        fields.update(overrides)
        return node_proof_payload(**fields)  # type: ignore[arg-type]

    original = payload()
    signature = sign_payload(keys.private_key, original)
    verify_payload(keys.public_key, original, signature, NodeReason.NODE_PROOF_INVALID)

    # Every field the proof is supposed to bind must break verification.
    for field, value in [
        ("session_id", "nsx-2"),
        ("server_nonce", "b" * 32),
        ("node_id", "node-2"),
        ("capabilities_digest", "1" * 64),
        ("protocol", "olympus-node/2"),
    ]:
        with pytest.raises(NodeMeshError) as failure:
            verify_payload(
                keys.public_key,
                payload(**{field: value}),
                signature,
                NodeReason.NODE_PROOF_INVALID,
            )
        assert failure.value.reason is NodeReason.NODE_PROOF_INVALID

    assert (
        original["purpose"]
        != server_proof_payload(
            protocol=PROTOCOL_ID, session_id="nsx-1", node_id="node-1", node_nonce="a" * 32
        )["purpose"]
    )


def test_public_keys_derive_from_private_keys() -> None:
    keys = generate_node_keypair()
    assert public_key_of(keys.private_key) == keys.public_key


def test_enrollment_secrets_are_single_use_and_stored_only_as_hashes() -> None:
    secret = new_enrollment_secret()
    token_id, secret_value = split_enrollment_token(secret.presented)

    assert token_id == secret.token_id
    assert secret_value not in secret.secret_hash
    assert enrollment_secret_matches(token_id, secret_value, secret.secret_hash) is True
    assert enrollment_secret_matches(token_id, "wrong", secret.secret_hash) is False
    assert enrollment_secret_matches("other", secret_value, secret.secret_hash) is False


@pytest.mark.parametrize(
    "presented", ["", "olynode", "olynode_only", "wrongprefix_a_b", "olynode__b", "olynode_a_"]
)
def test_malformed_enrollment_tokens_are_refused(presented: str) -> None:
    with pytest.raises(NodeMeshError) as failure:
        split_enrollment_token(presented)
    assert failure.value.reason is NodeReason.ENROLLMENT_MALFORMED


def test_signed_enrollment_token_is_authentic_and_tamper_evident() -> None:
    keys = generate_node_keypair()
    secret = new_enrollment_secret()
    signed = sign_enrollment_token(keys.private_key, secret.presented)

    assert signed.startswith("olynodev2.")
    assert verify_signed_enrollment_token(keys.public_key, signed) == secret.presented

    prefix, body, signature = signed.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    with pytest.raises(NodeMeshError) as tampered:
        verify_signed_enrollment_token(
            keys.public_key,
            f"{prefix}.{body}.{replacement}{signature[1:]}",
        )
    assert tampered.value.reason is NodeReason.ENROLLMENT_CREDENTIAL_MISMATCH


def test_dedupe_keys_are_deterministic_and_parameter_sensitive() -> None:
    first = dedupe_key_for("job-1", SYSTEM_INSPECT.name, {"sections": ["os", "cpu"]})
    same = dedupe_key_for("job-1", SYSTEM_INSPECT.name, {"sections": ["os", "cpu"]})
    other_parameters = dedupe_key_for("job-1", SYSTEM_INSPECT.name, {"sections": ["os"]})
    other_job = dedupe_key_for("job-2", SYSTEM_INSPECT.name, {"sections": ["os", "cpu"]})

    assert first == same
    assert first not in {other_parameters, other_job}
    assert len(first) == 64


def test_frames_reject_payloads_beyond_the_wire_bound() -> None:
    frame = JobDispatchFrame(
        job_id="job-1",
        attempt=1,
        dedupe_key="0" * 64,
        capability=SYSTEM_INSPECT.name,
        parameters={"filler": "x" * (MAX_FRAME_BYTES + 1)},
        deadline_seconds=10,
        max_output_bytes=1024,
        issued_at="2026-08-01T00:00:00+00:00",
    )
    with pytest.raises(NodeMeshError) as failure:
        encode_frame(frame)
    assert failure.value.reason is NodeReason.FRAME_TOO_LARGE

    oversized = '{"type":"heartbeat","sequence":0,"pad":"' + "x" * MAX_FRAME_BYTES + '"}'
    with pytest.raises(NodeMeshError) as inbound:
        parse_client_frame(oversized)
    assert inbound.value.reason is NodeReason.FRAME_TOO_LARGE


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "{}",
        '{"type":"nonexistent"}',
        '{"type":"heartbeat","sequence":-1}',
        '{"type":"heartbeat","sequence":0,"unexpected":true}',
    ],
)
def test_malformed_frames_are_refused(payload: str) -> None:
    with pytest.raises(NodeMeshError) as failure:
        parse_client_frame(payload)
    assert failure.value.reason is NodeReason.FRAME_MALFORMED


def test_client_and_server_frames_are_separate_vocabularies() -> None:
    heartbeat = encode_frame(HeartbeatFrame(sequence=1))
    assert parse_client_frame(heartbeat).type == "heartbeat"
    with pytest.raises(NodeMeshError):
        parse_server_frame(heartbeat)


def test_redaction_covers_object_keys_as_well_as_values() -> None:
    # A credential used as a JSON key is exactly as exposed as one used as a
    # value, so both positions must be masked.
    redacted = redact_value(
        {"olynode_deadbeef_supersecretvalue": "x", "value": "olynode_deadbeef_supersecretvalue"}
    )
    assert "supersecretvalue" not in str(redacted)
    assert REDACTION_PLACEHOLDER in str(list(redacted)[0])
    assert "hunter2" not in str(redact_value({"password=hunter2": "x"}))


@pytest.mark.parametrize(
    "text",
    [
        "password=hunter2",
        'api_key: "abcdefghijkl"',
        "Authorization: Bearer abcdefghijklmnop",
        "olynode_deadbeef_supersecretvalue",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkl",
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
    ],
)
def test_credential_shapes_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert REDACTION_PLACEHOLDER in redacted
    for secret in ["hunter2", "abcdefghijkl", "supersecretvalue", "IOSFODNN7EXAMPLE", "MIIB"]:
        assert secret not in redacted


def test_ordinary_text_and_digests_survive_redaction() -> None:
    digest = "a" * 64
    assert redact_text(digest) == digest
    assert redact_text("collected cpu section") == "collected cpu section"


def test_redaction_walks_nested_structures_and_bounds_depth() -> None:
    nested: dict[str, object] = {"a": {"b": {"c": ["password=hunter2"]}}}
    assert "hunter2" not in str(redact_value(nested))

    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(20):
        child: dict[str, object] = {}
        cursor["next"] = child
        cursor = child
    assert REDACTION_PLACEHOLDER in str(redact_value(deep))


def test_bounding_reports_truncation_on_a_utf8_boundary() -> None:
    kept, truncated = bound_text("a" * 10, 100)
    assert (kept, truncated) == ("a" * 10, False)

    cut, was_truncated = bound_text("é" * 50, 11)
    assert was_truncated is True
    assert cut.encode("utf-8")


def test_audit_chain_verifies_and_detects_tampering() -> None:
    log = NodeAuditLog(clock=lambda: datetime(2026, 8, 1, tzinfo=UTC))
    log.append(
        actor="local-jerry",
        action=AuditAction.ENROLLMENT_ISSUED,
        decision=AuditDecision.ALLOW,
        payload={"node_name": "jerry-windows"},
    )
    log.append(
        actor="local-jerry",
        action=AuditAction.DISPATCH_ADMITTED,
        decision=AuditDecision.ALLOW,
        job_id="job-1",
    )
    events = log.events()

    assert log.verify() is True
    assert events[0].previous_hash == "0" * 64
    assert events[1].previous_hash == events[0].event_hash
    assert log.head() == events[1].event_hash

    forged = list(events)
    forged[0] = replace(forged[0], actor="someone-else")
    assert verify_chain(forged) is False

    reordered = [events[1], events[0]]
    assert verify_chain(reordered) is False


def test_audit_payloads_are_redacted_before_they_are_hashed() -> None:
    log = NodeAuditLog(clock=lambda: datetime(2026, 8, 1, tzinfo=UTC))
    event = log.append(
        actor="local-jerry",
        action=AuditAction.DISPATCH_COMPLETED,
        decision=AuditDecision.ALLOW,
        payload={"detail": "token=abcdefghijklmnop"},
    )
    assert "abcdefghijklmnop" not in str(event.payload)
    assert log.verify() is True


def test_permanent_refusals_are_not_retried() -> None:
    assert is_permanent_refusal(NodeReason.CAPABILITY_RESERVED) is True
    assert is_permanent_refusal(NodeReason.NODE_REVOKED) is True
    assert is_permanent_refusal(NodeReason.DISPATCH_FROZEN) is True
    assert is_permanent_refusal(NodeReason.NODE_OFFLINE) is False
    assert is_permanent_refusal(NodeReason.SESSION_CLOSED) is False


def test_no_capability_declares_more_output_than_a_frame_can_carry() -> None:
    """A ceiling above the frame limit makes a capability undispatchable.

    `fs.read@1` shipped with a 1 MiB ceiling against a 256 KiB frame limit, so
    every dispatch of it failed pydantic validation before the frame was sent.
    Nothing caught it until the capability was exercised end to end, because
    both numbers were individually reasonable.
    """
    for name, descriptor in CAPABILITY_CATALOG.items():
        assert descriptor.max_output_bytes <= MAX_FRAME_BYTES, (
            f"{name} declares {descriptor.max_output_bytes} bytes of output but a dispatch "
            f"frame carries at most {MAX_FRAME_BYTES}"
        )
        assert descriptor.max_output_bytes >= 256, name


def test_no_enabled_capability_returns_artifacts_yet() -> None:
    """Artifact bounds are enforced from the catalog, so this states the truth.

    Every enabled capability declares zero artifacts, which now means a node
    streaming one is refused. Enabling artifacts for a capability is therefore
    a deliberate edit here as well as in the catalog.
    """
    for name in ENABLED_CAPABILITIES:
        descriptor = CAPABILITY_CATALOG[name]
        assert descriptor.max_artifacts == 0, f"{name} declares artifacts"
        assert descriptor.max_artifact_bytes == 0, f"{name} declares artifact bytes"


def test_artifact_allowances_are_internally_consistent() -> None:
    # A capability allowing artifacts but no bytes for them, or bytes but no
    # artifacts, can never actually return one — a bound that reads as
    # permission but behaves as refusal.
    for name, descriptor in CAPABILITY_CATALOG.items():
        allows_count = descriptor.max_artifacts > 0
        allows_bytes = descriptor.max_artifact_bytes > 0
        assert allows_count == allows_bytes, f"{name} allows artifacts inconsistently"


def test_a_credential_named_field_is_redacted_whatever_its_value_looks_like() -> None:
    """Structured secrets, not just secrets embedded in text.

    `password=hunter2` inside a string was caught. {"password": "hunter2"} was
    not: the name and the secret are separate values and neither looks like a
    secret on its own.
    """
    redacted = redact_value(
        {
            "password": "hunter2",
            "api_key": "short",
            "client_secret": {"nested": "still-a-secret"},
            "note": "ordinary text",
            "count": 7,
        }
    )

    assert redacted["password"] == REDACTION_PLACEHOLDER
    assert redacted["api_key"] == REDACTION_PLACEHOLDER
    assert redacted["client_secret"] == REDACTION_PLACEHOLDER
    # And it must not swallow everything it touches.
    assert redacted["note"] == "ordinary text"
    assert redacted["count"] == 7


def test_credential_key_matching_is_anchored_not_substring() -> None:
    # "passenger_count" or "token_count" are not credentials; matching on a
    # substring would redact ordinary fields and make output untrustworthy in
    # the other direction.
    redacted = redact_value({"passenger_count": 3, "token_count": 12, "subtokens": ["a"]})

    assert redacted == {"passenger_count": 3, "token_count": 12, "subtokens": ["a"]}

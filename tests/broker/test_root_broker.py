from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from olympus.broker.root import (
    BrokerDenied,
    BrokerRequest,
    FakeHostExecutor,
    SignedBrokerRequest,
    TypedRootBroker,
    literal_command_digest,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def signed(
    key: SigningKey,
    *,
    operation: str = "service.restart",
    parameters: dict[str, object] | None = None,
    nonce: str = "nonce-1",
    expires_at: datetime = NOW + timedelta(minutes=1),
) -> SignedBrokerRequest:
    request = BrokerRequest(
        request_id="request-1",
        nonce=nonce,
        operation=operation,
        parameters=parameters or {"service": "olympus-worker"},
        issued_at=NOW,
        expires_at=expires_at,
    )
    return SignedBrokerRequest(
        request=request, signature=key.sign(request.canonical_bytes()).signature
    )


def broker(key: SigningKey) -> tuple[TypedRootBroker, FakeHostExecutor]:
    executor = FakeHostExecutor()
    return (
        TypedRootBroker(
            verification_key=bytes(key.verify_key),
            orchestrator_uid=1001,
            executor=executor,
            allowed_services=frozenset({"olympus-worker", "olympus-gateway"}),
            literal_approval_verifier=lambda digest: (
                digest == literal_command_digest(("systemctl", "status", "olympus-worker"))
            ),
        ),
        executor,
    )


def test_fixed_typed_operation_executes_once_for_expected_nonroot_peer() -> None:
    key = SigningKey.generate()
    root, executor = broker(key)
    request = signed(key)

    receipt = root.execute(request, peer_uid=1001, now=NOW)

    assert receipt.operation == "service.restart"
    assert executor.calls == [("service.restart", {"service": "olympus-worker"})]
    with pytest.raises(BrokerDenied, match="replay"):
        root.execute(request, peer_uid=1001, now=NOW)


@pytest.mark.parametrize("failure", ["signature", "expiry", "peer", "schema"])
def test_signature_expiry_peer_and_schema_fail_closed(failure: str) -> None:
    key = SigningKey.generate()
    root, executor = broker(key)
    request = signed(key)
    peer_uid = 1001
    now = NOW
    if failure == "signature":
        request = SignedBrokerRequest(request.request, bytes(len(request.signature)))
    elif failure == "expiry":
        now = NOW + timedelta(minutes=2)
    elif failure == "peer":
        peer_uid = 0
    else:
        request = signed(key, parameters={"service": "sshd"})

    with pytest.raises(BrokerDenied):
        root.execute(request, peer_uid=peer_uid, now=now)
    assert executor.calls == []


def test_arbitrary_root_command_requires_exact_literal_command_digest() -> None:
    key = SigningKey.generate()
    root, executor = broker(key)
    argv = ("systemctl", "status", "olympus-worker")
    request = signed(
        key,
        operation="root.command.literal",
        parameters={
            "argv": list(argv),
            "approval_digest": literal_command_digest(argv),
        },
    )
    root.execute(request, peer_uid=1001, now=NOW)
    assert executor.calls[-1][1]["argv"] == list(argv)

    altered = signed(
        key,
        nonce="nonce-2",
        operation="root.command.literal",
        parameters={
            "argv": ["systemctl", "restart", "olympus-worker"],
            "approval_digest": literal_command_digest(argv),
        },
    )
    with pytest.raises(BrokerDenied, match="literal"):
        root.execute(altered, peer_uid=1001, now=NOW)

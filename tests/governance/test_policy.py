import json
from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from olympus.governance.policy import (
    PolicyActivationDenied,
    PolicyBundle,
    PolicyKernel,
    PolicyVerificationError,
    SignedPolicyRelease,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)
REQUIRED_POLICIES = {
    "authorization": {"default": "deny"},
    "trust": {"privileged_sink_max_taint": "operator-trusted"},
    "approval": {"literal_payload_binding": True},
    "budget": {"monthly_variable_usd": 50},
    "root_broker": {"default": "deny"},
}


def release(
    key: SigningKey,
    *,
    sequence: int = 1,
    expires_at: datetime = NOW + timedelta(days=30),
) -> SignedPolicyRelease:
    bundle = PolicyBundle(
        release_id=f"policy-{sequence}",
        sequence=sequence,
        issued_at=NOW,
        expires_at=expires_at,
        policies=REQUIRED_POLICIES,
    )
    payload = bundle.canonical_bytes()
    return SignedPolicyRelease(
        signer_id="offline-policy-root",
        payload=payload,
        signature=key.sign(payload).signature,
    )


def kernel(key: SigningKey) -> PolicyKernel:
    return PolicyKernel(
        verification_keys={"offline-policy-root": bytes(key.verify_key)},
        activation_principal="policy-release-service",
    )


def test_valid_signed_bundle_activates_all_governance_domains() -> None:
    key = SigningKey.generate()
    policy = kernel(key)

    activated = policy.verify_and_activate(
        release(key),
        principal="policy-release-service",
        now=NOW,
    )

    assert activated.sequence == 1
    assert set(activated.policies) == set(REQUIRED_POLICIES)
    assert policy.active_release == activated


@pytest.mark.parametrize("mutation", ["payload", "signature", "signer"])
def test_modified_unsigned_or_unauthorized_release_is_rejected(mutation: str) -> None:
    key = SigningKey.generate()
    signed = release(key)
    if mutation == "payload":
        data = json.loads(signed.payload)
        data["policies"]["budget"]["monthly_variable_usd"] = 5000
        signed = SignedPolicyRelease(
            signer_id=signed.signer_id,
            payload=json.dumps(data, sort_keys=True, separators=(",", ":")).encode(),
            signature=signed.signature,
        )
    elif mutation == "signature":
        signed = SignedPolicyRelease(
            signer_id=signed.signer_id,
            payload=signed.payload,
            signature=bytes(len(signed.signature)),
        )
    else:
        signed = SignedPolicyRelease(
            signer_id="agent-worker",
            payload=signed.payload,
            signature=signed.signature,
        )

    with pytest.raises(PolicyVerificationError):
        kernel(key).verify_and_activate(
            signed,
            principal="policy-release-service",
            now=NOW,
        )


def test_expired_and_rolled_back_releases_are_rejected() -> None:
    key = SigningKey.generate()
    policy = kernel(key)
    policy.verify_and_activate(
        release(key, sequence=2),
        principal="policy-release-service",
        now=NOW,
    )

    with pytest.raises(PolicyVerificationError, match="rollback"):
        policy.verify_and_activate(
            release(key, sequence=1),
            principal="policy-release-service",
            now=NOW,
        )
    with pytest.raises(PolicyVerificationError, match="expired"):
        kernel(key).verify_and_activate(
            release(key),
            principal="policy-release-service",
            now=NOW + timedelta(days=31),
        )


def test_agent_service_principal_cannot_activate_a_release() -> None:
    key = SigningKey.generate()

    with pytest.raises(PolicyActivationDenied):
        kernel(key).verify_and_activate(
            release(key),
            principal="olympus-agent-worker",
            now=NOW,
        )

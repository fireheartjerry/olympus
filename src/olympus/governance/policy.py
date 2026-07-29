import json
from dataclasses import asdict, dataclass
from datetime import datetime

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

REQUIRED_POLICY_DOMAINS = frozenset({"authorization", "trust", "approval", "budget", "root_broker"})


class PolicyVerificationError(ValueError):
    """The candidate policy release is not authentic or admissible."""


class PolicyActivationDenied(PermissionError):
    """The caller is not the isolated policy release service."""


@dataclass(frozen=True)
class PolicyBundle:
    release_id: str
    sequence: int
    issued_at: datetime
    expires_at: datetime
    policies: dict[str, dict[str, object]]

    def __post_init__(self) -> None:
        if not self.release_id.strip():
            raise ValueError("release_id must not be empty")
        if self.sequence < 1:
            raise ValueError("policy sequence must be positive")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("policy release must expire after issuance")
        if set(self.policies) != REQUIRED_POLICY_DOMAINS:
            raise ValueError("policy release must contain every governance domain exactly once")

    def canonical_bytes(self) -> bytes:
        value = asdict(self)
        value["issued_at"] = self.issued_at.isoformat()
        value["expires_at"] = self.expires_at.isoformat()
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> "PolicyBundle":
        try:
            value = json.loads(payload)
            if not isinstance(value, dict) or not isinstance(value.get("policies"), dict):
                raise TypeError
            policies = value["policies"]
            if any(not isinstance(item, dict) for item in policies.values()):
                raise TypeError
            bundle = cls(
                release_id=str(value["release_id"]),
                sequence=int(value["sequence"]),
                issued_at=datetime.fromisoformat(str(value["issued_at"])),
                expires_at=datetime.fromisoformat(str(value["expires_at"])),
                policies=policies,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicyVerificationError("policy payload is invalid") from exc
        if bundle.canonical_bytes() != payload:
            raise PolicyVerificationError("policy payload is not canonical")
        return bundle


@dataclass(frozen=True)
class SignedPolicyRelease:
    signer_id: str
    payload: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not self.signer_id.strip() or not self.payload or not self.signature:
            raise ValueError("signed release fields must not be empty")


class PolicyKernel:
    def __init__(
        self,
        *,
        verification_keys: dict[str, bytes],
        activation_principal: str,
    ) -> None:
        if not verification_keys or not activation_principal.strip():
            raise ValueError("policy trust root and activation principal are required")
        self._verification_keys = dict(verification_keys)
        self._activation_principal = activation_principal
        self._active: PolicyBundle | None = None

    @property
    def active_release(self) -> PolicyBundle | None:
        return self._active

    def verify_and_activate(
        self,
        release: SignedPolicyRelease,
        *,
        principal: str,
        now: datetime,
    ) -> PolicyBundle:
        if principal != self._activation_principal:
            raise PolicyActivationDenied("principal cannot activate policy releases")
        _require_aware(now, "now")
        verification_key = self._verification_keys.get(release.signer_id)
        if verification_key is None:
            raise PolicyVerificationError("policy signer is not authorized")
        try:
            VerifyKey(verification_key).verify(release.payload, release.signature)
        except (ValueError, BadSignatureError) as exc:
            raise PolicyVerificationError("policy signature is invalid") from exc
        bundle = PolicyBundle.from_canonical_bytes(release.payload)
        if now < bundle.issued_at:
            raise PolicyVerificationError("policy release is not active yet")
        if now >= bundle.expires_at:
            raise PolicyVerificationError("policy release expired")
        if self._active is not None and bundle.sequence <= self._active.sequence:
            raise PolicyVerificationError("policy rollback or duplicate release denied")
        self._active = bundle
        return bundle


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

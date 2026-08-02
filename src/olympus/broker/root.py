import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


class BrokerDenied(PermissionError):
    pass


@dataclass(frozen=True)
class BrokerRequest:
    request_id: str
    nonce: str
    operation: str
    parameters: dict[str, object]
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if any(not value.strip() for value in (self.request_id, self.nonce, self.operation)):
            raise ValueError("broker request identity, nonce, and operation are required")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("broker request must expire after issuance")
        if self.expires_at - self.issued_at > timedelta(minutes=5):
            raise ValueError("broker request lifetime cannot exceed five minutes")

    def canonical_bytes(self) -> bytes:
        value = asdict(self)
        value["issued_at"] = self.issued_at.isoformat()
        value["expires_at"] = self.expires_at.isoformat()
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SignedBrokerRequest:
    request: BrokerRequest
    signature: bytes

    def __post_init__(self) -> None:
        if not self.signature:
            raise ValueError("broker request signature is required")


@dataclass(frozen=True)
class BrokerReceipt:
    request_id: str
    operation: str
    request_digest: str


class HostExecutor(Protocol):
    def execute(self, operation: str, parameters: dict[str, object]) -> None: ...


class FakeHostExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, operation: str, parameters: dict[str, object]) -> None:
        self.calls.append((operation, dict(parameters)))


class TypedRootBroker:
    def __init__(
        self,
        *,
        verification_key: bytes,
        orchestrator_uid: int,
        executor: HostExecutor,
        allowed_services: frozenset[str],
        literal_approval_verifier: Callable[[str], bool] = lambda _: False,
    ) -> None:
        if orchestrator_uid <= 0:
            raise ValueError("orchestrator must have a dedicated non-root uid")
        if not allowed_services:
            raise ValueError("at least one typed service target is required")
        self._verification_key = VerifyKey(verification_key)
        self._orchestrator_uid = orchestrator_uid
        self._executor = executor
        self._allowed_services = allowed_services
        self._literal_approval_verifier = literal_approval_verifier
        self._used_nonces: set[str] = set()

    def execute(
        self,
        signed: SignedBrokerRequest,
        *,
        peer_uid: int,
        now: datetime,
    ) -> BrokerReceipt:
        request = signed.request
        _require_aware(now, "now")
        if peer_uid != self._orchestrator_uid:
            raise BrokerDenied("peer is outside the host socket privilege boundary")
        if now < request.issued_at or now >= request.expires_at:
            raise BrokerDenied("broker request expired or is not active")
        if request.nonce in self._used_nonces:
            raise BrokerDenied("broker nonce replay denied")
        try:
            self._verification_key.verify(request.canonical_bytes(), signed.signature)
        except (ValueError, BadSignatureError) as exc:
            raise BrokerDenied("broker signature is invalid") from exc
        self._validate_operation(request.operation, request.parameters)
        self._used_nonces.add(request.nonce)
        self._executor.execute(request.operation, dict(request.parameters))
        return BrokerReceipt(
            request_id=request.request_id,
            operation=request.operation,
            request_digest=hashlib.sha256(request.canonical_bytes()).hexdigest(),
        )

    def _validate_operation(self, operation: str, parameters: dict[str, object]) -> None:
        if operation == "service.restart":
            if (
                set(parameters) != {"service"}
                or parameters["service"] not in self._allowed_services
            ):
                raise BrokerDenied("service operation schema or target is denied")
            return
        if operation == "root.command.literal":
            self._validate_literal_command(parameters)
            return
        raise BrokerDenied("root operation is not in the fixed registry")

    def _validate_literal_command(self, parameters: dict[str, object]) -> None:
        if set(parameters) != {"argv", "approval_digest"}:
            raise BrokerDenied("literal root command schema is invalid")
        argv = parameters["argv"]
        approval_digest = parameters["approval_digest"]
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 64
            or any(not isinstance(value, str) or not value or "\x00" in value for value in argv)
            or not isinstance(approval_digest, str)
        ):
            raise BrokerDenied("literal root command arguments are invalid")
        expected = literal_command_digest(tuple(argv))
        if approval_digest != expected or not self._literal_approval_verifier(expected):
            raise BrokerDenied("Face ID approval does not match the literal root command")


def literal_command_digest(argv: tuple[str, ...]) -> str:
    if not argv or any(not value or "\x00" in value for value in argv):
        raise ValueError("literal command argv must contain safe non-empty strings")
    return hashlib.sha256(json.dumps(list(argv), separators=(",", ":")).encode()).hexdigest()


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum


class AuthorizationDenied(PermissionError):
    pass


class TrustLabel(StrEnum):
    OPERATOR = "operator-trusted"
    VERIFIED_EXTERNAL = "verified-external"
    EXTERNAL_UNTRUSTED = "external-untrusted"
    MODEL_DERIVED = "model-derived"


class ActionClass(StrEnum):
    AUTONOMOUS = "autonomous"
    PROTECTED = "protected"
    NEVER_AUTONOMOUS = "never-autonomous"


@dataclass(frozen=True)
class TaintedValue:
    value: object
    labels: frozenset[TrustLabel]

    @classmethod
    def derive(
        cls,
        value: object,
        *sources: "TaintedValue",
        model_derived: bool = False,
    ) -> "TaintedValue":
        labels = frozenset(label for source in sources for label in source.labels)
        if model_derived:
            labels |= frozenset({TrustLabel.MODEL_DERIVED})
        return cls(value=value, labels=labels)


@dataclass(frozen=True)
class Action:
    action_id: str
    kind: str
    classification: ActionClass
    payload: dict[str, object]
    variable_cost_usd: Decimal
    inputs: tuple[TaintedValue, ...]

    def __post_init__(self) -> None:
        if not self.action_id.strip() or not self.kind.strip():
            raise ValueError("action identity and kind are required")
        if self.variable_cost_usd < 0:
            raise ValueError("variable action cost cannot be negative")

    def digest(self) -> str:
        canonical = {
            "action_id": self.action_id,
            "classification": self.classification.value,
            "inputs": [
                {
                    "labels": sorted(label.value for label in item.labels),
                    "value": item.value,
                }
                for item in self.inputs
            ],
            "kind": self.kind,
            "payload": self.payload,
            "variable_cost_usd": str(self.variable_cost_usd),
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True)
class Approval:
    approval_id: str
    action_digest: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.approval_id.strip() or len(self.action_digest) != 64:
            raise ValueError("approval identity and SHA-256 action digest are required")
        _bounded_interval(self.issued_at, self.expires_at, "approval")


@dataclass(frozen=True)
class ScheduleCapability:
    capability_id: str
    action_kinds: frozenset[str]
    scope: dict[str, object]
    issued_at: datetime
    expires_at: datetime
    max_runs: int

    def __post_init__(self) -> None:
        if not self.capability_id.strip() or not self.action_kinds or not self.scope:
            raise ValueError("schedule identity, action kinds, and scope are required")
        if self.max_runs < 1:
            raise ValueError("schedule max_runs must be positive")
        _bounded_interval(self.issued_at, self.expires_at, "schedule")


@dataclass(frozen=True)
class AuthorizationDecision:
    action_id: str
    action_digest: str
    allowed: bool
    reason: str


@dataclass(frozen=True)
class AuthorizationAuditEvent:
    sequence: int
    decision: AuthorizationDecision
    previous_hash: str
    event_hash: str


class AuthorizationAudit:
    def __init__(self) -> None:
        self._events: list[AuthorizationAuditEvent] = []

    @property
    def events(self) -> tuple[AuthorizationAuditEvent, ...]:
        return tuple(self._events)

    def append(self, decision: AuthorizationDecision) -> None:
        sequence = len(self._events) + 1
        previous_hash = self._events[-1].event_hash if self._events else "0" * 64
        event_hash = _audit_hash(sequence, decision, previous_hash)
        self._events.append(
            AuthorizationAuditEvent(
                sequence=sequence,
                decision=decision,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
        )

    def verify(self) -> bool:
        previous_hash = "0" * 64
        for sequence, event in enumerate(self._events, start=1):
            if event.sequence != sequence or event.previous_hash != previous_hash:
                return False
            if event.event_hash != _audit_hash(sequence, event.decision, previous_hash):
                return False
            previous_hash = event.event_hash
        return True


class BudgetGovernor:
    def __init__(self, *, monthly_ceiling_usd: Decimal) -> None:
        if monthly_ceiling_usd <= 0:
            raise ValueError("monthly spending ceiling must be positive")
        self._ceiling = monthly_ceiling_usd
        self._spent = Decimal(0)

    @property
    def spent_usd(self) -> Decimal:
        return self._spent

    def reserve(self, amount: Decimal) -> None:
        if amount < 0:
            raise ValueError("budget reservation cannot be negative")
        if self._spent + amount > self._ceiling:
            raise AuthorizationDenied("hard monthly spending ceiling would be exceeded")
        self._spent += amount


class AuthorizationEngine:
    def __init__(self, budget: BudgetGovernor) -> None:
        self.budget = budget
        self.audit = AuthorizationAudit()
        self._consumed_approvals: set[str] = set()
        self._schedule_runs: dict[str, int] = {}

    def authorize(
        self,
        action: Action,
        *,
        now: datetime,
        approval: Approval | None = None,
        schedule: ScheduleCapability | None = None,
    ) -> AuthorizationDecision:
        _require_aware(now, "now")
        digest = action.digest()
        try:
            self._validate_taint(action)
            if schedule is not None:
                self._validate_schedule(action, schedule, now)
            if action.classification is not ActionClass.AUTONOMOUS:
                self._validate_approval(digest, approval, now)
            self.budget.reserve(action.variable_cost_usd)
            if approval is not None and action.classification is not ActionClass.AUTONOMOUS:
                self._consumed_approvals.add(approval.approval_id)
            if schedule is not None:
                self._schedule_runs[schedule.capability_id] = (
                    self._schedule_runs.get(schedule.capability_id, 0) + 1
                )
        except AuthorizationDenied as exc:
            self.audit.append(AuthorizationDecision(action.action_id, digest, False, str(exc)))
            raise
        decision = AuthorizationDecision(action.action_id, digest, True, "authorized")
        self.audit.append(decision)
        return decision

    def _validate_taint(self, action: Action) -> None:
        forbidden = {TrustLabel.EXTERNAL_UNTRUSTED, TrustLabel.MODEL_DERIVED}
        labels = {label for item in action.inputs for label in item.labels}
        if action.classification is not ActionClass.AUTONOMOUS and labels & forbidden:
            raise AuthorizationDenied("tainted input cannot control a privileged sink")

    def _validate_approval(
        self,
        action_digest: str,
        approval: Approval | None,
        now: datetime,
    ) -> None:
        if approval is None:
            raise AuthorizationDenied("literal action approval is required")
        if approval.approval_id in self._consumed_approvals:
            raise AuthorizationDenied("approval was already consumed")
        if now < approval.issued_at or now >= approval.expires_at:
            raise AuthorizationDenied("approval is not currently valid")
        if approval.action_digest != action_digest:
            raise AuthorizationDenied("approval does not match the literal action")

    def _validate_schedule(
        self,
        action: Action,
        schedule: ScheduleCapability,
        now: datetime,
    ) -> None:
        if now < schedule.issued_at or now >= schedule.expires_at:
            raise AuthorizationDenied("schedule is not currently valid")
        if action.kind not in schedule.action_kinds:
            raise AuthorizationDenied("action kind escapes schedule scope")
        if any(action.payload.get(key) != value for key, value in schedule.scope.items()):
            raise AuthorizationDenied("action payload escapes schedule scope")
        if self._schedule_runs.get(schedule.capability_id, 0) >= schedule.max_runs:
            raise AuthorizationDenied("schedule run limit was reached")


def _audit_hash(
    sequence: int,
    decision: AuthorizationDecision,
    previous_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "decision": asdict(decision),
            "previous_hash": previous_hash,
            "sequence": sequence,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _bounded_interval(issued_at: datetime, expires_at: datetime, name: str) -> None:
    _require_aware(issued_at, f"{name}.issued_at")
    _require_aware(expires_at, f"{name}.expires_at")
    if expires_at <= issued_at:
        raise ValueError(f"{name} must expire after issuance")


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

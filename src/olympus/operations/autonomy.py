from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from olympus.governance.authorization import (
    Action,
    AuthorizationDecision,
    AuthorizationEngine,
    ScheduleCapability,
)


class AutonomyDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ActivationProof:
    authority_epoch: int
    issued_at: datetime
    expires_at: datetime
    proof_digest: str

    def __post_init__(self) -> None:
        if self.authority_epoch < 1 or not self.proof_digest.strip():
            raise ValueError("activation epoch and proof digest are required")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("activation must expire after issuance")
        if self.expires_at - self.issued_at > timedelta(days=30):
            raise ValueError("high-autonomy activation cannot exceed 30 days")


@dataclass(frozen=True)
class Followup:
    followup_id: str
    run_at: datetime


class HighAutonomyController:
    def __init__(
        self,
        *,
        authorization: AuthorizationEngine,
        activation_verifier: Callable[[ActivationProof], bool],
        maximum_followups: int,
        maximum_followup_horizon: timedelta,
    ) -> None:
        if maximum_followups < 1 or maximum_followup_horizon <= timedelta(0):
            raise ValueError("followup limits must be positive")
        self._authorization = authorization
        self._activation_verifier = activation_verifier
        self._maximum_followups = maximum_followups
        self._maximum_followup_horizon = maximum_followup_horizon
        self._activation: ActivationProof | None = None
        self._followups: dict[str, Followup] = {}
        self._anomalies: list[str] = []

    def activate(self, proof: ActivationProof, *, now: datetime) -> None:
        _require_aware(now, "now")
        if now < proof.issued_at or now >= proof.expires_at:
            raise AutonomyDenied("activation proof is not currently valid")
        if not self._activation_verifier(proof):
            raise AutonomyDenied("activation proof did not verify")
        if (
            self._activation is not None
            and proof.authority_epoch <= self._activation.authority_epoch
        ):
            raise AutonomyDenied("activation epoch must advance")
        self._activation = proof
        self._anomalies.clear()

    def record_anomaly(self, reason: str) -> None:
        if not reason.strip():
            raise ValueError("anomaly reason is required")
        self._anomalies.append(reason)
        self._activation = None

    def run(
        self,
        action: Action,
        *,
        schedule: ScheduleCapability,
        now: datetime,
    ) -> AuthorizationDecision:
        self._require_active(now)
        return self._authorization.authorize(action, schedule=schedule, now=now)

    def schedule_followup(
        self,
        followup_id: str,
        run_at: datetime,
        *,
        now: datetime,
    ) -> Followup:
        self._require_active(now)
        _require_aware(run_at, "run_at")
        if not followup_id.strip() or followup_id in self._followups:
            raise AutonomyDenied("followup identity is empty or duplicated")
        if run_at <= now or run_at - now > self._maximum_followup_horizon:
            raise AutonomyDenied("followup escapes the allowed horizon")
        if len(self._followups) >= self._maximum_followups:
            raise AutonomyDenied("self-scheduled followup limit reached")
        followup = Followup(followup_id, run_at)
        self._followups[followup_id] = followup
        return followup

    def _require_active(self, now: datetime) -> ActivationProof:
        _require_aware(now, "now")
        if (
            self._activation is None
            or self._anomalies
            or now < self._activation.issued_at
            or now >= self._activation.expires_at
        ):
            raise AutonomyDenied("high autonomy is not active")
        return self._activation


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

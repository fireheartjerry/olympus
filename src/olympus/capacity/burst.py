from dataclasses import dataclass
from datetime import timedelta
from decimal import ROUND_CEILING, Decimal
from typing import Protocol


class BurstDenied(PermissionError):
    pass


@dataclass(frozen=True)
class CapacityPressure:
    cpu_percent: int
    memory_percent: int
    observed_minutes: int

    def __post_init__(self) -> None:
        if (
            self.cpu_percent < 0
            or self.cpu_percent > 100
            or self.memory_percent < 0
            or self.memory_percent > 100
            or self.observed_minutes < 0
        ):
            raise ValueError("capacity pressure evidence is invalid")

    def activation_threshold_met(self) -> bool:
        return self.observed_minutes >= 10 and (self.cpu_percent >= 80 or self.memory_percent >= 75)


@dataclass(frozen=True)
class BurstRequest:
    request_id: str
    worker_count: int
    duration: timedelta
    provider_hourly_usd: Decimal
    job_spend_limit_usd: Decimal
    monthly_spent_usd: Decimal
    monthly_ceiling_usd: Decimal
    pressure: CapacityPressure

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("burst request identity is required")
        if self.worker_count < 1 or self.worker_count > 32:
            raise ValueError("burst worker count must be between one and 32")
        if self.duration <= timedelta(0) or self.duration > timedelta(hours=24):
            raise ValueError("burst duration must be positive and at most 24 hours")
        costs = (
            self.provider_hourly_usd,
            self.job_spend_limit_usd,
            self.monthly_spent_usd,
            self.monthly_ceiling_usd,
        )
        if any(cost < 0 for cost in costs) or self.provider_hourly_usd == 0:
            raise ValueError("burst costs must be non-negative with a positive hourly rate")

    def forecast_usd(self) -> Decimal:
        hours = (Decimal(str(self.duration.total_seconds())) / Decimal(3600)).to_integral_value(
            rounding=ROUND_CEILING
        )
        return self.provider_hourly_usd * self.worker_count * hours


@dataclass(frozen=True)
class BurstResult:
    request_id: str
    forecast_usd: Decimal
    deleted_instances: int


class BurstProvider(Protocol):
    def provision(self, request_id: str, worker_count: int) -> tuple[str, ...]: ...

    def join_private(self, instance_id: str) -> None: ...

    def drain(self, instance_id: str) -> None: ...

    def delete(self, instance_id: str) -> None: ...

    def list_managed(self) -> tuple[str, ...]: ...


class BurstManager:
    def __init__(self, provider: BurstProvider) -> None:
        self._provider = provider
        self._active: set[str] = set()
        self._accrued_usd = Decimal(0)

    def run(self, request: BurstRequest) -> BurstResult:
        if not request.pressure.activation_threshold_met():
            raise BurstDenied("elastic burst activation threshold is not evidenced")
        forecast = request.forecast_usd()
        if forecast > request.job_spend_limit_usd:
            raise BurstDenied("burst exceeds the job spending limit")
        if request.monthly_spent_usd + self._accrued_usd + forecast > request.monthly_ceiling_usd:
            raise BurstDenied("burst exceeds the monthly spending ceiling")
        self._accrued_usd += forecast
        instances: tuple[str, ...] = ()
        joined: list[str] = []
        deleted = 0
        try:
            instances = self._provider.provision(request.request_id, request.worker_count)
            if len(instances) != request.worker_count or len(set(instances)) != len(instances):
                raise RuntimeError("provider returned an invalid instance set")
            self._active.update(instances)
            for instance_id in instances:
                self._provider.join_private(instance_id)
                joined.append(instance_id)
            for instance_id in reversed(joined):
                self._provider.drain(instance_id)
        finally:
            for instance_id in reversed(instances):
                self._provider.delete(instance_id)
                self._active.discard(instance_id)
                deleted += 1
        return BurstResult(request.request_id, forecast, deleted)

    def reconcile_orphans(self) -> int:
        orphans = [
            instance_id
            for instance_id in self._provider.list_managed()
            if instance_id not in self._active
        ]
        for instance_id in orphans:
            self._provider.delete(instance_id)
        return len(orphans)


class FakeBurstProvider:
    def __init__(self, *, fail_during_join: bool = False) -> None:
        self.instances: dict[str, str] = {}
        self.joined_private_count = 0
        self.drained_count = 0
        self._fail_during_join = fail_during_join

    def provision(self, request_id: str, worker_count: int) -> tuple[str, ...]:
        identifiers = tuple(f"{request_id}-worker-{index}" for index in range(worker_count))
        for instance_id in identifiers:
            self.instances[instance_id] = "provisioned"
        return identifiers

    def join_private(self, instance_id: str) -> None:
        if self._fail_during_join:
            raise RuntimeError("private cluster join failed")
        self.instances[instance_id] = "joined-private"
        self.joined_private_count += 1

    def drain(self, instance_id: str) -> None:
        self.instances[instance_id] = "drained"
        self.drained_count += 1

    def delete(self, instance_id: str) -> None:
        self.instances.pop(instance_id, None)

    def list_managed(self) -> tuple[str, ...]:
        return tuple(self.instances)

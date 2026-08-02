from datetime import timedelta
from decimal import Decimal

import pytest

from olympus.capacity.burst import (
    BurstDenied,
    BurstManager,
    BurstRequest,
    CapacityPressure,
    FakeBurstProvider,
)


def request(**overrides: object) -> BurstRequest:
    values: dict[str, object] = {
        "request_id": "burst-1",
        "worker_count": 3,
        "duration": timedelta(minutes=45),
        "provider_hourly_usd": Decimal("0.50"),
        "job_spend_limit_usd": Decimal("8"),
        "monthly_spent_usd": Decimal("10"),
        "monthly_ceiling_usd": Decimal("50"),
        "pressure": CapacityPressure(85, 80, 15),
    }
    values.update(overrides)
    return BurstRequest(**values)  # type: ignore[arg-type]


def test_forecast_provision_private_join_drain_delete_and_reconcile() -> None:
    provider = FakeBurstProvider()
    manager = BurstManager(provider)

    result = manager.run(request())

    assert result.forecast_usd == Decimal("1.50")
    assert result.deleted_instances == 3
    assert provider.instances == {}
    assert provider.joined_private_count == 3
    assert provider.drained_count == 3


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"pressure": CapacityPressure(20, 20, 2)}, "activation threshold"),
        ({"job_spend_limit_usd": Decimal("1")}, "job spending"),
        ({"monthly_spent_usd": Decimal("49")}, "monthly spending"),
    ],
)
def test_activation_and_spending_limits_fail_before_provision(
    overrides: dict[str, object],
    message: str,
) -> None:
    provider = FakeBurstProvider()
    with pytest.raises(BurstDenied, match=message):
        BurstManager(provider).run(request(**overrides))
    assert provider.instances == {}


def test_twenty_burst_drills_leave_zero_orphans() -> None:
    provider = FakeBurstProvider()
    manager = BurstManager(provider)

    for index in range(20):
        manager.run(request(request_id=f"burst-{index}"))

    assert provider.instances == {}
    assert manager.reconcile_orphans() == 0


def test_provider_failure_still_deletes_every_provisioned_instance() -> None:
    provider = FakeBurstProvider(fail_during_join=True)

    with pytest.raises(RuntimeError, match="join"):
        BurstManager(provider).run(request())

    assert provider.instances == {}

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from olympus.capacity.models import CapacityPlan, load_capacity_plan

CAPACITY_FILE = Path("config/capacity/vps4.yaml")


def approved_plan_data() -> dict[str, object]:
    return load_capacity_plan(CAPACITY_FILE).model_dump(mode="json")


def test_vps4_plan_matches_approved_aggregate_limits() -> None:
    plan = load_capacity_plan(CAPACITY_FILE)

    assert plan.node.cpu_millicores == 8000
    assert plan.node.memory_mib == 24576
    assert plan.reserved.cpu_millicores == 1000
    assert plan.reserved.memory_mib == 2048
    assert plan.allocatable.cpu_millicores == 7000
    assert plan.allocatable.memory_mib == 22528
    assert plan.always_on_cpu_request == 3000
    assert plan.always_on_memory_request == 8960
    assert plan.always_on_memory_limit == 11688
    assert plan.worker_quota.cpu_request_millicores == 3500
    assert plan.worker_quota.memory_request_mib == 8704
    assert plan.worker_quota.memory_limit_mib == 10752
    assert plan.unrequested_cpu_millicores == 500
    assert plan.unrequested_memory_mib == 4864


def test_vps4_plan_preserves_exact_approved_workload_ledger() -> None:
    plan = load_capacity_plan(CAPACITY_FILE)
    expected = {
        "postgres": (750, 2000, 3072, 4096),
        "temporal-frontend": (100, 400, 256, 320),
        "temporal-history": (150, 500, 384, 512),
        "temporal-matching": (75, 300, 192, 224),
        "temporal-internal-worker": (75, 300, 192, 224),
        "redis": (100, 500, 256, 400),
        "minio": (200, 1000, 512, 768),
        "discord-gateway": (100, 300, 128, 192),
        "supervisor": (300, 1000, 768, 896),
        "temporal-app-worker": (150, 500, 256, 288),
        "policy": (50, 200, 96, 160),
        "budget": (50, 150, 80, 144),
        "audit": (50, 150, 80, 144),
        "approval": (50, 200, 128, 160),
        "prometheus": (250, 750, 768, 896),
        "loki": (150, 500, 512, 640),
        "tempo": (100, 300, 384, 448),
        "grafana": (50, 200, 128, 256),
        "otel-collector": (100, 250, 256, 320),
        "ingress": (50, 250, 128, 160),
        "secrets-broker": (50, 250, 128, 160),
        "backup-controller": (50, 250, 256, 280),
    }
    actual = {
        workload.name: (
            workload.cpu_request_millicores,
            workload.cpu_limit_millicores,
            workload.memory_request_mib,
            workload.memory_limit_mib,
        )
        for workload in plan.always_on
    }

    assert actual == expected


def test_capacity_models_are_frozen() -> None:
    plan = load_capacity_plan(CAPACITY_FILE)

    with pytest.raises(ValidationError, match="Instance is frozen"):
        plan.node.memory_mib = 1


def test_always_on_collection_is_immutable() -> None:
    plan = load_capacity_plan(CAPACITY_FILE)

    with pytest.raises(AttributeError):
        plan.always_on.append(plan.always_on[0])


@pytest.mark.parametrize(
    "yaml_text",
    [
        "schema_version: 1\nschema_version: 1\n",
        "node:\n  cpu_millicores: 8000\n  cpu_millicores: 7000\n",
    ],
)
def test_capacity_file_rejects_duplicate_mapping_keys(
    tmp_path: Path,
    yaml_text: str,
) -> None:
    capacity_file = tmp_path / "capacity.yaml"
    capacity_file.write_text(yaml_text, encoding="utf-8")

    with pytest.raises(yaml.YAMLError, match="duplicate mapping key"):
        load_capacity_plan(capacity_file)


def test_capacity_loader_remains_safe(tmp_path: Path) -> None:
    capacity_file = tmp_path / "capacity.yaml"
    capacity_file.write_text(
        "schema_version: !!python/object/apply:os.system ['echo unsafe']\n",
        encoding="utf-8",
    )

    with pytest.raises(yaml.YAMLError, match="could not determine a constructor"):
        load_capacity_plan(capacity_file)


def test_capacity_rejects_memory_limit_overcommit() -> None:
    raw = approved_plan_data()
    worker_quota = raw["worker_quota"]
    assert isinstance(worker_quota, dict)
    worker_quota["memory_limit_mib"] = 12000

    with pytest.raises(ValidationError, match="memory limits exceed"):
        CapacityPlan.model_validate(raw)


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("node", "cpu_millicores"),
        ("reserved", "memory_mib"),
        ("worker_quota", "memory_request_mib"),
        ("required_headroom", "cpu_millicores"),
    ],
)
def test_capacity_rejects_non_positive_resource_values(section: str, field: str) -> None:
    raw = approved_plan_data()
    values = raw[section]
    assert isinstance(values, dict)
    values[field] = 0

    with pytest.raises(ValidationError, match="greater than 0"):
        CapacityPlan.model_validate(raw)


def test_capacity_rejects_non_positive_workload_resources() -> None:
    raw = approved_plan_data()
    always_on = raw["always_on"]
    assert isinstance(always_on, list)
    workload = always_on[0]
    assert isinstance(workload, dict)
    workload["cpu_limit_millicores"] = 0

    with pytest.raises(ValidationError, match="greater than 0"):
        CapacityPlan.model_validate(raw)


def test_capacity_rejects_duplicate_workload_names() -> None:
    raw = approved_plan_data()
    always_on = raw["always_on"]
    assert isinstance(always_on, list)
    first = always_on[0]
    second = always_on[1]
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    second["name"] = first["name"]

    with pytest.raises(ValidationError, match="workload names must be unique"):
        CapacityPlan.model_validate(raw)


@pytest.mark.parametrize(
    ("request_field", "limit_field"),
    [
        ("cpu_request_millicores", "cpu_limit_millicores"),
        ("memory_request_mib", "memory_limit_mib"),
    ],
)
def test_capacity_rejects_workload_request_above_limit(
    request_field: str,
    limit_field: str,
) -> None:
    raw = approved_plan_data()
    always_on = raw["always_on"]
    assert isinstance(always_on, list)
    workload = always_on[0]
    assert isinstance(workload, dict)
    workload[request_field] = int(workload[limit_field]) + 1

    with pytest.raises(ValidationError, match="workload request exceeds limit"):
        CapacityPlan.model_validate(raw)


def test_capacity_rejects_worker_memory_request_above_limit() -> None:
    raw = approved_plan_data()
    worker_quota = raw["worker_quota"]
    assert isinstance(worker_quota, dict)
    worker_quota["memory_request_mib"] = int(worker_quota["memory_limit_mib"]) + 1

    with pytest.raises(ValidationError, match="worker memory request exceeds limit"):
        CapacityPlan.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cpu_request_millicores", 3501, "CPU requests consume required headroom"),
        ("memory_request_mib", 8705, "memory requests consume required headroom"),
    ],
)
def test_capacity_rejects_requests_that_consume_required_headroom(
    field: str,
    value: int,
    message: str,
) -> None:
    raw = approved_plan_data()
    worker_quota = raw["worker_quota"]
    assert isinstance(worker_quota, dict)
    worker_quota[field] = value

    with pytest.raises(ValidationError, match=message):
        CapacityPlan.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cpu_millicores", 6999, "allocatable CPU does not match"),
        ("memory_mib", 22527, "allocatable memory does not match"),
    ],
)
def test_capacity_rejects_incoherent_allocatable_totals(
    field: str,
    value: int,
    message: str,
) -> None:
    raw = approved_plan_data()
    allocatable = raw["allocatable"]
    assert isinstance(allocatable, dict)
    allocatable[field] = value

    with pytest.raises(ValidationError, match=message):
        CapacityPlan.model_validate(raw)

from collections.abc import Hashable
from pathlib import Path
from typing import Annotated, Any, Literal, Self

import yaml  # type: ignore[import-untyped]
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

PositiveResource = Annotated[int, Field(gt=0)]
WorkloadName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ResourceTotal(StrictModel):
    cpu_millicores: PositiveResource
    memory_mib: PositiveResource


class WorkloadResources(StrictModel):
    name: WorkloadName
    cpu_request_millicores: PositiveResource
    cpu_limit_millicores: PositiveResource
    memory_request_mib: PositiveResource
    memory_limit_mib: PositiveResource

    @model_validator(mode="after")
    def validate_request_limits(self) -> Self:
        if self.cpu_request_millicores > self.cpu_limit_millicores:
            raise ValueError("workload request exceeds limit for CPU")
        if self.memory_request_mib > self.memory_limit_mib:
            raise ValueError("workload request exceeds limit for memory")
        return self


class WorkerQuota(StrictModel):
    cpu_request_millicores: PositiveResource
    memory_request_mib: PositiveResource
    memory_limit_mib: PositiveResource

    @model_validator(mode="after")
    def validate_memory_request_limit(self) -> Self:
        if self.memory_request_mib > self.memory_limit_mib:
            raise ValueError("worker memory request exceeds limit")
        return self


class CapacityPlan(StrictModel):
    schema_version: Literal[1]
    node: ResourceTotal
    reserved: ResourceTotal
    allocatable: ResourceTotal
    always_on: tuple[WorkloadResources, ...]
    worker_quota: WorkerQuota
    required_headroom: ResourceTotal

    @field_validator("always_on", mode="before")
    @classmethod
    def freeze_workload_collection(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @property
    def always_on_cpu_request(self) -> int:
        return sum(item.cpu_request_millicores for item in self.always_on)

    @property
    def always_on_memory_request(self) -> int:
        return sum(item.memory_request_mib for item in self.always_on)

    @property
    def always_on_memory_limit(self) -> int:
        return sum(item.memory_limit_mib for item in self.always_on)

    @property
    def unrequested_cpu_millicores(self) -> int:
        return (
            self.allocatable.cpu_millicores
            - self.always_on_cpu_request
            - self.worker_quota.cpu_request_millicores
        )

    @property
    def unrequested_memory_mib(self) -> int:
        return (
            self.allocatable.memory_mib
            - self.always_on_memory_request
            - self.worker_quota.memory_request_mib
        )

    @model_validator(mode="after")
    def validate_envelope(self) -> Self:
        workload_names = [item.name for item in self.always_on]
        if len(workload_names) != len(set(workload_names)):
            raise ValueError("workload names must be unique")
        if (
            self.node.cpu_millicores - self.reserved.cpu_millicores
            != self.allocatable.cpu_millicores
        ):
            raise ValueError("allocatable CPU does not match node minus reserved")
        if self.node.memory_mib - self.reserved.memory_mib != self.allocatable.memory_mib:
            raise ValueError("allocatable memory does not match node minus reserved")
        if (
            self.always_on_cpu_request + self.worker_quota.cpu_request_millicores
            > self.allocatable.cpu_millicores
        ):
            raise ValueError("CPU requests exceed allocatable capacity")
        if self.unrequested_cpu_millicores < self.required_headroom.cpu_millicores:
            raise ValueError("CPU requests consume required headroom")
        if self.unrequested_memory_mib < self.required_headroom.memory_mib:
            raise ValueError("memory requests consume required headroom")
        if (
            self.always_on_memory_limit + self.worker_quota.memory_limit_mib
            > self.allocatable.memory_mib
        ):
            raise ValueError("memory limits exceed allocatable capacity")
        return self


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: Any,
    deep: bool = False,
) -> dict[object, object]:
    if not isinstance(node, yaml.MappingNode):
        raise yaml.constructor.ConstructorError(
            None,
            None,
            f"expected a mapping node, but found {node.id}",
            node.start_mark,
        )

    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, Hashable):
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            )
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate mapping key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _safe_load_unique_yaml(source: str) -> object:
    loader = _UniqueKeySafeLoader(source)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load_capacity_plan(path: Path) -> CapacityPlan:
    raw = _safe_load_unique_yaml(path.read_text(encoding="utf-8"))
    return CapacityPlan.model_validate(raw)

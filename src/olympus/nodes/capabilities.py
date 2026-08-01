from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from olympus.contracts.commands import TrustLabel
from olympus.nodes.errors import NodeMeshError, NodeReason


class CapabilityStatus(StrEnum):
    """Whether a capability may be dispatched today."""

    ENABLED = "enabled"
    RESERVED = "reserved"


class CapabilityRisk(StrEnum):
    """Effect class of a capability, ordered from least to most dangerous."""

    OBSERVE = "observe"
    MUTATE_LOCAL = "mutate-local"
    MUTATE_EXTERNAL = "mutate-external"
    PRIVILEGED = "privileged"


@dataclass(frozen=True)
class CapabilityDescriptor:
    """Immutable declaration of one typed unit of node work.

    The catalog is control-plane truth. A node declares which capabilities it
    believes it can run, but the declaration is untrusted input: the effective
    capability set is the intersection of the control-plane grant, the node
    declaration, and the enabled entries of this catalog.
    """

    capability_id: str
    version: int
    title: str
    summary: str
    status: CapabilityStatus
    risk: CapabilityRisk
    mutating: bool
    requires_approval: bool
    output_trust_label: TrustLabel
    max_runtime_seconds: int
    max_output_bytes: int
    max_artifacts: int
    max_artifact_bytes: int

    @property
    def name(self) -> str:
        return f"{self.capability_id}@{self.version}"


def _descriptor(
    capability_id: str,
    version: int,
    title: str,
    summary: str,
    status: CapabilityStatus,
    risk: CapabilityRisk,
    *,
    mutating: bool,
    requires_approval: bool,
    max_runtime_seconds: int = 60,
    max_output_bytes: int = 65_536,
    max_artifacts: int = 0,
    max_artifact_bytes: int = 0,
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        capability_id=capability_id,
        version=version,
        title=title,
        summary=summary,
        status=status,
        risk=risk,
        mutating=mutating,
        requires_approval=requires_approval,
        # Node output describes a remote machine that the control plane cannot
        # independently verify, so it never carries control authority.
        output_trust_label=TrustLabel.EXTERNAL_UNTRUSTED,
        max_runtime_seconds=max_runtime_seconds,
        max_output_bytes=max_output_bytes,
        max_artifacts=max_artifacts,
        max_artifact_bytes=max_artifact_bytes,
    )


SYSTEM_INSPECT = _descriptor(
    "system.inspect",
    1,
    "Bounded system inspection",
    "Report a fixed set of non-sensitive host counters. Reads no file contents, "
    "no environment variables, no process list, and no network configuration.",
    CapabilityStatus.ENABLED,
    CapabilityRisk.OBSERVE,
    mutating=False,
    requires_approval=False,
    max_runtime_seconds=15,
    max_output_bytes=16_384,
)

_RESERVED = (
    _descriptor(
        "shell.powershell",
        1,
        "Bounded PowerShell execution",
        "Reserved for the allowlisted PowerShell slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.PRIVILEGED,
        mutating=True,
        requires_approval=True,
    ),
    _descriptor(
        "fs.read",
        1,
        "Bounded file read",
        "Reserved for the node file-access slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.OBSERVE,
        mutating=False,
        requires_approval=False,
    ),
    _descriptor(
        "fs.write",
        1,
        "Bounded file write",
        "Reserved for the node file-access slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.MUTATE_LOCAL,
        mutating=True,
        requires_approval=True,
    ),
    _descriptor(
        "agent.claude",
        1,
        "Local Claude Code session",
        "Reserved for the node coding-agent slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.MUTATE_LOCAL,
        mutating=True,
        requires_approval=True,
    ),
    _descriptor(
        "agent.codex",
        1,
        "Local Codex session",
        "Reserved for the node coding-agent slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.MUTATE_LOCAL,
        mutating=True,
        requires_approval=True,
    ),
    _descriptor(
        "browser.session",
        1,
        "Governed browser session",
        "Reserved for the agentic-chrome browser slice, which wraps the existing "
        "lease-and-handoff browser runtime behind this capability. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.MUTATE_EXTERNAL,
        mutating=True,
        requires_approval=True,
    ),
    _descriptor(
        "desktop.stream",
        1,
        "Read-only desktop stream",
        "Reserved for the desktop-observation slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.OBSERVE,
        mutating=False,
        requires_approval=True,
    ),
    _descriptor(
        "desktop.takeover",
        1,
        "Interactive desktop takeover",
        "Reserved for the manual-takeover slice. Not dispatchable.",
        CapabilityStatus.RESERVED,
        CapabilityRisk.PRIVILEGED,
        mutating=True,
        requires_approval=True,
    ),
)

CAPABILITY_CATALOG: Mapping[str, CapabilityDescriptor] = MappingProxyType(
    {descriptor.name: descriptor for descriptor in (SYSTEM_INSPECT, *_RESERVED)}
)

ENABLED_CAPABILITIES: tuple[str, ...] = tuple(
    sorted(
        name
        for name, descriptor in CAPABILITY_CATALOG.items()
        if descriptor.status is CapabilityStatus.ENABLED
    )
)


def describe_capability(name: str) -> CapabilityDescriptor:
    """Return the catalog entry for ``name`` or raise a typed refusal."""
    descriptor = CAPABILITY_CATALOG.get(name)
    if descriptor is None:
        raise NodeMeshError(NodeReason.CAPABILITY_UNKNOWN, f"unknown capability {name!r}")
    return descriptor


def require_dispatchable_capability(name: str) -> CapabilityDescriptor:
    """Return ``name``'s descriptor only when the capability is enabled."""
    descriptor = describe_capability(name)
    if descriptor.status is not CapabilityStatus.ENABLED:
        raise NodeMeshError(
            NodeReason.CAPABILITY_RESERVED,
            f"capability {name!r} is reserved and cannot be dispatched",
        )
    return descriptor


def normalize_capability_names(names: object) -> tuple[str, ...]:
    """Return a sorted, de-duplicated tuple of known capability names.

    Unknown names are dropped rather than rejected so that a newer node agent
    can declare a capability this control plane has not heard of without
    breaking its session. Dropping is safe because the control-plane grant, not
    the declaration, decides what may run.
    """
    if not isinstance(names, (list, tuple)):
        return ()
    known = {name for name in names if isinstance(name, str) and name in CAPABILITY_CATALOG}
    return tuple(sorted(known))

"""Capability scopes: the constraints a grant carries beyond its name.

``system.inspect@1`` needed no scope. It reads a fixed set of counters, so
granting it says everything there is to say. ``fs.read@1`` is different: the
capability name alone would mean "read any file on that machine", and a grant
that broad is not a grant, it is a handover.

A scope is therefore part of the grant, minted with the enrollment token and
owned by the control plane. A node declares which capabilities it can run; it
never says what they may touch.

**What this boundary is and is not.** The node agent runs as some OS user and
can already read whatever that user can; nothing here sandboxes a node against
itself. What a scope bounds is what Olympus will *cause* to be read and carried
back to the control plane, and it makes every such read an auditable, refusable
decision rather than an implicit capability of being enrolled.

**Where enforcement happens, and why twice.** The control plane can only check
paths *lexically* — it has no access to the node's filesystem, so it cannot
know that ``/srv/data/link`` is a symlink to ``/etc/shadow``. The node performs
the real check against the file it actually opened. Both are necessary: the
lexical check refuses the obvious attacks before any bytes move and leaves an
audit record, and the node-side check is the only one that can see the
filesystem as it really is.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePath, PureWindowsPath
from typing import Any

from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import NodePlatform

FILE_READ = "fs.read@1"

# Absolute ceiling on a single read, independent of what a scope asks for. A
# scope may lower this; nothing may raise it.
MAX_FILE_READ_BYTES = 1_048_576

# Windows reserved device names. Opening one of these does not read a file --
# it talks to a device -- and they resolve regardless of the directory they
# appear in, which makes them a containment escape rather than a curiosity.
_WINDOWS_DEVICE_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{digit}" for digit in range(1, 10)),
        *(f"lpt{digit}" for digit in range(1, 10)),
    }
)


class ScopeError(NodeMeshError):
    """Raised when a scope is malformed or a request falls outside it."""


def _pure(platform: NodePlatform) -> type[PurePath]:
    from pathlib import PurePosixPath

    return PureWindowsPath if platform is NodePlatform.WINDOWS else PurePosixPath


def normalize_path(raw: str, *, platform: NodePlatform) -> PurePath:
    """Resolve ``.`` and ``..`` lexically and reject anything unsafe to compare.

    ``PurePath`` deliberately does not collapse ``..``, because it cannot know
    whether a component is a symlink. That is exactly why this is lexical only
    and why the node checks again: here we need a single canonical spelling so
    that containment is decidable at all, and ``/srv/../etc/shadow`` must not
    read as a path under ``/srv``.
    """
    if not raw or not raw.strip():
        raise ScopeError(NodeReason.CAPABILITY_PARAMETERS_INVALID, "path must not be empty")
    if "\x00" in raw:
        raise ScopeError(
            NodeReason.CAPABILITY_PARAMETERS_INVALID, "path must not contain a NUL byte"
        )

    pure = _pure(platform)
    candidate = pure(raw)
    if not candidate.is_absolute():
        raise ScopeError(
            NodeReason.CAPABILITY_PARAMETERS_INVALID, f"path must be absolute: {raw!r}"
        )

    if platform is NodePlatform.WINDOWS:
        # \\server\share and \\?\ bypass normal path handling entirely.
        if raw.startswith("\\\\") or raw.startswith("//"):
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID, "UNC and device paths are refused"
            )
        if ":" in candidate.name:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID,
                "alternate data streams are refused",
            )

    anchor = candidate.anchor
    resolved: list[str] = []
    for part in candidate.parts[1:] if anchor else candidate.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                # Escaping above the anchor is meaningless and is only ever an
                # attempt to confuse the comparison that follows.
                raise ScopeError(
                    NodeReason.CAPABILITY_PARAMETERS_INVALID,
                    "path traverses above the filesystem root",
                )
            resolved.pop()
            continue
        if platform is NodePlatform.WINDOWS:
            stem = part.split(".", 1)[0].strip().lower()
            if stem in _WINDOWS_DEVICE_NAMES:
                raise ScopeError(
                    NodeReason.CAPABILITY_PARAMETERS_INVALID,
                    f"{part!r} is a reserved device name, not a file",
                )
        resolved.append(part)

    return pure(anchor).joinpath(*resolved)


def is_within(root: PurePath, candidate: PurePath, *, platform: NodePlatform) -> bool:
    """Whether ``candidate`` is ``root`` or lies beneath it.

    Compared component-wise rather than by string prefix: ``/srv/data-secret``
    starts with the string ``/srv/data`` but is not inside it, and a prefix
    comparison would hand out the wrong directory.
    """
    root_parts = root.parts
    candidate_parts = candidate.parts
    if platform is NodePlatform.WINDOWS:
        root_parts = tuple(part.lower() for part in root_parts)
        candidate_parts = tuple(part.lower() for part in candidate_parts)
    if len(candidate_parts) < len(root_parts):
        return False
    return candidate_parts[: len(root_parts)] == root_parts


@dataclass(frozen=True)
class FileReadScope:
    """The bound on one node's ``fs.read@1`` grant."""

    roots: tuple[str, ...]
    max_bytes: int = MAX_FILE_READ_BYTES
    platform: NodePlatform = NodePlatform.LINUX

    def __post_init__(self) -> None:
        if not self.roots:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID,
                "fs.read requires at least one allowed root; an empty scope grants nothing "
                "and an absent scope must never mean everything",
            )
        if self.max_bytes < 1 or self.max_bytes > MAX_FILE_READ_BYTES:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID,
                f"max_bytes must be between 1 and {MAX_FILE_READ_BYTES}",
            )
        for root in self.roots:
            normalized = normalize_path(root, platform=self.platform)
            if len(normalized.parts) <= 1:
                # "/" or "C:\" as a root is the whole machine wearing a scope.
                raise ScopeError(
                    NodeReason.CAPABILITY_PARAMETERS_INVALID,
                    f"{root!r} is the filesystem root; scope a real directory instead",
                )

    @property
    def normalized_roots(self) -> tuple[PurePath, ...]:
        return tuple(normalize_path(root, platform=self.platform) for root in self.roots)

    def resolve(self, raw_path: str) -> PurePath:
        """Return the normalized path, or refuse it as outside every root."""
        candidate = normalize_path(raw_path, platform=self.platform)
        for root in self.normalized_roots:
            if is_within(root, candidate, platform=self.platform):
                return candidate
        raise ScopeError(
            NodeReason.CAPABILITY_NOT_GRANTED,
            f"{raw_path!r} is outside every granted root for this node",
        )

    def to_mapping(self) -> dict[str, Any]:
        return {"roots": list(self.roots), "max_bytes": self.max_bytes}

    @classmethod
    def from_mapping(
        cls, payload: Mapping[str, Any], *, platform: NodePlatform = NodePlatform.LINUX
    ) -> FileReadScope:
        roots = payload.get("roots")
        if not isinstance(roots, Sequence) or isinstance(roots, str) or not roots:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID,
                "fs.read scope must list at least one root",
            )
        raw_max = payload.get("max_bytes", MAX_FILE_READ_BYTES)
        try:
            max_bytes = int(raw_max)
        except (TypeError, ValueError) as exc:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID, "max_bytes must be an integer"
            ) from exc
        return cls(
            roots=tuple(str(root) for root in roots),
            max_bytes=max_bytes,
            platform=platform,
        )


def parse_scopes(
    payload: Mapping[str, Any] | None, *, platform: NodePlatform
) -> dict[str, FileReadScope]:
    """Build the typed scopes for one node from its stored grant."""
    if not payload:
        return {}
    scopes: dict[str, FileReadScope] = {}
    for capability, raw in payload.items():
        if capability == FILE_READ:
            if not isinstance(raw, Mapping):
                raise ScopeError(
                    NodeReason.CAPABILITY_PARAMETERS_INVALID,
                    f"scope for {capability} must be an object",
                )
            scopes[capability] = FileReadScope.from_mapping(raw, platform=platform)
        # Unknown capability scopes are ignored rather than rejected so an older
        # control plane can read a record written by a newer one. They cannot
        # grant anything: a capability with no enforcement path is refused by
        # `assert_scoped` below.
    return scopes


def requires_scope(capability: str) -> bool:
    """Whether dispatching this capability is meaningless without a scope.

    Fail closed by name. A capability that can reach arbitrary host state must
    be listed here the moment it is defined, so that forgetting to plumb its
    scope refuses dispatch rather than granting everything.
    """
    return capability == FILE_READ


def assert_scoped_dispatch(
    *,
    capability: str,
    scopes: Mapping[str, FileReadScope],
    parameters: Mapping[str, Any],
) -> None:
    """Refuse a dispatch whose parameters fall outside the node's grant.

    This is the control-plane half, and it is lexical: it cannot resolve
    symlinks on a machine it does not have. It refuses the traversal and
    absolute-path escapes before any bytes move; the node refuses what only the
    node can see.
    """
    if not requires_scope(capability):
        return
    scope = scopes.get(capability)
    if scope is None:
        raise ScopeError(
            NodeReason.CAPABILITY_NOT_GRANTED,
            f"{capability} is granted without a scope; refusing rather than assuming any path",
        )
    raw_path = parameters.get("path")
    if not isinstance(raw_path, str):
        raise ScopeError(
            NodeReason.CAPABILITY_PARAMETERS_INVALID, "fs.read requires a 'path' string"
        )
    scope.resolve(raw_path)

    requested = parameters.get("max_bytes")
    if requested is not None:
        try:
            value = int(requested)
        except (TypeError, ValueError) as exc:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID, "max_bytes must be an integer"
            ) from exc
        if value < 1 or value > scope.max_bytes:
            raise ScopeError(
                NodeReason.CAPABILITY_PARAMETERS_INVALID,
                f"max_bytes must be between 1 and the granted {scope.max_bytes}",
            )

"""The node half of ``fs.read@1``: open a file without ever leaving the root.

The control plane checks paths lexically, which is all it can do from another
machine. It cannot know that ``/srv/data/report`` is a symlink to
``/etc/shadow``. This is where that is caught, because this is the only place
that can see the filesystem as it really is.

**How containment is enforced.** Where the platform supports it, the path is
walked one component at a time with ``openat`` and ``O_NOFOLLOW``, starting
from a directory handle for the root. Each step either opens a real directory
entry or fails; a symlink anywhere along the way is refused rather than
followed. This is deliberately not "resolve the path, then compare it to the
root": that check races. Between the comparison and the open, a component can
be replaced with a symlink, and the opened file is then whatever the attacker
pointed at. Walking with handles has nothing to race against, because each
component is resolved relative to a directory the previous step already
holds open.

On platforms without ``dir_fd`` support the walk degrades to an ``lstat`` of
each component plus a final containment check on the real path. That closes
the symlink escape but not the race, and it says so rather than pretending
otherwise.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

from olympus.node_agent.capabilities import (
    CapabilityRequest,
    CapabilityResult,
    ProgressReporter,
)
from olympus.nodes.errors import NodeMeshError
from olympus.nodes.models import NodePlatform
from olympus.nodes.scopes import FILE_READ, FileReadScope

# Chunked so a file that is enormous, or a character device that never ends, is
# bounded by how much has been read rather than by its declared size.
_CHUNK = 65_536

SUPPORTS_HANDLE_WALK = bool(getattr(os, "supports_dir_fd", set())) and os.open in getattr(
    os, "supports_dir_fd", set()
)


class FileReadRefused(Exception):
    """Raised when a read cannot be performed within the granted bounds."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class FileReadOutcome:
    path: str
    size_bytes: int
    returned_bytes: int
    truncated: bool
    sha256: str
    encoding: str
    content: str


def _relative_parts(root: PurePath, target: PurePath) -> tuple[str, ...]:
    return tuple(target.parts[len(root.parts) :])


def _is_symlink_at(directory: int, name: str) -> bool:
    """Whether ``name`` in this open directory is a symlink, without following it."""
    try:
        return stat.S_ISLNK(os.lstat(name, dir_fd=directory).st_mode)
    except OSError:
        return False


def _open_within_posix(root: Path, parts: tuple[str, ...]) -> int:
    """Walk from ``root`` to the target, refusing any symlink on the way."""
    # O_NONBLOCK matters as much as O_NOFOLLOW here. Opening a FIFO with no
    # writer blocks forever, and the file-type check that would refuse it lives
    # *after* the open — so without this, pointing the capability at a named
    # pipe inside the granted root hangs the job until its deadline and ties up
    # a worker, using nothing but a legitimately granted path. O_NONBLOCK makes
    # the open return immediately so fstat can refuse it. On regular files it
    # has no effect.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    # The root is operator-configured rather than caller-supplied, so it is
    # resolved once here; everything below it is walked without following.
    directory = os.open(str(root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            try:
                handle = os.open(
                    part,
                    flags if last else flags | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=directory,
                )
            except OSError as exc:
                # The errno alone does not identify a symlink. O_NOFOLLOW on a
                # final-component symlink gives ELOOP, but on an intermediate
                # one combined with O_DIRECTORY it gives ENOTDIR — the same
                # answer a plain file would give. Ask the directory handle
                # directly instead of inferring: lstat does not follow, so this
                # reports what was actually there without ever traversing it.
                if _is_symlink_at(directory, part):
                    raise FileReadRefused(
                        "capability-parameters-invalid",
                        f"{part!r} is a symbolic link; the granted root is "
                        "not left by following one",
                    ) from exc
                raise FileReadRefused(
                    "capability-parameters-invalid", f"cannot open {part!r}"
                ) from exc
            os.close(directory)
            directory = handle
        return directory
    except BaseException:
        os.close(directory)
        raise


def _open_within_fallback(root: Path, target: Path) -> int:
    """No ``dir_fd`` available: refuse symlinks component-wise, then verify.

    This is strictly weaker than the handle walk — a component can change
    between the check and the open — and is used only where the platform gives
    nothing better.
    """
    current = root
    for part in _relative_parts(root, target):
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise FileReadRefused(
                "capability-parameters-invalid", f"cannot inspect {part!r}"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise FileReadRefused(
                "capability-parameters-invalid",
                f"{part!r} is a symbolic link; the granted root is not left by following one",
            )
    real = Path(os.path.realpath(target))
    if real != target:
        raise FileReadRefused("capability-parameters-invalid", "path does not resolve to itself")
    return os.open(str(target), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))


def read_within_scope(scope: FileReadScope, raw_path: str, *, max_bytes: int) -> FileReadOutcome:
    """Read a file, or refuse. Never leaves the granted root."""
    target = scope.resolve(raw_path)
    root = _containing_root(scope, target)
    root_path = Path(str(root))
    target_path = Path(str(target))
    parts = _relative_parts(root, target)

    if not parts:
        raise FileReadRefused(
            "capability-parameters-invalid", "the granted root is a directory, not a file"
        )

    if SUPPORTS_HANDLE_WALK:
        handle = _open_within_posix(root_path, parts)
    else:  # pragma: no cover - exercised only on platforms without dir_fd
        handle = _open_within_fallback(root_path, target_path)

    try:
        info = os.fstat(handle)
        # Checked on the handle actually opened, not on the path. A path-based
        # check answers a question about a name; this answers it about the file.
        if not stat.S_ISREG(info.st_mode):
            raise FileReadRefused(
                "capability-parameters-invalid",
                "only regular files can be read; devices, directories, sockets, "
                "and FIFOs are refused",
            )

        digest = hashlib.sha256()
        collected = bytearray()
        remaining = max_bytes
        with os.fdopen(handle, "rb", closefd=True) as stream:
            handle = -1
            while remaining > 0:
                chunk = stream.read(min(_CHUNK, remaining))
                if not chunk:
                    break
                collected.extend(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            # One byte beyond the budget, purely to distinguish "the file ended"
            # from "the budget ended". Truncation is reported, never silent.
            truncated = bool(stream.read(1))
    finally:
        if handle != -1:
            os.close(handle)

    data = bytes(collected)
    try:
        content = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        # Binary is base64 rather than lossily decoded: a report that silently
        # replaced undecodable bytes would misrepresent the file it claims to
        # have read.
        content = base64.b64encode(data).decode("ascii")
        encoding = "base64"

    return FileReadOutcome(
        path=str(target),
        size_bytes=info.st_size,
        returned_bytes=len(data),
        truncated=truncated,
        sha256=digest.hexdigest(),
        encoding=encoding,
        content=content,
    )


class FileReadProvider:
    """Serves ``fs.read@1`` for one node, bounded by the grant it was given."""

    def __init__(self, *, scope: FileReadScope) -> None:
        self._scope = scope

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (FILE_READ,)

    @property
    def scope(self) -> FileReadScope:
        return self._scope

    async def execute(
        self, request: CapabilityRequest, report: ProgressReporter
    ) -> CapabilityResult:
        raw_path = request.parameters.get("path")
        if not isinstance(raw_path, str):
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="fs.read requires a 'path' string",
            )

        requested = request.parameters.get("max_bytes", self._scope.max_bytes)
        try:
            max_bytes = int(requested)
        except (TypeError, ValueError):
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="max_bytes must be an integer",
            )
        # The node re-applies its own ceiling. The control plane already checked
        # this, but a node that trusted the request to stay inside the grant
        # would be trusting the very thing the grant exists to bound.
        max_bytes = max(1, min(max_bytes, self._scope.max_bytes, request.max_output_bytes))

        await report("opening file within the granted root", 20)
        try:
            outcome = await asyncio.to_thread(
                read_within_scope, self._scope, raw_path, max_bytes=max_bytes
            )
        except FileReadRefused as refused:
            return CapabilityResult(
                status="rejected", reason=refused.reason, message=refused.message
            )
        except NodeMeshError as exc:
            # A scope refusal from resolve(): out of root, traversal, device name.
            return CapabilityResult(status="rejected", reason=exc.reason.value, message=exc.message)
        except OSError:
            return CapabilityResult(
                status="failed",
                reason="capability-failed",
                message="the file could not be read",
            )

        await report("read complete", 100)
        output: dict[str, Any] = {
            "path": outcome.path,
            "size_bytes": outcome.size_bytes,
            "returned_bytes": outcome.returned_bytes,
            "truncated": outcome.truncated,
            "sha256": outcome.sha256,
            "encoding": outcome.encoding,
            "content": outcome.content,
        }
        return CapabilityResult(status="succeeded", output=output)


def _containing_root(scope: FileReadScope, target: PurePath) -> PurePath:
    """Which granted root this already-validated target sits under."""
    for candidate in scope.normalized_roots:
        prefix = target.parts[: len(candidate.parts)]
        if scope.platform is NodePlatform.WINDOWS:
            if tuple(p.lower() for p in prefix) == tuple(p.lower() for p in candidate.parts):
                return candidate
        elif prefix == candidate.parts:
            return candidate
    # scope.resolve() already established containment, so reaching here means
    # the two disagree — a bug, not a refusal to report to the caller.
    raise AssertionError("resolved path is not under any granted root")

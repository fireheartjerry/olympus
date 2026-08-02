"""The node half of ``fs.write@1``: the first capability that changes a machine.

Everything enabled before this one observed. This one does not, and that
changes what "correct" has to mean:

* **A partial write is not an acceptable failure.** A crash, a full disk, or a
  killed process must leave the target either untouched or completely replaced,
  never half-written. So bytes go to a temporary file in the *same directory*,
  are flushed to disk, and only then replace the target with an atomic rename.
  Same directory because rename is only atomic within a filesystem.

* **The node verifies what it was asked to write.** The approval is bound to a
  content digest; the node recomputes it before anything is renamed into place.
  Writing bytes that do not match the approved digest would mean the approval
  authorized one thing and the machine received another.

* **Creating and replacing are different acts.** A create-only write that
  quietly replaces an existing file is a destructive operation wearing a safe
  approval, so the mode is part of the approved digest and is enforced here.

Containment is the same walk ``fs.read@1`` uses, for the same reason: the
control plane sees a string, and only the node can see that a component is a
symlink.
"""

from __future__ import annotations

import asyncio
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
from olympus.node_agent.file_read import FileReadRefused, _is_symlink_at
from olympus.nodes.errors import NodeMeshError
from olympus.nodes.models import NodePlatform
from olympus.nodes.scopes import FILE_WRITE, FileWriteScope, WriteMode


@dataclass(frozen=True)
class FileWriteOutcome:
    path: str
    written_bytes: int
    sha256: str
    mode: str
    replaced: bool


def _containing_root(scope: FileWriteScope, target: PurePath) -> PurePath:
    for candidate in scope.normalized_roots:
        prefix = target.parts[: len(candidate.parts)]
        if scope.platform is NodePlatform.WINDOWS:
            if tuple(p.lower() for p in prefix) == tuple(p.lower() for p in candidate.parts):
                return candidate
        elif prefix == candidate.parts:
            return candidate
    raise AssertionError("resolved path is not under any granted root")


def _open_parent_directory(root: Path, parts: tuple[str, ...]) -> int:
    """Open the directory that will hold the file, following no symlink.

    Only the directory is opened, never the target itself: the target may not
    exist yet, and opening it to check would be a different operation from the
    one performed a moment later.
    """
    directory = os.open(str(root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        for part in parts[:-1]:
            try:
                handle = os.open(part, flags, dir_fd=directory)
            except OSError as exc:
                if _is_symlink_at(directory, part):
                    raise FileReadRefused(
                        "capability-parameters-invalid",
                        f"{part!r} is a symbolic link; the granted root is "
                        "not left by following one",
                    ) from exc
                raise FileReadRefused(
                    "capability-parameters-invalid", f"cannot open directory {part!r}"
                ) from exc
            os.close(directory)
            directory = handle
        return directory
    except BaseException:
        os.close(directory)
        raise


def write_within_scope(
    scope: FileWriteScope,
    raw_path: str,
    *,
    content: bytes,
    mode: WriteMode,
    expected_sha256: str,
) -> FileWriteOutcome:
    """Write a file atomically inside the granted root, or refuse."""
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected_sha256.lower():
        # The approval covered a specific digest. Different bytes arrived.
        raise FileReadRefused(
            "capability-parameters-invalid",
            "content does not match the approved digest; refusing to write bytes "
            "that were never approved",
        )
    if len(content) > scope.max_bytes:
        raise FileReadRefused(
            "capability-parameters-invalid",
            f"content exceeds the granted ceiling of {scope.max_bytes} bytes",
        )

    target = scope.resolve(raw_path)
    root = _containing_root(scope, target)
    parts = tuple(target.parts[len(root.parts) :])
    name = parts[-1]

    directory = _open_parent_directory(Path(str(root)), parts)
    try:
        existing = _existing_kind(directory, name)
        if existing is not None:
            if existing == "symlink":
                # Writing through it would land outside the root, and replacing
                # it would silently destroy a link the operator did not name.
                raise FileReadRefused(
                    "capability-parameters-invalid",
                    f"{name!r} is a symbolic link; refusing to write through or over it",
                )
            if existing != "file":
                raise FileReadRefused(
                    "capability-parameters-invalid",
                    f"{name!r} exists and is not a regular file",
                )
            if mode is WriteMode.CREATE:
                raise FileReadRefused(
                    "capability-parameters-invalid",
                    f"{name!r} already exists and this write was approved as create-only",
                )
            if not scope.allow_overwrite:
                raise FileReadRefused(
                    "capability-not-granted",
                    "this node's grant does not permit replacing an existing file",
                )

        replaced = existing == "file"
        _atomic_write(directory, name, content)
    finally:
        os.close(directory)

    return FileWriteOutcome(
        path=str(target),
        written_bytes=len(content),
        sha256=actual,
        mode=mode.value,
        replaced=replaced,
    )


def _existing_kind(directory: int, name: str) -> str | None:
    """What is already at ``name``, without following a link to find out."""
    try:
        info = os.lstat(name, dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FileReadRefused("capability-parameters-invalid", f"cannot inspect {name!r}") from exc
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISREG(info.st_mode):
        return "file"
    return "other"


def _atomic_write(directory: int, name: str, content: bytes) -> None:
    """Write to a sibling temporary file, flush it, then rename into place.

    The rename is what makes this atomic: a reader sees either the old file or
    the new one, never a partial one. Flushing first is what makes it durable —
    without the fsync a crash can leave the rename visible while the bytes it
    points at are still in cache, which is a corrupt file that *looks* like a
    successful write.
    """
    # Created relative to the already-opened directory handle rather than by
    # path, so the temporary lands in the same directory the walk verified and
    # cannot be redirected by anything that changes underneath us. O_EXCL means
    # an attacker who guesses the name loses the race instead of winning it.
    temporary_name = f".{name}.{os.urandom(8).hex()}.partial"
    handle = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory,
    )
    try:
        with os.fdopen(handle, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, name, src_dir_fd=directory, dst_dir_fd=directory)
        # Durability of the rename itself, not just of the bytes.
        os.fsync(directory)
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except OSError:
            pass
        raise


class FileWriteProvider:
    """Serves ``fs.write@1``, bounded by the grant and the approved digest."""

    def __init__(self, *, scope: FileWriteScope) -> None:
        self._scope = scope

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (FILE_WRITE,)

    @property
    def scope(self) -> FileWriteScope:
        return self._scope

    async def execute(
        self, request: CapabilityRequest, report: ProgressReporter
    ) -> CapabilityResult:
        parameters = request.parameters
        raw_path = parameters.get("path")
        encoded = parameters.get("content_base64")
        expected = parameters.get("content_sha256")
        raw_mode = parameters.get("mode", WriteMode.CREATE.value)

        if not isinstance(raw_path, str) or not isinstance(encoded, str):
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="fs.write requires 'path' and 'content_base64'",
            )
        if not isinstance(expected, str) or len(expected) != 64:
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="fs.write requires the approved 'content_sha256'",
            )
        try:
            mode = WriteMode(str(raw_mode))
        except ValueError:
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="mode must be 'create' or 'overwrite'",
            )

        import base64
        import binascii

        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="content_base64 is not valid base64",
            )

        await report("writing within the granted root", 30)
        try:
            outcome = await asyncio.to_thread(
                write_within_scope,
                self._scope,
                raw_path,
                content=content,
                mode=mode,
                expected_sha256=expected,
            )
        except FileReadRefused as refused:
            return CapabilityResult(
                status="rejected", reason=refused.reason, message=refused.message
            )
        except NodeMeshError as exc:
            return CapabilityResult(status="rejected", reason=exc.reason.value, message=exc.message)
        except OSError:
            return CapabilityResult(
                status="failed",
                reason="capability-failed",
                message="the file could not be written",
            )

        await report("write complete", 100)
        output: dict[str, Any] = {
            "path": outcome.path,
            "written_bytes": outcome.written_bytes,
            "sha256": outcome.sha256,
            "mode": outcome.mode,
            "replaced": outcome.replaced,
        }
        return CapabilityResult(status="succeeded", output=output)

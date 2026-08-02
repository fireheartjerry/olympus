"""Adversarial tests for ``fs.write@1``, the first capability that changes a machine.

Read capabilities leak. Write capabilities destroy, and a destroyed file has no
"refused" state to fall back to. So these test not only what is refused, but
what the filesystem looks like afterwards when something goes wrong.
"""

import base64
import hashlib
import os
import stat
from pathlib import Path

import pytest

from olympus.node_agent.capabilities import CapabilityRequest
from olympus.node_agent.file_read import FileReadRefused
from olympus.node_agent.file_write import (
    FileWriteProvider,
    write_within_scope,
)
from olympus.nodes.errors import NodeMeshError
from olympus.nodes.scopes import (
    FILE_WRITE,
    FileWriteScope,
    WriteMode,
    file_write_action_digest,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "writable"
    directory.mkdir()
    (directory / "existing.txt").write_text("original\n", encoding="utf-8")
    (directory / "nested").mkdir()
    return directory


def scope_for(root: Path, **kwargs) -> FileWriteScope:
    return FileWriteScope(roots=(str(root),), **kwargs)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def run(provider: FileWriteProvider, **parameters):
    async def report(message: str, percent: int | None) -> None:
        return None

    return await provider.execute(
        CapabilityRequest(
            job_id="job-1",
            capability=FILE_WRITE,
            parameters=dict(parameters),
            deadline_seconds=15,
            max_output_bytes=16_384,
        ),
        report,
    )


# --- the happy path -------------------------------------------------------------


def test_creates_a_new_file(root: Path) -> None:
    body = b"olympus\n"
    outcome = write_within_scope(
        scope_for(root),
        str(root / "new.txt"),
        content=body,
        mode=WriteMode.CREATE,
        expected_sha256=digest(body),
    )

    assert (root / "new.txt").read_bytes() == body
    assert outcome.replaced is False
    assert outcome.written_bytes == len(body)


def test_overwrite_replaces_when_both_the_mode_and_the_grant_allow_it(root: Path) -> None:
    body = b"replaced\n"
    write_within_scope(
        scope_for(root, allow_overwrite=True),
        str(root / "existing.txt"),
        content=body,
        mode=WriteMode.OVERWRITE,
        expected_sha256=digest(body),
    )

    assert (root / "existing.txt").read_bytes() == body


# --- the approval binding --------------------------------------------------------


def test_content_that_does_not_match_the_approved_digest_is_refused(root: Path) -> None:
    """The whole point of binding an approval to a digest.

    An approval for one payload must not write a different one, or the approval
    authorized something the machine never received.
    """
    with pytest.raises(FileReadRefused, match="never approved"):
        write_within_scope(
            scope_for(root),
            str(root / "new.txt"),
            content=b"malicious",
            mode=WriteMode.CREATE,
            expected_sha256=digest(b"benign"),
        )

    assert not (root / "new.txt").exists()


def test_the_action_digest_binds_every_field_that_matters() -> None:
    """Each field must change the digest, or it is not really bound.

    A field that leaves the digest unchanged is a field an attacker may vary
    freely while reusing a captured approval.
    """
    base = dict(
        node_id="node-1",
        path="/srv/app/config.json",
        content_sha256=digest(b"a"),
        content_length=1,
        mode=WriteMode.CREATE,
    )
    original = file_write_action_digest(**base)

    variations = [
        {**base, "node_id": "node-2"},
        {**base, "path": "/srv/app/other.json"},
        {**base, "content_sha256": digest(b"b")},
        {**base, "content_length": 2},
        {**base, "mode": WriteMode.OVERWRITE},
    ]
    for variation in variations:
        assert file_write_action_digest(**variation) != original, variation

    # And it is stable for identical input, or approvals could never match.
    assert file_write_action_digest(**base) == original


def test_a_create_approval_cannot_become_an_overwrite(root: Path) -> None:
    # Destroying an existing file under an approval that said "create" is a
    # destructive act wearing a safe approval.
    body = b"sneaky\n"
    with pytest.raises(FileReadRefused, match="create-only"):
        write_within_scope(
            scope_for(root, allow_overwrite=True),
            str(root / "existing.txt"),
            content=body,
            mode=WriteMode.CREATE,
            expected_sha256=digest(body),
        )

    assert (root / "existing.txt").read_text() == "original\n"


def test_overwrite_is_refused_when_the_grant_forbids_it(root: Path) -> None:
    body = b"nope\n"
    with pytest.raises(FileReadRefused, match="does not permit replacing"):
        write_within_scope(
            scope_for(root, allow_overwrite=False),
            str(root / "existing.txt"),
            content=body,
            mode=WriteMode.OVERWRITE,
            expected_sha256=digest(body),
        )

    assert (root / "existing.txt").read_text() == "original\n"


# --- containment ------------------------------------------------------------------


def test_writing_outside_the_root_is_refused(root: Path, tmp_path: Path) -> None:
    body = b"x"
    with pytest.raises(NodeMeshError):
        write_within_scope(
            scope_for(root),
            str(tmp_path / "escaped.txt"),
            content=body,
            mode=WriteMode.CREATE,
            expected_sha256=digest(body),
        )
    assert not (tmp_path / "escaped.txt").exists()


def test_traversal_out_of_the_root_is_refused(root: Path, tmp_path: Path) -> None:
    body = b"x"
    with pytest.raises(NodeMeshError):
        write_within_scope(
            scope_for(root),
            str(root / ".." / "escaped.txt"),
            content=body,
            mode=WriteMode.CREATE,
            expected_sha256=digest(body),
        )
    assert not (tmp_path / "escaped.txt").exists()


def test_writing_over_a_symlink_is_refused_and_the_target_is_untouched(
    root: Path, tmp_path: Path
) -> None:
    """The escape that matters most for a write.

    Following it would write outside the root; replacing it would destroy a
    link the operator never named. Neither is acceptable, so both are refused.
    """
    outside = tmp_path / "outside.txt"
    outside.write_text("precious\n", encoding="utf-8")
    (root / "link.txt").symlink_to(outside)

    body = b"clobbered\n"
    with pytest.raises(FileReadRefused, match="symbolic link"):
        write_within_scope(
            scope_for(root, allow_overwrite=True),
            str(root / "link.txt"),
            content=body,
            mode=WriteMode.OVERWRITE,
            expected_sha256=digest(body),
        )

    assert outside.read_text() == "precious\n"
    assert (root / "link.txt").is_symlink()


def test_a_symlinked_parent_directory_is_refused(root: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "bridge").symlink_to(elsewhere)

    body = b"x"
    with pytest.raises(FileReadRefused, match="symbolic link"):
        write_within_scope(
            scope_for(root),
            str(root / "bridge" / "planted.txt"),
            content=body,
            mode=WriteMode.CREATE,
            expected_sha256=digest(body),
        )

    assert not (elsewhere / "planted.txt").exists()


def test_writing_over_a_directory_is_refused(root: Path) -> None:
    body = b"x"
    with pytest.raises(FileReadRefused, match="not a regular file"):
        write_within_scope(
            scope_for(root, allow_overwrite=True),
            str(root / "nested"),
            content=body,
            mode=WriteMode.OVERWRITE,
            expected_sha256=digest(body),
        )
    assert (root / "nested").is_dir()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need a POSIX host")
def test_writing_over_a_fifo_is_refused(root: Path) -> None:
    os.mkfifo(root / "pipe")
    body = b"x"

    with pytest.raises(FileReadRefused, match="not a regular file"):
        write_within_scope(
            scope_for(root, allow_overwrite=True),
            str(root / "pipe"),
            content=body,
            mode=WriteMode.OVERWRITE,
            expected_sha256=digest(body),
        )
    assert stat.S_ISFIFO((root / "pipe").stat().st_mode)


def test_the_granted_root_itself_cannot_be_written_as_a_file(root: Path) -> None:
    body = b"x"
    with pytest.raises(NodeMeshError):
        write_within_scope(
            scope_for(root),
            str(root),
            content=body,
            mode=WriteMode.CREATE,
            expected_sha256=digest(body),
        )


# --- atomicity and cleanliness -----------------------------------------------------


def test_a_refused_write_leaves_no_partial_file_behind(root: Path) -> None:
    """A rejected write must leave the directory exactly as it was.

    A stray `.partial` would be both confusing and, over time, a disk leak.
    """
    before = sorted(os.listdir(root))

    for content, expected in ((b"a", digest(b"b")), (b"x" * 999_999, digest(b"x" * 999_999))):
        with pytest.raises(FileReadRefused):
            write_within_scope(
                scope_for(root, max_bytes=64),
                str(root / "new.txt"),
                content=content,
                mode=WriteMode.CREATE,
                expected_sha256=expected,
            )

    assert sorted(os.listdir(root)) == before


def test_an_overwrite_is_atomic_and_never_leaves_a_temporary(root: Path) -> None:
    body = b"second version\n"
    write_within_scope(
        scope_for(root, allow_overwrite=True),
        str(root / "existing.txt"),
        content=body,
        mode=WriteMode.OVERWRITE,
        expected_sha256=digest(body),
    )

    assert (root / "existing.txt").read_bytes() == body
    assert [name for name in os.listdir(root) if "partial" in name] == []


def test_content_exceeding_the_granted_ceiling_is_refused(root: Path) -> None:
    body = b"y" * 500
    with pytest.raises(FileReadRefused, match="ceiling"):
        write_within_scope(
            scope_for(root, max_bytes=100),
            str(root / "big.txt"),
            content=body,
            mode=WriteMode.CREATE,
            expected_sha256=digest(body),
        )
    assert not (root / "big.txt").exists()


def test_the_written_file_is_not_world_readable(root: Path) -> None:
    # A capability that writes into a shared directory should not widen who can
    # read what it wrote.
    body = b"secretish\n"
    write_within_scope(
        scope_for(root),
        str(root / "private.txt"),
        content=body,
        mode=WriteMode.CREATE,
        expected_sha256=digest(body),
    )

    mode = (root / "private.txt").stat().st_mode
    assert not mode & stat.S_IROTH
    assert not mode & stat.S_IWOTH


# --- the provider surface ------------------------------------------------------------


async def test_provider_writes_and_reports(root: Path) -> None:
    body = b"through the provider\n"
    provider = FileWriteProvider(scope=scope_for(root))

    result = await run(
        provider,
        path=str(root / "provided.txt"),
        content_base64=base64.b64encode(body).decode(),
        content_sha256=digest(body),
        mode="create",
    )

    assert result.status == "succeeded"
    assert result.output["written_bytes"] == len(body)
    assert (root / "provided.txt").read_bytes() == body


async def test_provider_refuses_a_mismatched_digest(root: Path) -> None:
    provider = FileWriteProvider(scope=scope_for(root))

    result = await run(
        provider,
        path=str(root / "x.txt"),
        content_base64=base64.b64encode(b"actual").decode(),
        content_sha256=digest(b"approved"),
        mode="create",
    )

    assert result.status == "rejected"
    assert not (root / "x.txt").exists()


async def test_provider_requires_the_approved_digest(root: Path) -> None:
    provider = FileWriteProvider(scope=scope_for(root))

    result = await run(
        provider,
        path=str(root / "x.txt"),
        content_base64=base64.b64encode(b"a").decode(),
        mode="create",
    )

    assert result.status == "rejected"
    assert "content_sha256" in result.message


async def test_provider_rejects_an_unknown_mode(root: Path) -> None:
    body = b"a"
    provider = FileWriteProvider(scope=scope_for(root))

    result = await run(
        provider,
        path=str(root / "x.txt"),
        content_base64=base64.b64encode(body).decode(),
        content_sha256=digest(body),
        mode="append",
    )

    assert result.status == "rejected"
    assert "create" in result.message


async def test_provider_rejects_malformed_base64(root: Path) -> None:
    provider = FileWriteProvider(scope=scope_for(root))

    result = await run(
        provider,
        path=str(root / "x.txt"),
        content_base64="not base64!!",
        content_sha256=digest(b"a"),
        mode="create",
    )

    assert result.status == "rejected"
    assert not (root / "x.txt").exists()


async def test_provider_declares_only_the_write_capability(root: Path) -> None:
    assert FileWriteProvider(scope=scope_for(root)).capabilities == (FILE_WRITE,)

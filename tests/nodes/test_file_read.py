"""Adversarial tests for the node half of ``fs.read@1``, against a real filesystem.

The control plane's lexical check cannot see symlinks, devices, or races. These
tests use actual files, actual symlinks, and actual device nodes, because a
containment check verified only against a mock proves the mock is contained.
"""

import asyncio
import hashlib
import os
import stat
import threading
from pathlib import Path

import pytest

from olympus.node_agent.capabilities import CapabilityRequest
from olympus.node_agent.file_read import (
    SUPPORTS_HANDLE_WALK,
    FileReadProvider,
    FileReadRefused,
    _open_within_fallback,
    list_within_scope,
    read_within_scope,
)
from olympus.nodes.errors import NodeMeshError
from olympus.nodes.scopes import FILE_READ, FileReadScope


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "granted"
    directory.mkdir()
    (directory / "report.txt").write_text("olympus report\n", encoding="utf-8")
    (directory / "nested").mkdir()
    (directory / "nested" / "deep.txt").write_text("deep\n", encoding="utf-8")
    return directory


@pytest.fixture
def secret(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "shadow"
    target.write_text("root:$6$hunter2\n", encoding="utf-8")
    return target


def scope_for(root: Path, **kwargs) -> FileReadScope:
    return FileReadScope(roots=(str(root),), **kwargs)


async def run(provider: FileReadProvider, **parameters):
    async def report(message: str, percent: int | None) -> None:
        return None

    return await provider.execute(
        CapabilityRequest(
            job_id="job-1",
            capability=FILE_READ,
            parameters=dict(parameters),
            deadline_seconds=15,
            max_output_bytes=65_536,
        ),
        report,
    )


# --- the happy path -------------------------------------------------------------


def test_reads_a_file_inside_the_root(root: Path) -> None:
    outcome = read_within_scope(scope_for(root), str(root / "report.txt"), max_bytes=4096)

    assert outcome.content == "olympus report\n"
    assert outcome.encoding == "utf-8"
    assert outcome.truncated is False
    assert outcome.sha256 == hashlib.sha256(b"olympus report\n").hexdigest()
    assert outcome.returned_bytes == outcome.size_bytes


def test_reads_a_nested_file(root: Path) -> None:
    outcome = read_within_scope(scope_for(root), str(root / "nested" / "deep.txt"), max_bytes=4096)
    assert outcome.content == "deep\n"


# --- symlink escapes ------------------------------------------------------------


def test_a_symlink_to_a_file_outside_the_root_is_refused(root: Path, secret: Path) -> None:
    """The escape the control plane structurally cannot catch.

    The path is lexically perfect — it is inside the granted root — and the
    file it names is not.
    """
    (root / "innocent.txt").symlink_to(secret)

    with pytest.raises(FileReadRefused, match="symbolic link"):
        read_within_scope(scope_for(root), str(root / "innocent.txt"), max_bytes=4096)


def test_a_symlinked_directory_component_is_refused(root: Path, tmp_path: Path) -> None:
    # The final component is a real file; an intermediate directory is the lie.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "deep.txt").write_text("stolen\n", encoding="utf-8")
    (root / "bridge").symlink_to(elsewhere)

    with pytest.raises(FileReadRefused, match="symbolic link"):
        read_within_scope(scope_for(root), str(root / "bridge" / "deep.txt"), max_bytes=4096)


def test_a_symlink_pointing_back_inside_the_root_is_still_refused(root: Path) -> None:
    """Refused on being a link, not on where it points.

    Deciding by destination would mean resolving it, and a resolver that runs
    before the open is exactly the race this design avoids. Refusing every
    symlink is the check that has nothing to race against.
    """
    (root / "alias.txt").symlink_to(root / "report.txt")

    with pytest.raises(FileReadRefused, match="symbolic link"):
        read_within_scope(scope_for(root), str(root / "alias.txt"), max_bytes=4096)


def test_absolute_traversal_out_of_the_root_is_refused(root: Path, secret: Path) -> None:
    with pytest.raises(NodeMeshError):
        read_within_scope(scope_for(root), str(secret), max_bytes=4096)


def test_dotdot_traversal_is_refused(root: Path) -> None:
    with pytest.raises(NodeMeshError):
        read_within_scope(scope_for(root), str(root / ".." / "outside" / "shadow"), max_bytes=4096)


# --- non-regular files ----------------------------------------------------------


def test_a_directory_is_refused(root: Path) -> None:
    with pytest.raises(FileReadRefused, match="only regular files"):
        read_within_scope(scope_for(root), str(root / "nested"), max_bytes=4096)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need a POSIX host")
def test_a_fifo_is_refused_rather_than_blocking_forever(root: Path) -> None:
    """A FIFO with no writer blocks `open()` indefinitely.

    This is a real denial of service reachable with nothing but a legitimately
    granted path: the job hangs until its deadline and ties up a worker. It is
    caught by opening with O_NONBLOCK so the file-type check — which runs
    *after* the open — actually gets to run.

    Deliberately run under a timeout in a worker thread. Asserting the refusal
    directly would mean a regression hangs the whole suite instead of failing
    it, which is how this bug hid in the first place.
    """
    os.mkfifo(root / "pipe")
    outcome: dict[str, object] = {}

    def attempt() -> None:
        try:
            read_within_scope(scope_for(root), str(root / "pipe"), max_bytes=4096)
            outcome["result"] = "returned a read of a FIFO"
        except FileReadRefused as refused:
            outcome["result"] = refused
        except Exception as exc:  # noqa: BLE001 - reported below
            outcome["result"] = exc

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=10)

    assert not worker.is_alive(), "open() blocked on a FIFO; O_NONBLOCK regressed"
    refused = outcome["result"]
    assert isinstance(refused, FileReadRefused)
    assert "only regular files" in refused.message


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_a_character_device_inside_the_root_is_refused(root: Path) -> None:
    """/dev/zero never ends; reading it would return max_bytes of nothing.

    A hard link to a device places it inside the granted root without any
    symlink for the walk to catch, so the file-type check on the opened handle
    is what stops it.
    """
    try:
        os.link("/dev/zero", root / "zero")
    except OSError:
        pytest.skip("cannot hard-link a device on this filesystem")

    assert stat.S_ISCHR((root / "zero").stat().st_mode)
    with pytest.raises(FileReadRefused, match="only regular files"):
        read_within_scope(scope_for(root), str(root / "zero"), max_bytes=4096)


# --- bounds ---------------------------------------------------------------------


def test_oversized_files_are_truncated_and_say_so(root: Path) -> None:
    (root / "big.txt").write_text("x" * 10_000, encoding="utf-8")

    outcome = read_within_scope(scope_for(root), str(root / "big.txt"), max_bytes=100)

    assert outcome.returned_bytes == 100
    assert outcome.truncated is True
    assert outcome.size_bytes == 10_000
    # The digest covers what was returned, not the whole file, so a verifier
    # comparing it against the content it received agrees.
    assert outcome.sha256 == hashlib.sha256(b"x" * 100).hexdigest()


def test_a_file_exactly_at_the_budget_is_not_reported_as_truncated(root: Path) -> None:
    (root / "exact.txt").write_bytes(b"y" * 64)

    outcome = read_within_scope(scope_for(root), str(root / "exact.txt"), max_bytes=64)

    assert outcome.returned_bytes == 64
    assert outcome.truncated is False


def test_binary_content_is_base64_rather_than_lossily_decoded(root: Path) -> None:
    (root / "blob.bin").write_bytes(b"\x00\xff\xfe\x80binary")

    outcome = read_within_scope(scope_for(root), str(root / "blob.bin"), max_bytes=4096)

    assert outcome.encoding == "base64"
    import base64

    assert base64.b64decode(outcome.content) == b"\x00\xff\xfe\x80binary"


def test_the_granted_root_itself_is_not_a_readable_file(root: Path) -> None:
    with pytest.raises(FileReadRefused, match="directory, not a file"):
        read_within_scope(scope_for(root), str(root), max_bytes=4096)


# --- the provider surface --------------------------------------------------------


async def test_provider_returns_a_bounded_success(root: Path) -> None:
    provider = FileReadProvider(scope=scope_for(root))

    result = await run(provider, path=str(root / "report.txt"))

    assert result.status == "succeeded"
    assert result.output["content"] == "olympus report\n"
    assert result.output["truncated"] is False


async def test_provider_refuses_an_out_of_scope_path_without_leaking_it(
    root: Path, secret: Path
) -> None:
    provider = FileReadProvider(scope=scope_for(root))

    result = await run(provider, path=str(secret))

    assert result.status == "rejected"
    assert result.reason == "capability-not-granted"
    assert "hunter2" not in result.message


async def test_provider_reapplies_its_own_ceiling(root: Path) -> None:
    """A node must not trust the request to stay inside the grant.

    The control plane checks this too, but a node that took the request's word
    would be trusting exactly the thing the grant exists to bound.
    """
    (root / "big.txt").write_text("z" * 5_000, encoding="utf-8")
    provider = FileReadProvider(scope=scope_for(root, max_bytes=128))

    result = await run(provider, path=str(root / "big.txt"), max_bytes=99_999)

    assert result.status == "succeeded"
    assert result.output["returned_bytes"] == 128
    assert result.output["truncated"] is True


async def test_provider_rejects_a_missing_path(root: Path) -> None:
    provider = FileReadProvider(scope=scope_for(root))

    result = await run(provider)

    assert result.status == "rejected"
    assert result.reason == "capability-parameters-invalid"


async def test_provider_reports_a_missing_file_without_crashing(root: Path) -> None:
    provider = FileReadProvider(scope=scope_for(root))

    result = await run(provider, path=str(root / "absent.txt"))

    assert result.status == "rejected"
    assert result.reason == "capability-parameters-invalid"


async def test_provider_declares_only_the_file_read_capability(root: Path) -> None:
    assert FileReadProvider(scope=scope_for(root)).capabilities == (FILE_READ,)


@pytest.mark.skipif(not SUPPORTS_HANDLE_WALK, reason="platform has no dir_fd support")
def test_the_handle_walk_is_the_path_actually_taken() -> None:
    # Guards against silently degrading to the weaker fallback on Linux.
    assert SUPPORTS_HANDLE_WALK is True


def test_reading_does_not_leave_descriptors_open(root: Path) -> None:
    """A leak here would exhaust the agent after enough jobs."""
    before = len(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").exists() else None
    if before is None:
        pytest.skip("needs /proc")

    for _ in range(50):
        read_within_scope(scope_for(root), str(root / "report.txt"), max_bytes=4096)
        with pytest.raises(FileReadRefused):
            read_within_scope(scope_for(root), str(root / "nested"), max_bytes=4096)

    after = len(os.listdir("/proc/self/fd"))
    assert after <= before + 2


def test_concurrent_reads_are_independent(root: Path) -> None:
    async def exercise() -> list[str]:
        provider = FileReadProvider(scope=scope_for(root))
        results = await asyncio.gather(
            *(run(provider, path=str(root / "report.txt")) for _ in range(8))
        )
        return [result.status for result in results]

    assert asyncio.run(exercise()) == ["succeeded"] * 8


# --- the no-dir_fd fallback ------------------------------------------------------
#
# This path runs on any platform without `openat` support. It is security
# relevant and was previously unexercised: marking it `pragma: no cover` records
# that the *platform* is not the test host, which is not the same as the code
# being untestable. It is called directly here.


def test_fallback_refuses_a_symlinked_final_component(root: Path, secret: Path) -> None:
    (root / "innocent.txt").symlink_to(secret)

    with pytest.raises(FileReadRefused, match="symbolic link"):
        _open_within_fallback(root, root / "innocent.txt")


def test_fallback_refuses_a_symlinked_directory_component(root: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "deep.txt").write_text("stolen\n", encoding="utf-8")
    (root / "bridge").symlink_to(elsewhere)

    with pytest.raises(FileReadRefused, match="symbolic link"):
        _open_within_fallback(root, root / "bridge" / "deep.txt")


def test_fallback_opens_a_genuine_file(root: Path) -> None:
    handle = _open_within_fallback(root, root / "report.txt")
    try:
        assert os.read(handle, 64) == b"olympus report\n"
    finally:
        os.close(handle)


def test_fallback_refuses_a_missing_file(root: Path) -> None:
    with pytest.raises(FileReadRefused, match="cannot inspect"):
        _open_within_fallback(root, root / "absent.txt")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need a POSIX host")
def test_fallback_does_not_block_on_a_fifo(root: Path) -> None:
    # The same denial of service the handle walk had. Both paths open with
    # O_NONBLOCK; a regression in either one hangs a worker.
    os.mkfifo(root / "pipe")
    opened: dict[str, object] = {}

    def attempt() -> None:
        try:
            opened["fd"] = _open_within_fallback(root, root / "pipe")
        except Exception as exc:  # noqa: BLE001 - reported below
            opened["error"] = exc

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=10)

    assert not worker.is_alive(), "the fallback blocked on a FIFO; O_NONBLOCK regressed"
    if "fd" in opened:
        fd = opened["fd"]
        assert isinstance(fd, int)
        assert stat.S_ISFIFO(os.fstat(fd).st_mode)
        os.close(fd)


# --- fs.list: discovering names without reaching through them ------------------------


def test_listing_reports_entries_without_following_links(root: Path, secret: Path) -> None:
    """A listing that resolved links would describe files outside the root.

    It would do so while appearing to describe what is inside it, and without
    ever opening anything the caller could be refused.
    """
    (root / "link.txt").symlink_to(secret)

    listing = list_within_scope(scope_for(root), str(root))
    kinds = {entry["name"]: entry["kind"] for entry in listing.entries}

    assert kinds["report.txt"] == "file"
    assert kinds["nested"] == "directory"
    assert kinds["link.txt"] == "symlink"
    # Named, never resolved: no size, no content, nothing about the target.
    link = next(entry for entry in listing.entries if entry["name"] == "link.txt")
    assert "size_bytes" not in link


def test_listing_is_deterministic_and_reports_sizes(root: Path) -> None:
    listing = list_within_scope(scope_for(root), str(root))

    assert [entry["name"] for entry in listing.entries] == sorted(
        entry["name"] for entry in listing.entries
    )
    report = next(entry for entry in listing.entries if entry["name"] == "report.txt")
    assert report["size_bytes"] == len("olympus report\n")


def test_listing_never_recurses(root: Path) -> None:
    # One level only: a recursive listing of a large tree is an unbounded
    # operation wearing a bounded capability.
    listing = list_within_scope(scope_for(root), str(root))

    assert "deep.txt" not in {entry["name"] for entry in listing.entries}


def test_listing_outside_the_root_is_refused(root: Path, tmp_path: Path) -> None:
    with pytest.raises(NodeMeshError):
        list_within_scope(scope_for(root), str(tmp_path))


def test_listing_through_a_symlinked_directory_is_refused(root: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "secret.txt").write_text("x", encoding="utf-8")
    (root / "bridge").symlink_to(elsewhere)

    with pytest.raises(FileReadRefused, match="symbolic link"):
        list_within_scope(scope_for(root), str(root / "bridge"))


def test_listing_a_file_is_refused(root: Path) -> None:
    with pytest.raises(FileReadRefused, match="only a directory"):
        list_within_scope(scope_for(root), str(root / "report.txt"))


def test_a_large_directory_is_truncated_and_says_so(root: Path) -> None:
    for index in range(50):
        (root / f"entry-{index:03d}.txt").write_text("x", encoding="utf-8")

    listing = list_within_scope(scope_for(root), str(root), max_entries=10)

    assert len(listing.entries) == 10
    assert listing.truncated is True


def test_listing_does_not_leak_descriptors(root: Path) -> None:
    if not Path("/proc/self/fd").exists():
        pytest.skip("needs /proc")
    before = len(os.listdir("/proc/self/fd"))

    for _ in range(50):
        list_within_scope(scope_for(root), str(root))

    assert len(os.listdir("/proc/self/fd")) <= before + 2


async def test_list_provider_returns_a_bounded_listing(root: Path) -> None:
    from olympus.node_agent.file_read import FileListProvider

    provider = FileListProvider(scope=scope_for(root))

    async def report(message: str, percent: int | None) -> None:
        return None

    result = await provider.execute(
        CapabilityRequest(
            job_id="list-1",
            capability="fs.list@1",
            parameters={"path": str(root)},
            deadline_seconds=15,
            max_output_bytes=65_536,
        ),
        report,
    )

    assert result.status == "succeeded"
    assert result.output["entry_count"] >= 2
    assert result.output["truncated"] is False


async def test_list_provider_refuses_a_path_outside_the_root(root: Path, secret: Path) -> None:
    from olympus.node_agent.file_read import FileListProvider

    provider = FileListProvider(scope=scope_for(root))

    async def report(message: str, percent: int | None) -> None:
        return None

    result = await provider.execute(
        CapabilityRequest(
            job_id="list-2",
            capability="fs.list@1",
            parameters={"path": str(secret.parent)},
            deadline_seconds=15,
            max_output_bytes=65_536,
        ),
        report,
    )

    assert result.status == "rejected"

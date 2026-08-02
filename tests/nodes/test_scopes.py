"""Adversarial tests for capability scopes and lexical path containment.

Every test here is someone holding a real `fs.read@1` grant for one directory
and trying to read something else. A containment check is only worth having if
it says no to each.
"""

import pytest

from olympus.nodes.errors import NodeReason
from olympus.nodes.models import NodePlatform
from olympus.nodes.scopes import (
    FILE_READ,
    MAX_FILE_READ_BYTES,
    FileReadScope,
    ScopeError,
    assert_scoped_dispatch,
    is_within,
    normalize_path,
    parse_scopes,
    requires_scope,
)


def scope(*roots: str, max_bytes: int = 4096, platform: NodePlatform = NodePlatform.LINUX):
    return FileReadScope(
        roots=roots or ("/srv/olympus/data",), max_bytes=max_bytes, platform=platform
    )


# --- the escapes ---------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/srv/olympus/data/../../../etc/shadow",
        "/srv/olympus/data/../../etc/shadow",
        "/srv/olympus/../olympus-secrets/key",
        "/srv/olympus/data/./../../etc/passwd",
        "/etc/shadow",
        "/srv/olympus/datax/file",  # sibling whose name shares the prefix
        "/srv/olympus/data-secret/key",  # the classic string-prefix escape
    ],
)
def test_paths_outside_the_root_are_refused(path: str) -> None:
    with pytest.raises(ScopeError) as caught:
        scope().resolve(path)
    assert caught.value.reason is NodeReason.CAPABILITY_NOT_GRANTED


def test_traversal_is_collapsed_before_comparison_not_after() -> None:
    """`..` must not survive into the comparison.

    A check that string-matched the raw path would accept
    `/srv/olympus/data/../../../etc/shadow` because it starts with the root.
    """
    assert str(normalize_path("/srv/a/b/../c", platform=NodePlatform.LINUX)) == "/srv/a/c"
    assert str(normalize_path("/srv/./a//b", platform=NodePlatform.LINUX)) == "/srv/a/b"


def test_traversal_above_the_filesystem_root_is_refused() -> None:
    with pytest.raises(ScopeError, match="above the filesystem root"):
        normalize_path("/../../etc/shadow", platform=NodePlatform.LINUX)


@pytest.mark.parametrize("path", ["", "   ", "relative/path", "./relative"])
def test_non_absolute_and_empty_paths_are_refused(path: str) -> None:
    with pytest.raises(ScopeError):
        normalize_path(path, platform=NodePlatform.LINUX)


def test_nul_byte_is_refused() -> None:
    # A NUL truncates the path in any C-level open() the node eventually makes,
    # so "/srv/olympus/data/x\x00/../../etc/shadow" could open something else.
    with pytest.raises(ScopeError, match="NUL"):
        normalize_path("/srv/olympus/data/x\x00.txt", platform=NodePlatform.LINUX)


def test_paths_inside_the_root_are_allowed() -> None:
    allowed = scope().resolve("/srv/olympus/data/reports/day.json")
    assert str(allowed) == "/srv/olympus/data/reports/day.json"
    # The root itself is inside the root.
    assert str(scope().resolve("/srv/olympus/data")) == "/srv/olympus/data"


def test_containment_compares_components_not_string_prefixes() -> None:
    root = normalize_path("/srv/data", platform=NodePlatform.LINUX)
    inside = normalize_path("/srv/data/file", platform=NodePlatform.LINUX)
    sibling = normalize_path("/srv/database/file", platform=NodePlatform.LINUX)

    assert is_within(root, inside, platform=NodePlatform.LINUX) is True
    assert is_within(root, sibling, platform=NodePlatform.LINUX) is False


# --- Windows-specific escapes ---------------------------------------------------


def test_windows_reserved_device_names_are_refused() -> None:
    windows = scope("C:\\olympus\\data", platform=NodePlatform.WINDOWS)
    for name in ("CON", "nul", "COM1.txt", "LPT9"):
        with pytest.raises(ScopeError, match="reserved device name"):
            windows.resolve(f"C:\\olympus\\data\\{name}")


def test_windows_unc_and_stream_paths_are_refused() -> None:
    with pytest.raises(ScopeError, match="UNC"):
        normalize_path("\\\\server\\share\\file", platform=NodePlatform.WINDOWS)
    with pytest.raises(ScopeError, match="alternate data stream"):
        normalize_path("C:\\olympus\\data\\file.txt:hidden", platform=NodePlatform.WINDOWS)


def test_windows_containment_is_case_insensitive() -> None:
    windows = scope("C:\\Olympus\\Data", platform=NodePlatform.WINDOWS)
    # Refusing this would be a false negative on a case-insensitive filesystem;
    # accepting the equivalent on Linux would be a false positive.
    assert windows.resolve("c:\\olympus\\data\\report.txt")

    linux = scope("/srv/Data", platform=NodePlatform.LINUX)
    with pytest.raises(ScopeError):
        linux.resolve("/srv/data/report.txt")


# --- the scope itself -----------------------------------------------------------


def test_an_empty_scope_is_refused_rather_than_meaning_everything() -> None:
    with pytest.raises(ScopeError, match="at least one allowed root"):
        FileReadScope(roots=())


@pytest.mark.parametrize("root", ["/", "C:\\"])
def test_the_filesystem_root_is_not_an_acceptable_scope(root: str) -> None:
    platform = NodePlatform.WINDOWS if "C:" in root else NodePlatform.LINUX
    with pytest.raises(ScopeError, match="filesystem root"):
        FileReadScope(roots=(root,), platform=platform)


def test_max_bytes_cannot_exceed_the_absolute_ceiling() -> None:
    with pytest.raises(ScopeError):
        FileReadScope(roots=("/srv/data",), max_bytes=MAX_FILE_READ_BYTES + 1)
    with pytest.raises(ScopeError):
        FileReadScope(roots=("/srv/data",), max_bytes=0)


def test_scope_round_trips_through_its_stored_mapping() -> None:
    original = scope("/srv/olympus/data", "/var/log/olympus", max_bytes=2048)
    restored = FileReadScope.from_mapping(original.to_mapping())

    assert restored.roots == original.roots
    assert restored.max_bytes == original.max_bytes


# --- dispatch admission ---------------------------------------------------------


def test_a_capability_needing_a_scope_is_refused_when_it_has_none() -> None:
    """Granted-but-unscoped must fail closed.

    If plumbing ever drops the scope, the safe outcome is a refused dispatch,
    not an unbounded read.
    """
    assert requires_scope(FILE_READ) is True
    with pytest.raises(ScopeError, match="without a scope"):
        assert_scoped_dispatch(capability=FILE_READ, scopes={}, parameters={"path": "/srv/x"})


def test_dispatch_outside_the_scope_is_refused_before_any_bytes_move() -> None:
    with pytest.raises(ScopeError) as caught:
        assert_scoped_dispatch(
            capability=FILE_READ,
            scopes={FILE_READ: scope()},
            parameters={"path": "/etc/shadow"},
        )
    assert caught.value.reason is NodeReason.CAPABILITY_NOT_GRANTED


def test_dispatch_requires_a_path_parameter() -> None:
    with pytest.raises(ScopeError, match="requires a 'path' string"):
        assert_scoped_dispatch(capability=FILE_READ, scopes={FILE_READ: scope()}, parameters={})
    with pytest.raises(ScopeError, match="requires a 'path' string"):
        assert_scoped_dispatch(
            capability=FILE_READ, scopes={FILE_READ: scope()}, parameters={"path": 17}
        )


def test_a_request_cannot_raise_its_own_byte_ceiling() -> None:
    scopes = {FILE_READ: scope(max_bytes=1024)}
    assert_scoped_dispatch(
        capability=FILE_READ,
        scopes=scopes,
        parameters={"path": "/srv/olympus/data/f", "max_bytes": 512},
    )
    with pytest.raises(ScopeError, match="between 1 and the granted 1024"):
        assert_scoped_dispatch(
            capability=FILE_READ,
            scopes=scopes,
            parameters={"path": "/srv/olympus/data/f", "max_bytes": 4096},
        )


def test_unscoped_capabilities_pass_through_untouched() -> None:
    # system.inspect reads fixed counters and has nothing to scope.
    assert requires_scope("system.inspect@1") is False
    assert_scoped_dispatch(capability="system.inspect@1", scopes={}, parameters={})


def test_parsing_ignores_unknown_capability_scopes_without_granting_them() -> None:
    """Forward compatibility must not become a grant.

    An older control plane reading a newer record should not choke, but an
    unknown scope must never authorize anything either.
    """
    parsed = parse_scopes(
        {FILE_READ: {"roots": ["/srv/data"]}, "future.capability@1": {"anything": True}},
        platform=NodePlatform.LINUX,
    )

    assert set(parsed) == {FILE_READ}


def test_scope_is_parsed_against_the_nodes_own_platform() -> None:
    parsed = parse_scopes(
        {FILE_READ: {"roots": ["C:\\olympus\\data"]}}, platform=NodePlatform.WINDOWS
    )
    assert parsed[FILE_READ].resolve("c:\\olympus\\data\\x.txt")

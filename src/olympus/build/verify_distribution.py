from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
FORBIDDEN_DIRECTORIES = {
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "htmlcov",
    "outputs",
    "work",
}


class DistributionError(ValueError):
    """Raised when a distribution violates the release-content policy."""


def _archive_members(path: Path) -> Iterable[tuple[str, int]]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            yield from ((member.filename, member.file_size) for member in archive.infolist())
        return

    if path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(path, "r:*") as archive:
            yield from ((member.name, member.size) for member in archive.getmembers())
        return

    raise DistributionError(f"unsupported distribution format: {path.name}")


def _is_forbidden(name: str) -> bool:
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if any(part in FORBIDDEN_DIRECTORIES for part in parts):
        return True
    return any(
        part == ".env" or (part.startswith(".env.") and part != ".env.example") for part in parts
    )


def verify_distribution(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
    """Reject oversized distributions and repository-local or secret-bearing content."""
    if path.stat().st_size > max_bytes:
        raise DistributionError(f"{path.name} exceeds the {max_bytes}-byte compressed size ceiling")

    expanded_bytes = 0
    for name, size in _archive_members(path):
        expanded_bytes += size
        if _is_forbidden(name):
            raise DistributionError(f"{path.name} contains forbidden path: {name}")

    if expanded_bytes > max_bytes:
        raise DistributionError(f"{path.name} exceeds the {max_bytes}-byte expanded size ceiling")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Olympus distribution archives")
    parser.add_argument("archives", type=Path, nargs="+")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args(argv)

    try:
        for archive in args.archives:
            verify_distribution(archive, max_bytes=args.max_bytes)
    except (DistributionError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"distribution verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

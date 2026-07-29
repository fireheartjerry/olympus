from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from olympus.build.verify_distribution import DistributionError, verify_distribution


def _write_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def _write_wheel(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)


@pytest.mark.parametrize(
    "forbidden_path",
    [
        "olympus-0.1.0/work/local-tool.exe",
        "olympus-0.1.0/outputs/trace.json",
        "olympus-0.1.0/.venv/pyvenv.cfg",
        "olympus-0.1.0/src/olympus/__pycache__/module.pyc",
        "olympus-0.1.0/.pytest_cache/state",
        "olympus-0.1.0/.env",
        "olympus-0.1.0/.env.production",
    ],
)
def test_rejects_forbidden_sdist_content(tmp_path: Path, forbidden_path: str) -> None:
    archive = tmp_path / "olympus-0.1.0.tar.gz"
    _write_tar(archive, {forbidden_path: b"secret"})

    with pytest.raises(DistributionError, match="forbidden"):
        verify_distribution(archive)


def test_allows_expected_sdist_content_and_env_example(tmp_path: Path) -> None:
    archive = tmp_path / "olympus-0.1.0.tar.gz"
    _write_tar(
        archive,
        {
            "olympus-0.1.0/pyproject.toml": b"[project]",
            "olympus-0.1.0/src/olympus/__init__.py": b'__version__ = "0.1.0"',
            "olympus-0.1.0/.env.example": b"OLYMPUS_DEV_TOKEN=",
        },
    )

    verify_distribution(archive)


def test_rejects_oversized_archive(tmp_path: Path) -> None:
    archive = tmp_path / "olympus-0.1.0-py3-none-any.whl"
    _write_wheel(archive, {"olympus/payload.bin": b"x" * 2_000})

    with pytest.raises(DistributionError, match="size ceiling"):
        verify_distribution(archive, max_bytes=1_000)


def test_allows_expected_wheel_content(tmp_path: Path) -> None:
    archive = tmp_path / "olympus-0.1.0-py3-none-any.whl"
    _write_wheel(archive, {"olympus/__init__.py": b'__version__ = "0.1.0"'})

    verify_distribution(archive)

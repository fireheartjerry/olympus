import tomllib
from pathlib import Path

from olympus import __version__


def test_package_version_is_explicit() -> None:
    assert __version__ == "0.1.0"


def test_build_backend_is_pinned_in_the_lock_and_build_constraints() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["build-system"]["requires"] == [
        "hatchling==1.31.0",
        "editables==0.5",
    ]
    assert "hatchling==1.31.0" in pyproject["dependency-groups"]["dev"]
    assert "editables==0.5" in pyproject["dependency-groups"]["dev"]
    assert pyproject["tool"]["uv"]["build-constraint-dependencies"] == ["hatchling==1.31.0"]
    assert "no-build-isolation-package" not in pyproject["tool"]["uv"]
    assert "extra-build-dependencies" not in pyproject["tool"]["uv"]

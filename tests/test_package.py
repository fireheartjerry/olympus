import tomllib
from pathlib import Path

from olympus import __version__


def test_package_version_is_explicit() -> None:
    assert __version__ == "0.1.0"


def test_build_backend_is_pinned_in_the_lock_and_build_constraints() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    expected_build_dependencies = [
        "editables==0.5",
        "hatchling==1.31.0",
        "packaging==26.2",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "trove-classifiers==2026.6.1.19",
    ]

    assert pyproject["build-system"]["requires"] == [
        "hatchling==1.31.0",
        "editables==0.5",
    ]
    assert "hatchling==1.31.0" in pyproject["dependency-groups"]["dev"]
    assert "editables==0.5" in pyproject["dependency-groups"]["dev"]
    assert pyproject["tool"]["uv"]["build-constraint-dependencies"] == expected_build_dependencies
    assert "no-build-isolation-package" not in pyproject["tool"]["uv"]
    assert "extra-build-dependencies" not in pyproject["tool"]["uv"]

    constraints = Path("build-constraints.txt").read_text(encoding="utf-8")
    requirement_lines = [
        line.removesuffix(" \\") for line in constraints.splitlines() if line and line[0].isalpha()
    ]
    assert requirement_lines == expected_build_dependencies
    assert constraints.count("--hash=sha256:") == 2 * len(expected_build_dependencies)

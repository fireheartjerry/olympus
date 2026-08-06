"""Fail-closed environment compatibility for the Fire rename."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any


def apply_fire_environment_aliases(
    values: dict[str, Any],
    *,
    fields: Iterable[str],
    canonical_prefix: str,
    legacy_prefix: str,
) -> dict[str, Any]:
    """Copy Fire or legacy Olympus environment values into explicit settings.

    Explicit constructor values retain Pydantic's normal highest priority. During
    the transition both prefixes are accepted, but contradictory dual writes are
    rejected before any service can start with ambiguous configuration.
    """
    resolved = dict(values)
    for field in fields:
        suffix = field.upper()
        canonical_name = f"{canonical_prefix}{suffix}"
        legacy_name = f"{legacy_prefix}{suffix}"
        canonical_value = os.environ.get(canonical_name)
        legacy_value = os.environ.get(legacy_name)

        if (
            canonical_value is not None
            and legacy_value is not None
            and canonical_value != legacy_value
        ):
            raise ValueError(f"conflicting Fire and legacy Olympus environment values for {suffix}")

        selected = canonical_value if canonical_value is not None else legacy_value
        if field not in resolved and selected is not None:
            resolved[field] = selected
    return resolved

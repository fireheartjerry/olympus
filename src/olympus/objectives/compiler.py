"""Deterministic objective-contract compilation and canonical hashing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal
from enum import Enum

from pydantic import BaseModel

from olympus.objectives.models import (
    AuthorizedObjective,
    ObjectiveAuthorization,
    ObjectiveContract,
    ObjectiveDraft,
)


def _canonical_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="json", exclude_none=False))
    if isinstance(value, datetime):
        rendered = value.isoformat()
        return rendered[:-6] + "Z" if rendered.endswith("+00:00") else rendered
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def canonical_sha256(value: BaseModel | Mapping[str, object]) -> str:
    payload = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compile_objective(draft: ObjectiveDraft) -> ObjectiveContract:
    """Freeze a validated draft into a digest-bound objective contract.

    Planning and model reasoning happen after this boundary. The compiler does
    not infer permissions, expand scope, or invent success criteria. The digest
    binds the normalized contract representation, not the pre-normalized draft.
    """

    context_refs = tuple(dict.fromkeys(draft.context_refs))
    non_goals = tuple(dict.fromkeys(item.strip() for item in draft.non_goals if item.strip()))
    allowed_domains = tuple(dict.fromkeys(draft.allowed_domains))
    prohibited_domains = tuple(dict.fromkeys(draft.prohibited_domains))
    termination_conditions = tuple(
        dict.fromkeys(item.strip() for item in draft.termination_conditions if item.strip())
    )
    contract_values: dict[str, object] = {
        "schema_version": 1,
        "objective_id": draft.objective_id,
        "owner_id": draft.owner_id,
        "statement": draft.statement.strip(),
        "mode": draft.mode,
        "created_at": draft.created_at,
        "context_refs": context_refs,
        "success_criteria": draft.success_criteria,
        "non_goals": non_goals,
        "allowed_domains": allowed_domains,
        "prohibited_domains": prohibited_domains,
        "budget": draft.budget,
        "authority": draft.authority,
        "notification_policy": draft.notification_policy,
        "termination_conditions": termination_conditions,
    }
    digest = canonical_sha256(contract_values)
    return ObjectiveContract(
        schema_version=1,
        objective_id=draft.objective_id,
        owner_id=draft.owner_id,
        statement=draft.statement.strip(),
        mode=draft.mode,
        created_at=draft.created_at,
        context_refs=context_refs,
        success_criteria=draft.success_criteria,
        non_goals=non_goals,
        allowed_domains=allowed_domains,
        prohibited_domains=prohibited_domains,
        budget=draft.budget,
        authority=draft.authority,
        notification_policy=draft.notification_policy,
        termination_conditions=termination_conditions,
        canonical_digest=digest,
    )


def seal_authorized_objective(
    contract: ObjectiveContract, authorization: ObjectiveAuthorization
) -> AuthorizedObjective:
    """Bind an already-verified authority decision to one objective contract.

    This function performs canonical sealing only. It deliberately cannot
    verify WebAuthn, leases, policy releases, or approvals; the existing
    production authority subsystem must do that before calling it.
    """

    payload: dict[str, object] = {
        "schema_version": 1,
        "contract": contract,
        "authorization": authorization,
    }
    return AuthorizedObjective(
        contract=contract,
        authorization=authorization,
        envelope_digest=canonical_sha256(payload),
    )

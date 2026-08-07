"""Contracts for contextual transfer of active operational control.

Takeover is an orchestration mode over narrow governed capabilities. It is not
an unrestricted capability and does not widen authority by itself.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class TakeoverDomain(StrEnum):
    CURRENT_COMPUTER_TASK = "current-computer-task"
    SOFTWARE_PROJECT = "software-project"
    PRESENTATION = "presentation"
    INCIDENT = "incident"
    COMMUNICATION = "communication"
    LOGISTICS = "logistics"
    RESEARCH = "research"
    GENERAL_OPERATIONS = "general-operations"


class TakeoverState(StrEnum):
    REQUESTED = "requested"
    INTERPRETING = "interpreting"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REFUSED = "refused"
    FAILED = "failed"


class TakeoverEndReason(StrEnum):
    OBJECTIVE_COMPLETE = "objective-complete"
    OWNER_STOPPED = "owner-stopped"
    MANUAL_CONTROL_CONFLICT = "manual-control-conflict"
    AUTHORITY_EXPIRED = "authority-expired"
    FROZEN = "frozen"
    POLICY_REFUSED = "policy-refused"
    NO_LONGER_USEFUL = "no-longer-useful"
    FAILURE = "failure"


class TakeoverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=128)
    owner_id: str = Field(min_length=1, max_length=128)
    requested_at: AwareDatetime
    invocation_text: str = Field(default="Fire, take over.", min_length=1, max_length=1000)
    context_refs: tuple[str, ...]
    explicit_objective: str | None = Field(default=None, max_length=8000)
    suggested_domain: TakeoverDomain | None = None

    @model_validator(mode="after")
    def require_context(self) -> TakeoverRequest:
        if not self.context_refs and not self.explicit_objective:
            raise ValueError("takeover requires context or an explicit objective")
        return self


class TakeoverInterpretation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    inferred_domain: TakeoverDomain
    objective_summary: str = Field(min_length=1, max_length=8000)
    confidence: float = Field(ge=0.0, le=1.0)
    objective_contract_id: str | None = Field(default=None, max_length=128)
    material_ambiguities: tuple[str, ...] = ()
    one_sentence_confirmation: str = Field(min_length=1, max_length=1000)


class TakeoverSession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    objective_contract_id: str = Field(min_length=1, max_length=128)
    state: TakeoverState
    started_at: AwareDatetime
    active_node_ids: tuple[str, ...]
    active_graph_ids: tuple[str, ...]
    authority_lease_id: str = Field(min_length=1, max_length=256)
    end_reason: TakeoverEndReason | None = None
    ended_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_terminal_state(self) -> TakeoverSession:
        terminal = self.state in {
            TakeoverState.COMPLETED,
            TakeoverState.CANCELLED,
            TakeoverState.REFUSED,
            TakeoverState.FAILED,
        }
        if terminal and (self.end_reason is None or self.ended_at is None):
            raise ValueError("terminal takeover sessions require an end reason and time")
        if not terminal and (self.end_reason is not None or self.ended_at is not None):
            raise ValueError("non-terminal takeover sessions cannot carry terminal fields")
        return self

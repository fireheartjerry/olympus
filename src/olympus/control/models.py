from dataclasses import dataclass
from enum import StrEnum

from olympus.authority.models import AuthorityContext


class ControlAction(StrEnum):
    FREEZE = "freeze"
    INSPECT = "inspect"
    PAUSE = "pause"
    CANCEL = "cancel"
    RESUME = "resume"
    UNFREEZE = "unfreeze"


_GLOBAL_ACTIONS = {ControlAction.FREEZE, ControlAction.UNFREEZE}
_TARGETED_ACTIONS = {
    ControlAction.INSPECT,
    ControlAction.PAUSE,
    ControlAction.CANCEL,
    ControlAction.RESUME,
}


@dataclass(frozen=True)
class ControlRequest:
    action: ControlAction
    target_workflow_id: str | None
    authority: AuthorityContext

    def __post_init__(self) -> None:
        if self.action in _TARGETED_ACTIONS and not self.target_workflow_id:
            raise ValueError("target_workflow_id is required for job control")
        if self.action in _GLOBAL_ACTIONS and self.target_workflow_id is not None:
            raise ValueError("global control cannot target one workflow")

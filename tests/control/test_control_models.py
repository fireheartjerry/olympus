import pytest

from olympus.authority.models import AuthorityContext
from olympus.control.models import ControlAction, ControlRequest


def test_control_request_requires_target_for_job_action() -> None:
    authority = AuthorityContext(
        commander_id="628053765181800448",
        guild_id="123",
        channel_id="456",
        interaction_id="789",
        authority_epoch=1,
        lease_id="lease-1",
    )

    with pytest.raises(ValueError, match="target_workflow_id"):
        ControlRequest(
            action=ControlAction.PAUSE,
            target_workflow_id=None,
            authority=authority,
        )


def test_freeze_control_cannot_target_one_workflow() -> None:
    authority = AuthorityContext(
        commander_id="628053765181800448",
        guild_id="123",
        channel_id="456",
        interaction_id="789",
        authority_epoch=None,
        lease_id=None,
    )

    with pytest.raises(ValueError, match="global control"):
        ControlRequest(
            action=ControlAction.FREEZE,
            target_workflow_id="job-1",
            authority=authority,
        )

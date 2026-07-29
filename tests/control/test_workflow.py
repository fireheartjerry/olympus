from datetime import UTC, datetime

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.contracts.commands import CommandEnvelope, JobStatus
from olympus.control.workflow import ControlSnapshot
from olympus.workflows.command import CommandWorkflow


def command(job_id: str) -> CommandEnvelope:
    return CommandEnvelope(
        job_id=job_id,
        commander_id="628053765181800448",
        guild_id="100000000000000001",
        channel_id="100000000000000002",
        interaction_id="100000000000000003",
        authority_lease_id="lease-1",
        authority_epoch=2,
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 29, tzinfo=UTC).isoformat(),
    )


async def test_start_signal_pause_survives_until_explicit_resume() -> None:
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="control-test",
            workflows=[CommandWorkflow],
            activities=[compile_graph_activity],
        ):
            handle = await environment.client.start_workflow(
                CommandWorkflow.run,
                command("job-paused"),
                id="job-paused",
                task_queue="control-test",
                start_signal="pause",
                start_signal_args=["control-pause-1"],
            )
            snapshot = await handle.query(CommandWorkflow.inspect)
            assert snapshot == ControlSnapshot(
                paused=True,
                cancelled=False,
                frozen=False,
                processed_control_ids=("control-pause-1",),
            )

            await handle.signal(CommandWorkflow.resume, "control-resume-1")
            receipt = await handle.result()

    assert receipt.status is JobStatus.COMPILED


async def test_freeze_is_terminal_and_duplicate_control_is_idempotent() -> None:
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="control-freeze-test",
            workflows=[CommandWorkflow],
            activities=[compile_graph_activity],
        ):
            handle = await environment.client.start_workflow(
                CommandWorkflow.run,
                command("job-frozen"),
                id="job-frozen",
                task_queue="control-freeze-test",
                start_signal="freeze",
                start_signal_args=["control-freeze-1"],
            )
            await handle.signal(CommandWorkflow.freeze, "control-freeze-1")
            receipt = await handle.result()

    assert receipt.status is JobStatus.FROZEN
    assert receipt.node_count == 0

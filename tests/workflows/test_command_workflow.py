from datetime import UTC, datetime

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.contracts.commands import CommandEnvelope, JobStatus
from olympus.workflows.command import CommandWorkflow


async def test_command_workflow_returns_compiled_receipt() -> None:
    command = CommandEnvelope(
        job_id="job-temporal-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    )
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="olympus-test",
            workflows=[CommandWorkflow],
            activities=[compile_graph_activity],
        ):
            receipt = await environment.client.execute_workflow(
                CommandWorkflow.run,
                command,
                id=command.job_id,
                task_queue="olympus-test",
            )
    assert receipt.job_id == command.job_id
    assert receipt.status is JobStatus.COMPILED
    assert receipt.node_count == 1
    assert len(receipt.graph_digest) == 64

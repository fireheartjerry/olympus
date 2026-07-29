import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from temporalio import workflow
from temporalio.client import WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, TimeoutError, TimeoutType
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.contracts.commands import CommandEnvelope, JobStatus
from olympus.workflows.command import (
    COMPILE_GRAPH_ACTIVITY_MAXIMUM_ATTEMPTS,
    COMPILE_GRAPH_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT,
    COMPILE_GRAPH_ACTIVITY_START_TO_CLOSE_TIMEOUT,
    CommandWorkflow,
)

SHORT_UNAVAILABLE_ACTIVITY_TIMEOUT = timedelta(milliseconds=250)


@workflow.defn
class ShortUnavailableActivityWorkflow:
    @workflow.run
    async def run(self, command: CommandEnvelope) -> None:
        await workflow.execute_activity(
            "test-unavailable-activity",
            command,
            schedule_to_close_timeout=SHORT_UNAVAILABLE_ACTIVITY_TIMEOUT,
            start_to_close_timeout=timedelta(seconds=1),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


async def test_command_workflow_returns_compiled_receipt_with_bounded_activity_options() -> None:
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
            handle = await environment.client.start_workflow(
                CommandWorkflow.run,
                command,
                id=command.job_id,
                task_queue="olympus-test",
            )
            receipt = await handle.result()
            history = await handle.fetch_history()
    assert receipt.job_id == command.job_id
    assert receipt.status is JobStatus.COMPILED
    assert receipt.node_count == 1
    assert len(receipt.graph_digest) == 64
    scheduled_event = next(
        event
        for event in history.events
        if event.HasField("activity_task_scheduled_event_attributes")
    )
    scheduled_attributes = scheduled_event.activity_task_scheduled_event_attributes
    assert (
        scheduled_attributes.schedule_to_close_timeout.ToTimedelta()
        == COMPILE_GRAPH_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT
    )
    assert (
        scheduled_attributes.start_to_close_timeout.ToTimedelta()
        == COMPILE_GRAPH_ACTIVITY_START_TO_CLOSE_TIMEOUT
    )
    assert (
        scheduled_attributes.retry_policy.maximum_attempts
        == COMPILE_GRAPH_ACTIVITY_MAXIMUM_ATTEMPTS
    )


async def test_unavailable_activity_fails_within_its_schedule_deadline() -> None:
    command = CommandEnvelope(
        job_id="job-temporal-timeout",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    )
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="olympus-timeout-test",
            workflows=[ShortUnavailableActivityWorkflow],
            no_remote_activities=True,
        ):
            handle = await environment.client.start_workflow(
                ShortUnavailableActivityWorkflow.run,
                command,
                id=command.job_id,
                task_queue="olympus-timeout-test",
            )
            with pytest.raises(WorkflowFailureError) as exc_info:
                await asyncio.wait_for(handle.result(), timeout=5)
            history = await handle.fetch_history()

    assert isinstance(exc_info.value.cause, ActivityError)
    assert isinstance(exc_info.value.cause.cause, TimeoutError)
    # The test server can report either timeout when both deadlines expire together.
    assert exc_info.value.cause.cause.type in {
        TimeoutType.SCHEDULE_TO_START,
        TimeoutType.SCHEDULE_TO_CLOSE,
    }
    scheduled_event = next(
        event
        for event in history.events
        if event.HasField("activity_task_scheduled_event_attributes")
    )
    assert (
        scheduled_event.activity_task_scheduled_event_attributes.schedule_to_close_timeout.ToTimedelta()
        == SHORT_UNAVAILABLE_ACTIVITY_TIMEOUT
    )

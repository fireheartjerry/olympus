import asyncio

import pytest
from temporalio import activity
from temporalio.client import WorkflowFailureError
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.activities.node_dispatch import DISPATCH_ACTIVITY_NAME, SELECT_ACTIVITY_NAME
from olympus.node_agent.__main__ import MIN_BACKOFF_SECONDS
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.dispatch import NodeJobRequest
from olympus.nodes.errors import NodeReason
from olympus.nodes.models import DispatchAuthority, NodeJobOutcome, NodeJobStatus
from olympus.workflows.node_job import (
    NODE_JOB_ACTIVITY_HEARTBEAT_TIMEOUT,
    NODE_JOB_ACTIVITY_MAXIMUM_ATTEMPTS,
    NODE_JOB_ACTIVITY_RETRY_INTERVAL,
    NODE_JOB_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT,
    NodeJobWorkflow,
)

TASK_QUEUE = "olympus-node-test"
AUTHORITY = DispatchAuthority(commander_id="local-jerry", authority_lease_id="development-lease")


@activity.defn(name=SELECT_ACTIVITY_NAME)
async def select(job: NodeJobRequest) -> str:
    return job.node_id or "node-1"


def request(job_id: str = "node-job-1") -> NodeJobRequest:
    return NodeJobRequest(
        job_id=job_id,
        capability=SYSTEM_INSPECT.name,
        authority=AUTHORITY,
        parameters={"sections": ["os"]},
        node_id="node-1",
    )


def succeeding_outcome(job: NodeJobRequest) -> NodeJobOutcome:
    return NodeJobOutcome(
        job_id=job.job_id,
        node_id="node-1",
        capability=job.capability,
        dedupe_key=job.dedupe_key,
        status=NodeJobStatus.SUCCEEDED,
        attempt=job.attempt,
        output={"sections": {"os": {"system": "Windows"}}},
    )


async def run_workflow(
    activities: list[object], job: NodeJobRequest, *, signal: str = ""
) -> object:
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=TASK_QUEUE,
            workflows=[NodeJobWorkflow],
            activities=[select, *activities],  # type: ignore[arg-type]
        ):
            handle = await environment.client.start_workflow(
                NodeJobWorkflow.run, job, id=job.job_id, task_queue=TASK_QUEUE
            )
            if signal:
                await asyncio.sleep(0.2)
                await handle.signal(NodeJobWorkflow.request_cancellation, signal)
            result = await asyncio.wait_for(handle.result(), timeout=60)
            history = await handle.fetch_history()
    return result, history


async def test_the_workflow_returns_the_node_outcome_within_its_bounds() -> None:
    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        return succeeding_outcome(job)

    outcome, history = await run_workflow([dispatch], request())

    assert outcome.status is NodeJobStatus.SUCCEEDED
    assert outcome.output == {"sections": {"os": {"system": "Windows"}}}
    assert outcome.trust_label.value == "external-untrusted"

    scheduled = next(
        event.activity_task_scheduled_event_attributes
        for event in history.events
        if event.HasField("activity_task_scheduled_event_attributes")
        and event.activity_task_scheduled_event_attributes.activity_type.name
        == DISPATCH_ACTIVITY_NAME
    )
    assert scheduled.activity_type.name == DISPATCH_ACTIVITY_NAME
    assert scheduled.schedule_to_close_timeout.ToTimedelta() == (
        NODE_JOB_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT
    )
    assert scheduled.heartbeat_timeout.ToTimedelta() == NODE_JOB_ACTIVITY_HEARTBEAT_TIMEOUT
    assert scheduled.retry_policy.maximum_attempts == NODE_JOB_ACTIVITY_MAXIMUM_ATTEMPTS
    assert scheduled.retry_policy.initial_interval.ToTimedelta() == NODE_JOB_ACTIVITY_RETRY_INTERVAL


async def test_a_transient_failure_is_retried_within_the_worker_recovery_bound() -> None:
    attempts: list[int] = []

    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        attempts.append(activity.info().attempt)
        if activity.info().attempt == 1:
            raise ApplicationError(
                "session closed mid-dispatch",
                NodeReason.SESSION_CLOSED.value,
                type=NodeReason.SESSION_CLOSED.value,
            )
        return succeeding_outcome(job)

    outcome, _ = await run_workflow([dispatch], request("node-job-retry"))

    assert attempts == [1, 2]
    assert outcome.status is NodeJobStatus.SUCCEEDED


async def test_a_permanent_refusal_is_not_retried() -> None:
    attempts: list[int] = []

    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        attempts.append(activity.info().attempt)
        raise ApplicationError(
            "dispatch is frozen",
            NodeReason.DISPATCH_FROZEN.value,
            type=NodeReason.DISPATCH_FROZEN.value,
            non_retryable=True,
        )

    with pytest.raises(WorkflowFailureError) as failure:
        await run_workflow([dispatch], request("node-job-frozen"))

    assert attempts == [1]
    cause = failure.value.cause
    assert isinstance(cause, ActivityError)
    assert isinstance(cause.cause, ApplicationError)
    assert cause.cause.type == NodeReason.DISPATCH_FROZEN.value


async def test_cancellation_returns_a_cancelled_outcome_rather_than_a_lost_job() -> None:
    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        while True:
            activity.heartbeat({"job_id": job.job_id})
            await asyncio.sleep(0.2)

    outcome, _ = await run_workflow(
        [dispatch], request("node-job-cancel"), signal="operator cancellation"
    )

    assert outcome.status is NodeJobStatus.CANCELLED
    assert outcome.reason == NodeReason.JOB_CANCELLED.value
    assert outcome.message == "operator cancellation"


async def test_the_workflow_id_is_the_job_id_so_a_replay_cannot_duplicate_work() -> None:
    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        return succeeding_outcome(job)

    job = request("node-job-unique")
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=TASK_QUEUE,
            workflows=[NodeJobWorkflow],
            activities=[select, dispatch],
        ):
            first = await environment.client.start_workflow(
                NodeJobWorkflow.run, job, id=job.job_id, task_queue=TASK_QUEUE
            )
            await first.result()
            second = await environment.client.start_workflow(
                NodeJobWorkflow.run, job, id=job.job_id, task_queue=TASK_QUEUE
            )
            assert second.result_run_id != first.result_run_id
    # A second execution is only possible under a new run id, and it carries the
    # same dedupe key, so the node replays rather than repeating the work.
    assert job.dedupe_key == request("node-job-unique").dedupe_key


async def test_the_retry_lands_after_a_disconnected_node_can_reconnect() -> None:
    # A retry that fires before the agent's minimum reconnect backoff can never
    # find the node online, which would make the documented recovery impossible.
    assert NODE_JOB_ACTIVITY_RETRY_INTERVAL.total_seconds() > MIN_BACKOFF_SECONDS + 1


async def test_the_job_is_pinned_to_one_node_so_a_retry_cannot_run_it_elsewhere() -> None:
    dispatched_nodes: list[str] = []
    selections: list[int] = []

    @activity.defn(name=SELECT_ACTIVITY_NAME)
    async def selecting(job: NodeJobRequest) -> str:
        selections.append(activity.info().attempt)
        return "node-alpha"

    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        dispatched_nodes.append(job.node_id or "")
        if activity.info().attempt == 1:
            raise ApplicationError(
                "session closed mid-dispatch",
                NodeReason.SESSION_CLOSED.value,
                type=NodeReason.SESSION_CLOSED.value,
            )
        return succeeding_outcome(job)

    unpinned = NodeJobRequest(
        job_id="node-job-unpinned",
        capability=SYSTEM_INSPECT.name,
        authority=AUTHORITY,
        parameters={"sections": ["os"]},
    )
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=TASK_QUEUE,
            workflows=[NodeJobWorkflow],
            activities=[selecting, dispatch],
        ):
            handle = await environment.client.start_workflow(
                NodeJobWorkflow.run, unpinned, id=unpinned.job_id, task_queue=TASK_QUEUE
            )
            outcome = await asyncio.wait_for(handle.result(), timeout=90)
            assigned = await handle.query(NodeJobWorkflow.assigned_node)

    # Selection happens once; both dispatch attempts target the same machine.
    assert selections == [1]
    assert dispatched_nodes == ["node-alpha", "node-alpha"]
    assert assigned == "node-alpha"
    assert outcome.status is NodeJobStatus.SUCCEEDED


async def test_a_failed_job_does_not_keep_reporting_itself_as_dispatched() -> None:
    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch(job: NodeJobRequest) -> NodeJobOutcome:
        raise ApplicationError(
            "dispatch is frozen",
            NodeReason.DISPATCH_FROZEN.value,
            type=NodeReason.DISPATCH_FROZEN.value,
            non_retryable=True,
        )

    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=TASK_QUEUE,
            workflows=[NodeJobWorkflow],
            activities=[select, dispatch],
        ):
            job = request("node-job-status")
            handle = await environment.client.start_workflow(
                NodeJobWorkflow.run, job, id=job.job_id, task_queue=TASK_QUEUE
            )
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), timeout=60)
            reported = await handle.query(NodeJobWorkflow.status)

    assert reported == NodeJobStatus.FAILED.value

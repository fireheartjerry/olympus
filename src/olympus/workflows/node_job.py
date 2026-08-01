import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, CancelledError
from temporalio.workflow import ActivityCancellationType

with workflow.unsafe.imports_passed_through():
    from dataclasses import replace

    from olympus.activities.node_dispatch import NodeDispatchActivities
    from olympus.nodes.dispatch import NodeJobRequest
    from olympus.nodes.errors import NodeReason
    from olympus.nodes.models import NodeJobOutcome, NodeJobStatus

NODE_JOB_WORKFLOW_EXECUTION_TIMEOUT = timedelta(minutes=10)
NODE_JOB_SELECT_SCHEDULE_TO_CLOSE_TIMEOUT = timedelta(seconds=30)
NODE_JOB_SELECT_START_TO_CLOSE_TIMEOUT = timedelta(seconds=10)
NODE_JOB_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT = timedelta(minutes=5)
NODE_JOB_ACTIVITY_START_TO_CLOSE_TIMEOUT = timedelta(minutes=4)
NODE_JOB_ACTIVITY_HEARTBEAT_TIMEOUT = timedelta(seconds=30)
# Section 15 bounds worker recovery at two attempts before the pool circuit-breaks.
NODE_JOB_ACTIVITY_MAXIMUM_ATTEMPTS = 2
# The retry must land after a disconnected node has had time to dial back in.
# The agent's minimum reconnect backoff is two seconds plus jitter, so a retry
# on Temporal's one-second default would always find the node still offline.
NODE_JOB_ACTIVITY_RETRY_INTERVAL = timedelta(seconds=8)


def _retry_policy() -> RetryPolicy:
    return RetryPolicy(
        maximum_attempts=NODE_JOB_ACTIVITY_MAXIMUM_ATTEMPTS,
        initial_interval=NODE_JOB_ACTIVITY_RETRY_INTERVAL,
    )


@workflow.defn
class NodeJobWorkflow:
    """Durable owner of one node job.

    The workflow is the only durable record of the job. It pins the chosen node
    before dispatching, so a retry after a lost connection reaches the same
    machine and replays from that node's dedupe ledger rather than repeating the
    work somewhere else.
    """

    def __init__(self) -> None:
        self._cancel_reason: str = ""
        self._status: str = NodeJobStatus.PENDING.value
        self._node_id: str = ""

    @workflow.run
    async def run(self, request: NodeJobRequest) -> NodeJobOutcome:
        try:
            return await self._run(request)
        except asyncio.CancelledError:
            self._status = NodeJobStatus.CANCELLED.value
            raise
        except BaseException:
            self._status = NodeJobStatus.FAILED.value
            raise

    async def _run(self, request: NodeJobRequest) -> NodeJobOutcome:
        self._node_id = await workflow.execute_activity_method(
            NodeDispatchActivities.select_node,
            request,
            schedule_to_close_timeout=NODE_JOB_SELECT_SCHEDULE_TO_CLOSE_TIMEOUT,
            start_to_close_timeout=NODE_JOB_SELECT_START_TO_CLOSE_TIMEOUT,
            retry_policy=_retry_policy(),
        )
        pinned = replace(request, node_id=self._node_id)

        self._status = NodeJobStatus.DISPATCHED.value
        attempt = asyncio.ensure_future(
            workflow.execute_activity_method(
                NodeDispatchActivities.dispatch_node_job,
                pinned,
                schedule_to_close_timeout=NODE_JOB_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT,
                start_to_close_timeout=NODE_JOB_ACTIVITY_START_TO_CLOSE_TIMEOUT,
                heartbeat_timeout=NODE_JOB_ACTIVITY_HEARTBEAT_TIMEOUT,
                retry_policy=_retry_policy(),
                cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            )
        )
        await workflow.wait_condition(lambda: attempt.done() or bool(self._cancel_reason))
        if not attempt.done():
            attempt.cancel()
            try:
                outcome = await attempt
            except (asyncio.CancelledError, ActivityError, CancelledError):
                # Cancellation was requested here, so the job ends in a declared
                # terminal state rather than as a lost or failed execution.
                self._status = NodeJobStatus.CANCELLED.value
                return NodeJobOutcome(
                    job_id=pinned.job_id,
                    node_id=self._node_id,
                    capability=pinned.capability,
                    dedupe_key=pinned.dedupe_key,
                    status=NodeJobStatus.CANCELLED,
                    attempt=pinned.attempt,
                    reason=NodeReason.JOB_CANCELLED.value,
                    message=self._cancel_reason,
                )
        else:
            outcome = attempt.result()
        self._status = outcome.status.value
        return outcome

    @workflow.signal
    def request_cancellation(self, reason: str) -> None:
        """Ask the node to stop. Reducing work never requires more authority."""
        self._cancel_reason = reason or NodeReason.JOB_CANCELLED.value

    @workflow.query
    def status(self) -> str:
        return self._status

    @workflow.query
    def assigned_node(self) -> str:
        """The node this job was pinned to, or empty before selection completes."""
        return self._node_id

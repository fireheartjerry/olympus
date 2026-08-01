import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, CancelledError
from temporalio.workflow import ActivityCancellationType

with workflow.unsafe.imports_passed_through():
    from olympus.activities.node_dispatch import NodeDispatchActivities
    from olympus.nodes.dispatch import NodeJobRequest
    from olympus.nodes.errors import NodeReason
    from olympus.nodes.models import NodeJobOutcome, NodeJobStatus

NODE_JOB_WORKFLOW_EXECUTION_TIMEOUT = timedelta(minutes=10)
NODE_JOB_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT = timedelta(minutes=5)
NODE_JOB_ACTIVITY_START_TO_CLOSE_TIMEOUT = timedelta(minutes=4)
NODE_JOB_ACTIVITY_HEARTBEAT_TIMEOUT = timedelta(seconds=30)
# Section 15 bounds worker recovery at two attempts before the pool circuit-breaks.
NODE_JOB_ACTIVITY_MAXIMUM_ATTEMPTS = 2


@workflow.defn
class NodeJobWorkflow:
    """Durable owner of one node job.

    The workflow is the only durable record of the job. The dispatch activity
    carries a single attempt to whichever live session currently holds the node;
    if that attempt dies with the connection, Temporal retries it and the node's
    dedupe ledger replays the recorded result instead of repeating the work.
    """

    def __init__(self) -> None:
        self._cancel_reason: str = ""
        self._progress: str = ""
        self._status: str = NodeJobStatus.PENDING.value

    @workflow.run
    async def run(self, request: NodeJobRequest) -> NodeJobOutcome:
        self._status = NodeJobStatus.DISPATCHED.value
        attempt = asyncio.ensure_future(
            workflow.execute_activity_method(
                NodeDispatchActivities.dispatch_node_job,
                request,
                schedule_to_close_timeout=NODE_JOB_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT,
                start_to_close_timeout=NODE_JOB_ACTIVITY_START_TO_CLOSE_TIMEOUT,
                heartbeat_timeout=NODE_JOB_ACTIVITY_HEARTBEAT_TIMEOUT,
                retry_policy=RetryPolicy(maximum_attempts=NODE_JOB_ACTIVITY_MAXIMUM_ATTEMPTS),
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
                    job_id=request.job_id,
                    node_id=request.node_id or "",
                    capability=request.capability,
                    dedupe_key=request.dedupe_key,
                    status=NodeJobStatus.CANCELLED,
                    attempt=request.attempt,
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
    def last_progress(self) -> str:
        return self._progress

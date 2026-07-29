from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from olympus.activities.compile_graph import compile_graph_activity
    from olympus.contracts.commands import CommandEnvelope, CompiledJobReceipt, JobStatus
    from olympus.control.workflow import ControlSnapshot, WorkflowControlState

COMMAND_WORKFLOW_EXECUTION_TIMEOUT = timedelta(seconds=60)
COMPILE_GRAPH_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT = timedelta(seconds=30)
COMPILE_GRAPH_ACTIVITY_START_TO_CLOSE_TIMEOUT = timedelta(seconds=10)
COMPILE_GRAPH_ACTIVITY_MAXIMUM_ATTEMPTS = 3
CONTROL_CHECKPOINT_WAIT_TIMEOUT = timedelta(seconds=55)


@workflow.defn
class CommandWorkflow:
    def __init__(self) -> None:
        self._control = WorkflowControlState()

    @workflow.signal
    async def pause(self, control_id: str) -> None:
        self._control.pause(control_id)

    @workflow.signal
    async def resume(self, control_id: str) -> None:
        self._control.resume(control_id)

    @workflow.signal
    async def cancel(self, control_id: str) -> None:
        self._control.cancel(control_id)

    @workflow.signal
    async def freeze(self, control_id: str) -> None:
        self._control.freeze(control_id)

    @workflow.query
    def inspect(self) -> ControlSnapshot:
        return self._control.snapshot()

    @workflow.run
    async def run(self, command: CommandEnvelope) -> CompiledJobReceipt:
        try:
            await workflow.wait_condition(
                lambda: not self._control.paused or self._control.cancelled or self._control.frozen,
                timeout=CONTROL_CHECKPOINT_WAIT_TIMEOUT,
                timeout_summary="bounded-control-checkpoint",
            )
        except TimeoutError:
            self._control.cancel("control-wait-timeout")
        if self._control.frozen:
            return _terminal_receipt(command, JobStatus.FROZEN)
        if self._control.cancelled:
            return _terminal_receipt(command, JobStatus.CANCELLED)
        graph = await workflow.execute_activity(
            compile_graph_activity,
            command,
            schedule_to_close_timeout=COMPILE_GRAPH_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT,
            start_to_close_timeout=COMPILE_GRAPH_ACTIVITY_START_TO_CLOSE_TIMEOUT,
            retry_policy=RetryPolicy(maximum_attempts=COMPILE_GRAPH_ACTIVITY_MAXIMUM_ATTEMPTS),
        )
        return CompiledJobReceipt(
            job_id=command.job_id,
            status=JobStatus.COMPILED,
            node_count=len(graph.nodes),
            graph_digest=graph.digest,
        )


def _terminal_receipt(command: CommandEnvelope, status: JobStatus) -> CompiledJobReceipt:
    return CompiledJobReceipt(
        job_id=command.job_id,
        status=status,
        node_count=0,
        graph_digest="",
    )

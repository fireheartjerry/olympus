from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from olympus.activities.compile_graph import compile_graph_activity
    from olympus.contracts.commands import CommandEnvelope, CompiledJobReceipt, JobStatus

COMMAND_WORKFLOW_EXECUTION_TIMEOUT = timedelta(seconds=60)
COMPILE_GRAPH_ACTIVITY_SCHEDULE_TO_CLOSE_TIMEOUT = timedelta(seconds=30)
COMPILE_GRAPH_ACTIVITY_START_TO_CLOSE_TIMEOUT = timedelta(seconds=10)
COMPILE_GRAPH_ACTIVITY_MAXIMUM_ATTEMPTS = 3


@workflow.defn
class CommandWorkflow:
    @workflow.run
    async def run(self, command: CommandEnvelope) -> CompiledJobReceipt:
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

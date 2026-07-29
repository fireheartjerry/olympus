from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from olympus.activities.compile_graph import compile_graph_activity
    from olympus.contracts.commands import CommandEnvelope, CompiledJobReceipt, JobStatus


@workflow.defn
class CommandWorkflow:
    @workflow.run
    async def run(self, command: CommandEnvelope) -> CompiledJobReceipt:
        graph = await workflow.execute_activity(
            compile_graph_activity,
            command,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        return CompiledJobReceipt(
            job_id=command.job_id,
            status=JobStatus.COMPILED,
            node_count=len(graph.nodes),
            graph_digest=graph.digest,
        )

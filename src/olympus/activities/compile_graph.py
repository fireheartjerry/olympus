from temporalio import activity

from olympus.contracts.commands import CommandEnvelope
from olympus.graphs.compiler import compile_noop_graph
from olympus.graphs.models import CompiledGraph


@activity.defn
async def compile_graph_activity(command: CommandEnvelope) -> CompiledGraph:
    return compile_noop_graph(command)

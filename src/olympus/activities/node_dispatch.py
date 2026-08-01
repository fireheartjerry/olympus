import asyncio
import contextlib
from dataclasses import replace
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.errors import NodeMeshError, is_permanent_refusal
from olympus.nodes.models import NodeJobOutcome
from olympus.nodes.protocol import JobProgressFrame

DISPATCH_ACTIVITY_NAME = "dispatch-node-job"
ACTIVITY_HEARTBEAT_INTERVAL_SECONDS = 2
_PROGRESS_QUEUE_CAPACITY = 256


class NodeDispatchActivities:
    """Activities that reach live node sessions.

    They are hosted by the process that owns the WebSocket connections, so a
    dispatch never needs a second orchestrator or a side channel. Temporal still
    owns the job's durable state; this activity only carries one attempt of it.
    """

    def __init__(self, *, dispatch: NodeDispatchService) -> None:
        self._dispatch = dispatch

    @activity.defn(name=DISPATCH_ACTIVITY_NAME)
    async def dispatch_node_job(self, request: NodeJobRequest) -> NodeJobOutcome:
        """Place one attempt of a node job and relay its progress as heartbeats."""
        attempt = activity.info().attempt
        scoped = replace(request, attempt=attempt)
        progress: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_PROGRESS_QUEUE_CAPACITY)

        async def on_progress(frame: JobProgressFrame) -> None:
            # The session pump delivers this from its own task, which carries no
            # activity context, so it only enqueues. The heartbeat task below is
            # created inside the activity and therefore inherits that context.
            with contextlib.suppress(asyncio.QueueFull):
                progress.put_nowait(
                    {
                        "job_id": frame.job_id,
                        "sequence": frame.sequence,
                        "percent": frame.percent,
                        "message": frame.message,
                    }
                )

        beat = asyncio.create_task(self._beat(scoped.job_id, progress))
        try:
            return await self._dispatch.run_job(scoped, on_progress=on_progress)
        except NodeMeshError as exc:
            raise ApplicationError(
                exc.message,
                exc.reason.value,
                type=exc.reason.value,
                non_retryable=is_permanent_refusal(exc.reason),
            ) from exc
        finally:
            beat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await beat

    async def _beat(self, job_id: str, progress: asyncio.Queue[dict[str, Any]]) -> None:
        """Heartbeat steadily so a cancellation request reaches this attempt promptly."""
        while True:
            try:
                async with asyncio.timeout(ACTIVITY_HEARTBEAT_INTERVAL_SECONDS):
                    detail = await progress.get()
            except TimeoutError:
                detail = {"job_id": job_id, "alive": True}
            activity.heartbeat(detail)

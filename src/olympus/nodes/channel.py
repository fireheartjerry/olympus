import asyncio
from typing import Protocol

CLOSE_NORMAL = 1000
CLOSE_POLICY_VIOLATION = 1008
CLOSE_MESSAGE_TOO_BIG = 1009


class ChannelClosed(Exception):
    """Raised when a channel is read or written after the peer went away."""

    def __init__(self, reason: str = "channel closed") -> None:
        super().__init__(reason)
        self.reason = reason


class NodeChannel(Protocol):
    """One bidirectional text channel. The protocol is transport independent.

    Production uses a WebSocket the node dialled out to the control plane over;
    tests use an in-memory pair. Both sides of the protocol are written against
    this interface, so the same code runs in both settings.
    """

    async def send(self, payload: str) -> None: ...

    async def receive(self) -> str: ...

    async def close(self, *, code: int = CLOSE_NORMAL, reason: str = "") -> None: ...


class MemoryChannel:
    """In-memory channel half backed by a bounded queue."""

    def __init__(self, *, inbox: asyncio.Queue[str | None], outbox: asyncio.Queue[str | None]):
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False
        self._peer: MemoryChannel | None = None

    @property
    def closed(self) -> bool:
        return self._closed

    async def send(self, payload: str) -> None:
        # Sending to a peer that has gone away fails here exactly as it does on
        # a real socket, so tests written against this channel see the same
        # failure modes production does.
        if self._closed or (self._peer is not None and self._peer.closed):
            raise ChannelClosed("send on a closed channel")
        await self._outbox.put(payload)

    async def receive(self) -> str:
        if self._closed:
            raise ChannelClosed("receive on a closed channel")
        payload = await self._inbox.get()
        if payload is None:
            self._closed = True
            raise ChannelClosed("peer closed the channel")
        return payload

    async def close(self, *, code: int = CLOSE_NORMAL, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        # Notify the peer, then wake any receive already waiting on this half so
        # closing behaves like a real socket shutdown rather than hanging.
        await self._outbox.put(None)
        await self._inbox.put(None)


def create_channel_pair(maxsize: int = 256) -> tuple[MemoryChannel, MemoryChannel]:
    """Return two connected in-memory channel halves."""
    left_to_right: asyncio.Queue[str | None] = asyncio.Queue(maxsize=maxsize)
    right_to_left: asyncio.Queue[str | None] = asyncio.Queue(maxsize=maxsize)
    left = MemoryChannel(inbox=right_to_left, outbox=left_to_right)
    right = MemoryChannel(inbox=left_to_right, outbox=right_to_left)
    left._peer = right
    right._peer = left
    return left, right

import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from olympus.nodes.channel import CLOSE_NORMAL, ChannelClosed
from olympus.nodes.protocol import MAX_FRAME_BYTES

OPEN_TIMEOUT_SECONDS = 20


class WebSocketClientChannel:
    """Node-side channel over an outbound WebSocket connection."""

    def __init__(self, connection: ClientConnection) -> None:
        self._connection = connection

    async def send(self, payload: str) -> None:
        try:
            await self._connection.send(payload)
        except (ConnectionClosed, WebSocketException) as exc:
            raise ChannelClosed("control plane closed the connection") from exc

    async def receive(self) -> str:
        try:
            message = await self._connection.recv()
        except (ConnectionClosed, WebSocketException) as exc:
            raise ChannelClosed("control plane closed the connection") from exc
        return message if isinstance(message, str) else message.decode("utf-8")

    async def close(self, *, code: int = CLOSE_NORMAL, reason: str = "") -> None:
        await self._connection.close(code=code, reason=reason[:120])


@asynccontextmanager
async def open_session_channel(
    url: str, *, ssl_context: ssl.SSLContext | None = None
) -> AsyncIterator[WebSocketClientChannel]:
    """Dial the control plane. Nodes only ever connect outbound; they never listen."""
    try:
        async with connect(
            url,
            ssl=ssl_context,
            max_size=MAX_FRAME_BYTES,
            open_timeout=OPEN_TIMEOUT_SECONDS,
            ping_interval=20,
            ping_timeout=20,
        ) as connection:
            yield WebSocketClientChannel(connection)
    except (OSError, WebSocketException) as exc:
        raise ChannelClosed("could not establish the control-plane session") from exc

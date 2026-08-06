import ssl
from typing import Any

from olympus.node_agent import transport


class FakeConnection:
    async def __aenter__(self) -> "FakeConnection":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


async def test_wss_uses_the_verified_library_default_when_no_context_is_supplied(
    monkeypatch: Any,
) -> None:
    captured: dict[str, object] = {}

    def connect(url: str, **options: object) -> FakeConnection:
        captured.update(options)
        captured["url"] = url
        return FakeConnection()

    monkeypatch.setattr(transport, "connect", connect)

    async with transport.open_session_channel("wss://control.example/session"):
        pass

    assert captured["url"] == "wss://control.example/session"
    assert "ssl" not in captured


async def test_an_explicit_tls_context_is_forwarded(monkeypatch: Any) -> None:
    captured: dict[str, object] = {}

    def connect(url: str, **options: object) -> FakeConnection:
        captured.update(options)
        return FakeConnection()

    monkeypatch.setattr(transport, "connect", connect)
    context = ssl.create_default_context()

    async with transport.open_session_channel("wss://control.example/session", ssl_context=context):
        pass

    assert captured["ssl"] is context

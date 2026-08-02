import json
from dataclasses import replace

import pytest

from olympus.audit_export.exporter import AuditExporter
from olympus.audit_export.models import build_segments
from olympus.audit_export.store import (
    InMemoryWriteOnceStore,
    ObjectAlreadyExists,
    S3ObjectLockStore,
)
from olympus.nodes.audit import AuditAction, AuditDecision, AuditDraft, NodeAuditLog

pytestmark = pytest.mark.asyncio


def _chain(count: int) -> tuple:
    log = NodeAuditLog()
    for index in range(count):
        log.append_draft(
            AuditDraft(
                actor="operator",
                action=AuditAction.SESSION_OPENED,
                decision=AuditDecision.OBSERVE,
                payload={"index": index},
            )
        )
    return log.events()


async def test_export_writes_every_event_and_is_resumable() -> None:
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(store=store, chain="node-mesh", max_events_per_segment=4)

    events = _chain(10)
    first = await exporter.export(events)
    assert first.events_exported == 10
    assert first.segments_written == 3  # 4 + 4 + 2
    assert first.last_exported_sequence == 10

    # Re-running with no new events must write nothing at all.
    again = await exporter.export(events)
    assert again.segments_written == 0
    assert again.events_exported == 0

    # New events append without rewriting anything already stored.
    log = NodeAuditLog()
    log.extend(events)
    log.append_draft(
        AuditDraft(
            actor="operator",
            action=AuditAction.NODE_REVOKED,
            decision=AuditDecision.ALLOW,
        )
    )
    third = await exporter.export(log.events())
    assert third.events_exported == 1
    assert third.last_exported_sequence == 11

    verification = await exporter.verify()
    assert verification.intact is True
    assert verification.events == 11
    assert verification.problems == ()


async def test_exported_objects_are_never_overwritten() -> None:
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(store=store, chain="node-mesh")
    events = _chain(3)
    await exporter.export(events)

    key = next(iter(store.objects))
    with pytest.raises(ObjectAlreadyExists):
        await store.put_once(key, b"rewritten")
    assert b"rewritten" not in store.objects[key]


async def test_a_rewritten_local_chain_is_refused_against_stored_evidence() -> None:
    """Object Lock means the true range is still there to contradict the rewrite."""
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(store=store, chain="node-mesh", max_events_per_segment=10)
    events = _chain(3)
    await exporter.export(events)
    original = dict(store.objects)

    # Rewrite history on the host, then try to export the same range again.
    # The exporter cannot delete or overwrite the stored object, so it must
    # notice that what it holds disagrees with what is already durable.
    tampered = (replace(events[0], actor="attacker"),) + events[1:]
    exporter_after_tamper = AuditExporter(
        store=_ReExportingStore(store), chain="node-mesh", max_events_per_segment=10
    )
    with pytest.raises(RuntimeError, match="may have been rewritten"):
        await exporter_after_tamper.export(tampered)

    # The pre-tamper evidence is untouched.
    assert store.objects == original
    restored = await exporter.restore()
    assert restored[0]["actor"] == "operator"


class _ReExportingStore:
    """Reports nothing exported so the exporter retries an already-stored range."""

    def __init__(self, inner: InMemoryWriteOnceStore) -> None:
        self._inner = inner

    async def put_once(self, key: str, body: bytes) -> None:
        await self._inner.put_once(key, body)

    async def get(self, key: str) -> bytes | None:
        return await self._inner.get(key)

    async def list_keys(self, prefix: str) -> tuple[str, ...]:
        return ()


async def test_verification_detects_a_missing_segment() -> None:
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(store=store, chain="node-mesh", max_events_per_segment=2)
    await exporter.export(_chain(6))
    assert (await exporter.verify()).intact is True

    # Deleting a middle segment is what a partial-loss incident looks like.
    middle = sorted(store.objects)[1]
    del store.objects[middle]

    result = await exporter.verify()
    assert result.intact is False
    assert any("expected" in problem for problem in result.problems)


async def test_verification_detects_a_broken_link_inside_a_segment() -> None:
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(store=store, chain="node-mesh")
    await exporter.export(_chain(4))

    key = next(iter(store.objects))
    document = json.loads(store.objects[key])
    document["events"][2]["previous_hash"] = "f" * 64
    store.objects[key] = json.dumps(document).encode()

    result = await exporter.verify()
    assert result.intact is False
    assert any("does not link" in problem for problem in result.problems)


async def test_restore_returns_the_chain_in_order() -> None:
    store = InMemoryWriteOnceStore()
    exporter = AuditExporter(store=store, chain="node-mesh", max_events_per_segment=3)
    events = _chain(7)
    await exporter.export(events)

    restored = await exporter.restore()
    assert [event["sequence"] for event in restored] == list(range(1, 8))
    assert restored[0]["event_hash"] == events[0].event_hash


async def test_a_gap_in_the_local_chain_is_refused_before_any_write() -> None:
    events = list(_chain(5))
    del events[2]
    with pytest.raises(ValueError, match="gap at sequence"):
        build_segments(events, chain="node-mesh")


async def test_segment_keys_sort_in_sequence_order() -> None:
    segments = build_segments(_chain(2500), chain="node-mesh", max_events=100)
    keys = [segment.key for segment in segments]
    assert keys == sorted(keys)
    assert keys[0].endswith("000000000001-000000000100.json")


async def test_object_lock_store_rejects_an_unsafe_configuration() -> None:
    with pytest.raises(ValueError):
        S3ObjectLockStore(bucket="b", client=object(), retention_days=0)
    with pytest.raises(ValueError):
        S3ObjectLockStore(bucket="b", client=object(), retention_days=1, retention_mode="NONE")


async def test_object_lock_store_writes_with_retention_and_refuses_replacement() -> None:
    class FakeS3:
        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}
            self.calls: list[dict] = []

        def put_object(self, **kwargs):
            self.calls.append(kwargs)
            self.objects[kwargs["Key"]] = kwargs["Body"]

        def get_object(self, Bucket, Key):  # noqa: N803 - boto3 casing
            if Key not in self.objects:
                raise _NoSuchKey()
            return {"Body": _Body(self.objects[Key])}

        def list_objects_v2(self, **kwargs):
            prefix = kwargs.get("Prefix", "")
            contents = [{"Key": key} for key in sorted(self.objects) if key.startswith(prefix)]
            return {"Contents": contents, "IsTruncated": False}

    class _NoSuchKey(Exception):
        response = {"Error": {"Code": "NoSuchKey"}}

    class _Body:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

    client = FakeS3()
    store = S3ObjectLockStore(
        bucket="olympus-audit", client=client, retention_days=30, retention_mode="COMPLIANCE"
    )
    exporter = AuditExporter(store=store, chain="node-mesh")
    result = await exporter.export(_chain(3))
    assert result.events_exported == 3

    call = client.calls[0]
    assert call["ObjectLockMode"] == "COMPLIANCE"
    assert call["ObjectLockRetainUntilDate"] is not None
    assert call["IfNoneMatch"] == "*"
    assert call["ChecksumSHA256"]

    with pytest.raises(ObjectAlreadyExists):
        await store.put_once(call["Key"], b"different")

    assert (await exporter.verify()).intact is True

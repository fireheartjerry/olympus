import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from olympus.audit_export.models import (
    GENESIS_HASH,
    ExportSegment,
    build_segments,
)
from olympus.audit_export.store import (
    ObjectAlreadyExists,
    WriteOnceObjectStore,
)


@dataclass(frozen=True)
class ExportResult:
    """What one export run put off-host."""

    chain: str
    segments_written: int
    events_exported: int
    last_exported_sequence: int
    already_present: tuple[str, ...] = ()

    @property
    def exported(self) -> bool:
        return self.segments_written > 0


@dataclass(frozen=True)
class VerificationResult:
    """Whether what is off-host is a complete, unbroken chain."""

    chain: str
    segments: int
    events: int
    last_sequence: int
    intact: bool
    problems: tuple[str, ...] = ()


class AuditExporter:
    """Copies a hash-chained audit log into write-once object storage.

    The on-host chain is tamper-*evident*: anyone who can write the database
    can rewrite history, and the chain only makes that detectable. Exporting
    each run to storage the control plane cannot overwrite or delete makes the
    rewrite *recoverable* as well, because the pre-tamper events still exist
    somewhere the attacker's database access does not reach.
    """

    def __init__(
        self, *, store: WriteOnceObjectStore, chain: str, max_events_per_segment: int = 500
    ) -> None:
        if not chain.strip():
            raise ValueError("chain must not be empty")
        self._store = store
        self._chain = chain
        self._max_events = max_events_per_segment

    @property
    def prefix(self) -> str:
        return f"audit/{self._chain}/"

    async def last_exported_sequence(self) -> int:
        """Read the high-water mark from storage rather than from local state.

        Storage is the authority on what is durable off-host. A locally cached
        cursor could disagree with reality after a crash, and disagreeing in
        the optimistic direction would silently skip events forever.
        """
        keys = await self._store.list_keys(self.prefix)
        if not keys:
            return 0
        last = keys[-1].rsplit("/", 1)[-1].removesuffix(".json")
        return int(last.split("-")[1])

    async def export(self, events: Sequence[Any]) -> ExportResult:
        """Append every not-yet-exported event, skipping ranges already stored."""
        start_after = await self.last_exported_sequence()
        segments = build_segments(
            events,
            chain=self._chain,
            start_after=start_after,
            max_events=self._max_events,
        )
        if not segments:
            return ExportResult(
                chain=self._chain,
                segments_written=0,
                events_exported=0,
                last_exported_sequence=start_after,
            )

        written = 0
        exported = 0
        present: list[str] = []
        last_sequence = start_after
        for segment in segments:
            try:
                await self._store.put_once(segment.key, segment.body())
                written += 1
                exported += len(segment.events)
            except ObjectAlreadyExists:
                # Two exporters raced, or a previous run committed the object
                # after its cursor read. Either way the range is already
                # durable; confirm it matches rather than assuming it does.
                stored = await self._store.get(segment.key)
                if stored != segment.body():
                    raise RuntimeError(
                        f"stored segment {segment.key} differs from the local chain; "
                        "the on-host audit log may have been rewritten"
                    ) from None
                present.append(segment.key)
            last_sequence = segment.last_sequence

        return ExportResult(
            chain=self._chain,
            segments_written=written,
            events_exported=exported,
            last_exported_sequence=last_sequence,
            already_present=tuple(present),
        )

    async def verify(self) -> VerificationResult:
        """Re-read every exported segment and confirm the chain is unbroken.

        This is the recovery-time question — "is the off-host copy trustworthy
        and complete?" — so it reads storage back rather than trusting
        anything the control plane holds.
        """
        keys = await self._store.list_keys(self.prefix)
        problems: list[str] = []
        expected_sequence = 1
        expected_previous = GENESIS_HASH
        events = 0
        last_sequence = 0

        for key in keys:
            raw = await self._store.get(key)
            if raw is None:
                problems.append(f"{key}: listed but unreadable")
                continue
            try:
                document = json.loads(raw)
            except json.JSONDecodeError as exc:
                problems.append(f"{key}: unparseable ({exc.msg})")
                continue

            first = document["first_sequence"]
            last = document["last_sequence"]
            if first != expected_sequence:
                problems.append(
                    f"{key}: starts at {first}, expected {expected_sequence} "
                    "(a segment is missing or duplicated)"
                )
            if document["first_previous_hash"] != expected_previous:
                problems.append(f"{key}: does not link to the preceding segment")
            segment_events = document["events"]
            if len(segment_events) != last - first + 1:
                problems.append(f"{key}: event count does not match its range")

            # Re-link every event inside the segment.
            previous = document["first_previous_hash"]
            for event in segment_events:
                if event["previous_hash"] != previous:
                    problems.append(
                        f"{key}: event {event.get('sequence')} does not link to its predecessor"
                    )
                    break
                previous = event["event_hash"]
            else:
                if previous != document["last_event_hash"]:
                    problems.append(f"{key}: last_event_hash does not match its events")

            events += len(segment_events)
            expected_sequence = last + 1
            expected_previous = document["last_event_hash"]
            last_sequence = last

        return VerificationResult(
            chain=self._chain,
            segments=len(keys),
            events=events,
            last_sequence=last_sequence,
            intact=not problems,
            problems=tuple(problems),
        )

    async def restore(self) -> tuple[dict[str, Any], ...]:
        """Return every exported event in order, for rebuilding after a loss."""
        restored: list[dict[str, Any]] = []
        for key in await self._store.list_keys(self.prefix):
            raw = await self._store.get(key)
            if raw is None:
                continue
            restored.extend(json.loads(raw)["events"])
        restored.sort(key=lambda event: event["sequence"])
        return tuple(restored)


def segment_from_bytes(raw: bytes) -> ExportSegment:
    """Rebuild a segment from its stored bytes, for offline inspection."""
    document = json.loads(raw)
    return ExportSegment(
        chain=document["chain"],
        first_sequence=document["first_sequence"],
        last_sequence=document["last_sequence"],
        first_previous_hash=document["first_previous_hash"],
        last_event_hash=document["last_event_hash"],
        events=tuple(document["events"]),
    )

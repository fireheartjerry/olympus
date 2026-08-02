import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from olympus.audit_export.models import (
    GENESIS_HASH,
    ExportSegment,
    build_segments,
)
from olympus.audit_export.signing import (
    ChainVerification,
    Keyring,
    SegmentSigner,
    StoredSegmentEvidence,
    build_attestation,
    sign_segment,
    signature_key_for,
    verify_exported_chain,
)
from olympus.audit_export.store import (
    ObjectAlreadyExists,
    WriteOnceObjectStore,
)

SIGNATURE_SUFFIX = ".sig.json"


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
        self,
        *,
        store: WriteOnceObjectStore,
        chain: str,
        max_events_per_segment: int = 500,
        signer: SegmentSigner | None = None,
        bucket: str = "",
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not chain.strip():
            raise ValueError("chain must not be empty")
        if signer is not None and not bucket.strip():
            raise ValueError("a signing exporter must know which bucket it is attesting to")
        self._store = store
        self._chain = chain
        self._max_events = max_events_per_segment
        self._signer = signer
        self._bucket = bucket
        self._now = now if now is not None else (lambda: datetime.now(UTC))

    @property
    def prefix(self) -> str:
        return f"audit/{self._chain}/"

    @property
    def signs(self) -> bool:
        return self._signer is not None

    async def _segment_keys(self) -> tuple[str, ...]:
        """Every segment key under this chain, excluding signature sidecars.

        Sidecars share the prefix, so anything that treats a raw listing as a
        list of segments would try to parse ``...-000000000005.json.sig.json``
        as a sequence range and would count each segment twice.
        """
        keys = await self._store.list_keys(self.prefix)
        return tuple(key for key in keys if not key.endswith(SIGNATURE_SUFFIX))

    async def last_exported_sequence(self) -> int:
        """Read the high-water mark from storage rather than from local state.

        Storage is the authority on what is durable off-host. A locally cached
        cursor could disagree with reality after a crash, and disagreeing in
        the optimistic direction would silently skip events forever.
        """
        keys = await self._segment_keys()
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
                identity = await self._store.put_once(segment.key, segment.body())
                await self._attest(segment, identity)
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

    async def _attest(self, segment: ExportSegment, identity: Any) -> None:
        """Sign the segment that was just sealed and store the attestation beside it.

        This happens after the write, not before, because the attestation binds
        the object's version ID and retention — facts that do not exist until
        the object does. The sidecar is itself written write-once, so a later
        compromise can no more replace a signature than it can replace the
        bytes the signature covers.
        """
        if self._signer is None:
            return
        attestation = build_attestation(
            chain=segment.chain,
            first_sequence=segment.first_sequence,
            last_sequence=segment.last_sequence,
            first_previous_hash=segment.first_previous_hash,
            last_event_hash=segment.last_event_hash,
            segment_body=segment.body(),
            bucket=self._bucket,
            object_key=segment.key,
            version_id=identity.version_id,
            retention_mode=identity.retention_mode,
            retention_until=identity.retention_until,
            signer_key_id=self._signer.key_id,
            signed_at=self._now(),
        )
        signed = await sign_segment(attestation=attestation, signer=self._signer)
        await self._store.put_once(signature_key_for(segment.key), signed.document())

    async def collect_evidence(self) -> tuple[StoredSegmentEvidence, ...]:
        """Gather exactly what an offline verifier needs, and nothing else.

        Everything returned here is bytes plus object identity. There is no
        handle to the store, no client, and no credential, so the result can be
        written to a directory, carried to another machine, and checked there.
        """
        evidence: list[StoredSegmentEvidence] = []
        for key in await self._segment_keys():
            segment_body = await self._store.get(key)
            sidecar_body = await self._store.get(signature_key_for(key))
            identity = await self._store.head(key)
            if segment_body is None or sidecar_body is None or identity is None:
                raise RuntimeError(
                    f"{key}: cannot assemble verification evidence "
                    "(segment, signature, or object identity is missing)"
                )
            evidence.append(
                StoredSegmentEvidence(
                    object_key=key,
                    version_id=identity.version_id,
                    segment_body=segment_body,
                    sidecar_body=sidecar_body,
                )
            )
        return tuple(evidence)

    async def verify_authenticity(self, keyring: Keyring) -> ChainVerification:
        """Ask the key-backed question, which ``verify`` deliberately does not.

        ``verify`` establishes that the exported chain is internally
        consistent. This establishes that Olympus is who wrote it. Keeping them
        as two calls keeps the two claims from being confused for one.
        """
        return verify_exported_chain(
            evidence=await self.collect_evidence(),
            keyring=keyring,
            bucket=self._bucket,
            chain=self._chain,
            genesis_hash=GENESIS_HASH,
        )

    async def verify(self) -> VerificationResult:
        """Re-read every exported segment and confirm the chain is unbroken.

        This is the recovery-time question — "is the off-host copy trustworthy
        and complete?" — so it reads storage back rather than trusting
        anything the control plane holds.
        """
        keys = await self._segment_keys()
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
        for key in await self._segment_keys():
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

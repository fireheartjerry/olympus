import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

SEGMENT_FORMAT_VERSION = 1
GENESIS_HASH = "0" * 64


class ChainedEvent(Protocol):
    """The minimum every Olympus audit chain exposes: a sequence and two links.

    Only these three attributes are common. Beyond them the chains diverge —
    the node-mesh log exposes ``body()`` and hex hashes, the authority log a
    canonical JSON ``body`` string and raw bytes hashes — so ``_as_mapping``
    and ``_hash_to_hex`` do the reconciling. Assuming more than this protocol
    guarantees is what broke the first real authority export.
    """

    @property
    def sequence(self) -> int: ...

    @property
    def previous_hash(self) -> str: ...

    @property
    def event_hash(self) -> str: ...


@dataclass(frozen=True)
class ExportSegment:
    """One immutable, contiguous run of audit events bound for object storage.

    A segment is the unit of export because per-event objects would multiply
    request cost without adding evidence: the hash chain already binds events
    to each other, so what storage must preserve is the run and its endpoints.
    """

    chain: str
    first_sequence: int
    last_sequence: int
    first_previous_hash: str
    last_event_hash: str
    events: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        if self.first_sequence < 1:
            raise ValueError("first_sequence must be strictly positive")
        if self.last_sequence < self.first_sequence:
            raise ValueError("last_sequence must not precede first_sequence")
        if len(self.events) != self.last_sequence - self.first_sequence + 1:
            raise ValueError("segment event count does not match its sequence range")
        if not self.chain.strip():
            raise ValueError("chain must not be empty")

    @property
    def key(self) -> str:
        """Deterministic, lexicographically ordered object key.

        Zero padding keeps `list_objects` order identical to sequence order,
        so a reader never has to sort by parsing, and a gap is visible as a
        break in the printed range rather than something only arithmetic finds.
        """
        return f"audit/{self.chain}/{self.first_sequence:012d}-{self.last_sequence:012d}.json"

    def body(self) -> bytes:
        """Serialize the segment canonically so the same range hashes the same."""
        document = {
            "version": SEGMENT_FORMAT_VERSION,
            "chain": self.chain,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "first_previous_hash": self.first_previous_hash,
            "last_event_hash": self.last_event_hash,
            "events": [dict(event) for event in self.events],
        }
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.body()).hexdigest()


def build_segments(
    events: Sequence[Any], *, chain: str, start_after: int = 0, max_events: int = 500
) -> tuple[ExportSegment, ...]:
    """Split an in-order chain into contiguous segments not yet exported.

    Events at or below ``start_after`` are already durable off-host and are
    never rewritten: Object Lock would refuse the overwrite anyway, and an
    exporter that retries the whole chain each run would turn a cheap append
    into an unbounded one.
    """
    pending = [event for event in events if event.sequence > start_after]
    if not pending:
        return ()
    pending.sort(key=lambda event: event.sequence)

    expected = pending[0].sequence
    for event in pending:
        if event.sequence != expected:
            raise ValueError(f"audit chain has a gap at sequence {expected}; refusing to export")
        expected += 1

    segments: list[ExportSegment] = []
    for offset in range(0, len(pending), max_events):
        window = pending[offset : offset + max_events]
        segments.append(
            ExportSegment(
                chain=chain,
                first_sequence=window[0].sequence,
                last_sequence=window[-1].sequence,
                first_previous_hash=_hash_to_hex(window[0].previous_hash),
                last_event_hash=_hash_to_hex(window[-1].event_hash),
                events=tuple(_as_mapping(event) for event in window),
            )
        )
    return tuple(segments)


def _hash_to_hex(value: Any) -> str:
    """Normalize a chain hash to lowercase hex.

    The two Olympus chains store hashes differently — the node-mesh log keeps
    hex text, the authority log keeps raw bytes — and JSON can represent only
    one of those. Normalizing here rather than at each call site means an
    exported segment has a single spelling regardless of which chain produced
    it, which is what lets a verifier compare links across them at all.
    """
    if isinstance(value, bytes | bytearray):
        return bytes(value).hex()
    return str(value)


def _as_mapping(event: Any) -> Mapping[str, Any]:
    """Render one audit event as the mapping that gets serialized and signed.

    Both chains are supported, and they are genuinely different shapes: the
    node-mesh event exposes ``body()`` returning a dict, while the authority
    event carries ``body`` as canonical JSON *text* with bytes hashes. Whatever
    the source, the result always carries ``sequence``, ``previous_hash``, and
    ``event_hash`` as hex, because verification re-links events using exactly
    those three fields.
    """
    if isinstance(event, Mapping):
        return dict(event)

    body = getattr(event, "body", None)

    if callable(body):
        mapping = dict(body())
        mapping["event_hash"] = _hash_to_hex(event.event_hash)
        mapping["previous_hash"] = _hash_to_hex(mapping.get("previous_hash", event.previous_hash))
        return mapping

    if body is not None:
        # The authority chain hashes a canonical JSON string. It is parsed back
        # into structure here so the exported segment stays one document rather
        # than a document with JSON smuggled inside a string field; the hash
        # that binds it is carried alongside either way.
        return {
            "sequence": event.sequence,
            "event_type": getattr(event, "event_type", ""),
            "body": json.loads(body) if isinstance(body, str) else body,
            "previous_hash": _hash_to_hex(event.previous_hash),
            "event_hash": _hash_to_hex(event.event_hash),
        }

    from dataclasses import asdict, is_dataclass

    if is_dataclass(event) and not isinstance(event, type):
        return asdict(event)
    raise TypeError(f"cannot serialize audit event of type {type(event)!r}")

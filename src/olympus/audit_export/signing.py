"""Key-backed authenticity for exported audit segments.

The hash chain already answers *"is this run internally consistent?"*. It
cannot answer *"did Olympus write this?"* — anyone who can produce bytes can
produce a self-consistent chain, because every hash in it is computed from the
bytes they chose. Signing closes that gap: a segment carries an Ed25519
signature made by a KMS key the exporter can use but cannot read, export, or
delete, over a statement that names the exact object the bytes live in.

The two properties stay distinct on purpose and are checked separately:

* **Integrity** (hash chain) — the events are contiguous and unmodified
  relative to each other.
* **Authenticity** (this module) — a specific trusted key attested to these
  exact bytes, at this exact object identity, at a time when that key was
  still trusted.

Neither implies the other. A perfectly linked chain with no valid signature is
unattributed. A validly signed segment that does not link to its predecessor is
authentic but out of place. Verification refuses both.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

SIGNATURE_SCHEMA_VERSION = 1
SIGNING_ALGORITHM = "ED25519_SHA_512"

# Domain separation. A signature is only ever meaningful as an audit-segment
# attestation, so the signed bytes begin with a context string no other Olympus
# protocol uses. Without it, a signature produced for some future message type
# under the same key could be replayed here.
_ATTESTATION_CONTEXT = b"olympus.audit-export.segment-attestation.v1"

# KMS refuses a RAW message larger than this, and the attestation is designed
# to stay far below it: the segment itself is bound by digest, not by value.
_MAX_STATEMENT_BYTES = 4096


class SignatureError(Exception):
    """Base class for every reason a segment's authenticity is not established."""


class UnknownSigner(SignatureError):
    """The attestation names a key that is not in the pinned trust store."""


class UntrustedSigner(SignatureError):
    """The named key is known but was not trusted when it signed."""


class ObjectIdentityMismatch(SignatureError):
    """The attestation describes a different object than the one presented."""


class SegmentDigestMismatch(SignatureError):
    """The segment bytes do not hash to the value the attestation covers."""


class ChainLinkMismatch(SignatureError):
    """The segment does not continue the chain the verifier is following."""


class InvalidSignature(SignatureError):
    """The signature does not verify under the pinned public key."""


class MalformedAttestation(SignatureError):
    """The sidecar document is not a well-formed attestation."""


@dataclass(frozen=True)
class SegmentAttestation:
    """Everything a signature commits to, beyond the segment bytes themselves.

    Each field exists to defeat a specific substitution. Dropping any one of
    them makes some rearrangement of otherwise-valid material verify:

    * ``segment_sha256`` — modified bytes.
    * ``first_previous_hash`` / ``last_event_hash`` — a segment spliced in with
      the wrong predecessor.
    * ``chain`` / ``first_sequence`` / ``last_sequence`` — a real segment
      replayed at the wrong position, or one chain's segment offered as
      another's.
    * ``bucket`` / ``object_key`` / ``version_id`` — the right bytes presented
      as a different stored object, which is how a rollback to a superseded
      version would otherwise pass.
    * ``retention_mode`` / ``retention_until`` — a segment that was never
      actually sealed being passed off as one that was.
    * ``signer_key_id`` — which key's authority is being claimed, so trust is
      resolved against a pinned identity rather than whatever key happens to
      verify.
    * ``signed_at`` — when the claim was made, so revocation and expiry are
      decidable.
    """

    schema_version: int
    chain: str
    first_sequence: int
    last_sequence: int
    first_previous_hash: str
    last_event_hash: str
    segment_sha256: str
    bucket: str
    object_key: str
    version_id: str
    retention_mode: str
    retention_until: str
    signer_key_id: str
    signed_at: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "chain": self.chain,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "first_previous_hash": self.first_previous_hash,
            "last_event_hash": self.last_event_hash,
            "segment_sha256": self.segment_sha256,
            "bucket": self.bucket,
            "object_key": self.object_key,
            "version_id": self.version_id,
            "retention_mode": self.retention_mode,
            "retention_until": self.retention_until,
            "signer_key_id": self.signer_key_id,
            "signed_at": self.signed_at,
        }

    def statement(self) -> bytes:
        """The exact bytes that get signed.

        Canonicalization is the whole point: the verifier reconstructs these
        bytes from parsed fields, so any encoding freedom — key order, spacing,
        unicode escaping — would let two different documents share one
        signature. Sorted keys with no insignificant whitespace leaves exactly
        one encoding per value.
        """
        body = json.dumps(
            self.to_mapping(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        statement = _ATTESTATION_CONTEXT + b"\n" + body
        if len(statement) > _MAX_STATEMENT_BYTES:
            raise MalformedAttestation("attestation statement exceeds the signable size")
        return statement

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> SegmentAttestation:
        expected = set(cls.__dataclass_fields__)
        present = set(document)
        if present != expected:
            missing = sorted(expected - present)
            extra = sorted(present - expected)
            raise MalformedAttestation(
                "attestation fields do not match the schema "
                f"(missing={missing}, unexpected={extra})"
            )
        try:
            attestation = cls(
                schema_version=int(document["schema_version"]),
                chain=str(document["chain"]),
                first_sequence=int(document["first_sequence"]),
                last_sequence=int(document["last_sequence"]),
                first_previous_hash=str(document["first_previous_hash"]),
                last_event_hash=str(document["last_event_hash"]),
                segment_sha256=str(document["segment_sha256"]),
                bucket=str(document["bucket"]),
                object_key=str(document["object_key"]),
                version_id=str(document["version_id"]),
                retention_mode=str(document["retention_mode"]),
                retention_until=str(document["retention_until"]),
                signer_key_id=str(document["signer_key_id"]),
                signed_at=str(document["signed_at"]),
            )
        except (TypeError, ValueError) as exc:
            raise MalformedAttestation(f"attestation field has the wrong type: {exc}") from exc
        if attestation.schema_version != SIGNATURE_SCHEMA_VERSION:
            raise MalformedAttestation(
                f"unsupported attestation schema version {attestation.schema_version}"
            )
        return attestation


@dataclass(frozen=True)
class SignedSegment:
    """An attestation together with the signature over it."""

    attestation: SegmentAttestation
    signature: bytes

    def document(self) -> bytes:
        return json.dumps(
            {
                "schema_version": SIGNATURE_SCHEMA_VERSION,
                "signing_algorithm": SIGNING_ALGORITHM,
                "attestation": self.attestation.to_mapping(),
                "signature": base64.b64encode(self.signature).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> SignedSegment:
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MalformedAttestation(f"signature sidecar is not JSON: {exc.msg}") from exc
        if not isinstance(document, dict):
            raise MalformedAttestation("signature sidecar must be a JSON object")
        if document.get("signing_algorithm") != SIGNING_ALGORITHM:
            raise MalformedAttestation(
                f"unsupported signing algorithm {document.get('signing_algorithm')!r}"
            )
        attestation_body = document.get("attestation")
        if not isinstance(attestation_body, dict):
            raise MalformedAttestation("signature sidecar has no attestation object")
        try:
            signature = base64.b64decode(str(document["signature"]), validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise MalformedAttestation("signature is not valid base64") from exc
        if len(signature) != 64:
            raise MalformedAttestation("an Ed25519 signature must be 64 bytes")
        return cls(
            attestation=SegmentAttestation.from_mapping(attestation_body),
            signature=signature,
        )


def signature_key_for(object_key: str) -> str:
    """The sidecar key for a segment.

    A sidecar rather than an embedded field because the segment bytes must be
    hashed *before* they can be signed, and rewriting the object to embed the
    result is exactly what Object Lock forbids.
    """
    return f"{object_key}.sig.json"


class SegmentSigner(Protocol):
    """The narrow signing surface. Deliberately cannot verify or read a key."""

    @property
    def key_id(self) -> str: ...

    async def sign(self, statement: bytes) -> bytes: ...


class KmsEd25519Signer:
    """Signs through AWS KMS, which holds a private key nobody can extract.

    The exporter is granted ``kms:Sign`` on this one key ARN and nothing else —
    no ``GetPublicKey``, because verification uses the pinned public key rather
    than asking the service, and an offline verifier that has to call AWS is
    not offline.
    """

    def __init__(self, *, key_id: str, client: Any) -> None:
        if not key_id.strip():
            raise ValueError("key_id must not be empty")
        self._key_id = key_id
        self._client = client

    @property
    def key_id(self) -> str:
        return self._key_id

    async def sign(self, statement: bytes) -> bytes:
        import asyncio

        def _sign() -> bytes:
            response = self._client.sign(
                KeyId=self._key_id,
                Message=statement,
                MessageType="RAW",
                SigningAlgorithm=SIGNING_ALGORITHM,
            )
            signature: bytes = response["Signature"]
            return signature

        signature = await asyncio.to_thread(_sign)
        if len(signature) != 64:
            raise SignatureError("KMS returned a signature that is not raw Ed25519")
        return signature


class LocalEd25519Signer:
    """An in-process signer for tests.

    It produces signatures the real verifier accepts, so a test proves the
    verification logic rather than proving a stub agrees with itself.
    """

    def __init__(self, *, key_id: str, private_key: Any | None = None) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._key_id = key_id
        self._private_key = private_key if private_key is not None else Ed25519PrivateKey.generate()

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_der(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        der: bytes = self._private_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return der

    async def sign(self, statement: bytes) -> bytes:
        signature: bytes = self._private_key.sign(statement)
        return signature


@dataclass(frozen=True)
class TrustedSigner:
    """A pinned public identity and the window in which it was trusted."""

    key_id: str
    public_key_der: bytes
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        for name in ("not_before", "not_after", "revoked_at"):
            value = getattr(self, name)
            if value is not None and value.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.not_after <= self.not_before:
            raise ValueError("not_after must follow not_before")

    def assert_trusted_at(self, moment: datetime) -> None:
        if moment < self.not_before:
            raise UntrustedSigner(
                f"{self.key_id} signed at {moment.isoformat()}, before it was trusted"
            )
        if moment > self.not_after:
            raise UntrustedSigner(f"{self.key_id} was expired at {moment.isoformat()}")
        if self.revoked_at is not None and moment >= self.revoked_at:
            raise UntrustedSigner(
                f"{self.key_id} was revoked at {self.revoked_at.isoformat()}; "
                f"the signature claims {moment.isoformat()}"
            )


@dataclass(frozen=True)
class Keyring:
    """The pinned trust store an offline verifier is given.

    Trust is pinned rather than discovered. Fetching the public key from KMS at
    verification time would mean an attacker who controls the AWS account can
    also control what "valid" means, which is the failure the off-host copy
    exists to survive.
    """

    signers: Mapping[str, TrustedSigner]

    def resolve(self, key_id: str) -> TrustedSigner:
        signer = self.signers.get(key_id)
        if signer is None:
            raise UnknownSigner(f"{key_id} is not a pinned Olympus audit signer")
        return signer


def _parse_timestamp(value: str, *, field: str) -> datetime:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise MalformedAttestation(f"{field} is not an ISO-8601 timestamp: {value!r}") from exc
    if moment.tzinfo is None:
        raise MalformedAttestation(f"{field} must carry a UTC offset")
    return moment


def build_attestation(
    *,
    chain: str,
    first_sequence: int,
    last_sequence: int,
    first_previous_hash: str,
    last_event_hash: str,
    segment_body: bytes,
    bucket: str,
    object_key: str,
    version_id: str,
    retention_mode: str,
    retention_until: str,
    signer_key_id: str,
    signed_at: datetime,
) -> SegmentAttestation:
    if signed_at.tzinfo is None:
        raise ValueError("signed_at must be timezone-aware")
    return SegmentAttestation(
        schema_version=SIGNATURE_SCHEMA_VERSION,
        chain=chain,
        first_sequence=first_sequence,
        last_sequence=last_sequence,
        first_previous_hash=first_previous_hash,
        last_event_hash=last_event_hash,
        segment_sha256=hashlib.sha256(segment_body).hexdigest(),
        bucket=bucket,
        object_key=object_key,
        version_id=version_id,
        retention_mode=retention_mode,
        retention_until=retention_until,
        signer_key_id=signer_key_id,
        signed_at=signed_at.astimezone(UTC).isoformat(),
    )


async def sign_segment(*, attestation: SegmentAttestation, signer: SegmentSigner) -> SignedSegment:
    if attestation.signer_key_id != signer.key_id:
        raise SignatureError(
            "attestation names a different key than the signer being used; "
            "refusing to produce a signature that misattributes itself"
        )
    signature = await signer.sign(attestation.statement())
    return SignedSegment(attestation=attestation, signature=signature)


def verify_signed_segment(
    *,
    segment_body: bytes,
    sidecar_body: bytes,
    keyring: Keyring,
    bucket: str,
    object_key: str,
    version_id: str,
    expected_previous_hash: str | None = None,
    expected_first_sequence: int | None = None,
    expected_chain: str | None = None,
) -> SegmentAttestation:
    """Establish that these exact bytes, at this exact object, were signed.

    Purely local: it takes bytes and a pinned keyring and calls nothing. That
    is the point — the evidence has to hold up on a machine that has no
    credentials for, and no reachability to, the account that produced it.
    """
    signed = SignedSegment.from_bytes(sidecar_body)
    attestation = signed.attestation

    # Identity before cryptography: a signature that verifies over a statement
    # about some *other* object has told us nothing about this one.
    if attestation.bucket != bucket:
        raise ObjectIdentityMismatch(
            f"attestation covers bucket {attestation.bucket!r}, presented as {bucket!r}"
        )
    if attestation.object_key != object_key:
        raise ObjectIdentityMismatch(
            f"attestation covers key {attestation.object_key!r}, presented as {object_key!r}"
        )
    if attestation.version_id != version_id:
        raise ObjectIdentityMismatch(
            f"attestation covers version {attestation.version_id!r}, presented as {version_id!r}"
        )

    actual_digest = hashlib.sha256(segment_body).hexdigest()
    if actual_digest != attestation.segment_sha256:
        raise SegmentDigestMismatch(
            f"{object_key}: stored bytes hash to {actual_digest}, "
            f"attestation covers {attestation.segment_sha256}"
        )

    if expected_chain is not None and attestation.chain != expected_chain:
        raise ChainLinkMismatch(
            f"{object_key}: segment belongs to chain {attestation.chain!r}, "
            f"expected {expected_chain!r}"
        )
    if (
        expected_first_sequence is not None
        and attestation.first_sequence != expected_first_sequence
    ):
        raise ChainLinkMismatch(
            f"{object_key}: segment starts at {attestation.first_sequence}, "
            f"expected {expected_first_sequence} (a segment is missing, duplicated, or reordered)"
        )
    if (
        expected_previous_hash is not None
        and attestation.first_previous_hash != expected_previous_hash
    ):
        raise ChainLinkMismatch(f"{object_key}: segment does not continue the verified predecessor")

    signer = keyring.resolve(attestation.signer_key_id)
    signer.assert_trusted_at(_parse_timestamp(attestation.signed_at, field="signed_at"))

    from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    public_key = load_der_public_key(signer.public_key_der)
    if not isinstance(public_key, Ed25519PublicKey):
        raise UntrustedSigner(f"{signer.key_id} is pinned as a non-Ed25519 key")
    try:
        public_key.verify(signed.signature, attestation.statement())
    except _CryptoInvalidSignature as exc:
        raise InvalidSignature(
            f"{object_key}: signature does not verify under pinned key {signer.key_id}"
        ) from exc

    return attestation


@dataclass(frozen=True)
class StoredSegmentEvidence:
    """One segment as an offline verifier receives it: bytes plus identity."""

    object_key: str
    version_id: str
    segment_body: bytes
    sidecar_body: bytes


@dataclass(frozen=True)
class ChainVerification:
    chain: str
    segments: int
    events: int
    last_sequence: int
    authentic: bool
    problems: tuple[str, ...] = ()


def verify_exported_chain(
    *,
    evidence: Sequence[StoredSegmentEvidence],
    keyring: Keyring,
    bucket: str,
    chain: str,
    genesis_hash: str,
) -> ChainVerification:
    """Verify authenticity *and* linkage across a whole exported chain.

    Order matters and is not taken on trust: each segment must both continue
    the previously verified segment and be signed as starting exactly where the
    verifier expects. Reordering two otherwise-valid segments therefore fails
    even though each one's signature is individually perfect.
    """
    problems: list[str] = []
    expected_sequence = 1
    expected_previous = genesis_hash
    events = 0
    last_sequence = 0

    for item in evidence:
        try:
            attestation = verify_signed_segment(
                segment_body=item.segment_body,
                sidecar_body=item.sidecar_body,
                keyring=keyring,
                bucket=bucket,
                object_key=item.object_key,
                version_id=item.version_id,
                expected_previous_hash=expected_previous,
                expected_first_sequence=expected_sequence,
                expected_chain=chain,
            )
        except SignatureError as exc:
            problems.append(f"{item.object_key}: {exc}")
            # The chain's state is now unknown, so continuing would report
            # cascading nonsense about every later segment.
            break

        events += attestation.last_sequence - attestation.first_sequence + 1
        last_sequence = attestation.last_sequence
        expected_sequence = attestation.last_sequence + 1
        expected_previous = attestation.last_event_hash

    return ChainVerification(
        chain=chain,
        segments=len(evidence),
        events=events,
        last_sequence=last_sequence,
        authentic=not problems,
        problems=tuple(problems),
    )

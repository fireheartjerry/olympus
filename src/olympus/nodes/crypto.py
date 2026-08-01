import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from olympus.nodes.errors import NodeMeshError, NodeReason

_ENROLLMENT_PREFIX = "olynode"
_ENROLLMENT_HASH_DOMAIN = b"olympus-node-enrollment-v1"
_DEDUPE_HASH_DOMAIN = "olympus-node-dedupe-v1"
_ENROLLMENT_ID_BYTES = 8
_ENROLLMENT_SECRET_BYTES = 32
NONCE_BYTES = 32
_ED25519_RAW_KEY_BYTES = 32


def canonical_json(payload: Any) -> bytes:
    """Return the canonical byte encoding used for every signature and digest."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def digest_of(payload: Any) -> str:
    """Return the hex SHA-256 digest of a canonically encoded payload."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def encode_bytes(raw: bytes) -> str:
    """Return unpadded base64url text for transport and storage."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_bytes(text: str) -> bytes:
    """Decode unpadded base64url text, raising a typed error on malformed input."""
    if not isinstance(text, str) or not text:
        raise NodeMeshError(NodeReason.HANDSHAKE_MALFORMED, "expected base64url text")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise NodeMeshError(NodeReason.HANDSHAKE_MALFORMED, "malformed base64url text") from exc


def random_nonce() -> str:
    """Return a fresh single-use handshake nonce."""
    return encode_bytes(secrets.token_bytes(NONCE_BYTES))


@dataclass(frozen=True)
class NodeKeyPair:
    """Raw Ed25519 key material generated on the node itself."""

    private_key: str
    public_key: str


def generate_node_keypair() -> NodeKeyPair:
    """Generate an Ed25519 identity. The private half never leaves its machine."""
    private = Ed25519PrivateKey.generate()
    return NodeKeyPair(
        private_key=encode_bytes(private.private_bytes_raw()),
        public_key=encode_bytes(private.public_key().public_bytes_raw()),
    )


def public_key_of(private_key: str) -> str:
    """Derive the base64url public key for an encoded private key."""
    return encode_bytes(_load_private_key(private_key).public_key().public_bytes_raw())


def _load_private_key(private_key: str) -> Ed25519PrivateKey:
    raw = decode_bytes(private_key)
    if len(raw) != _ED25519_RAW_KEY_BYTES:
        raise NodeMeshError(NodeReason.ENROLLMENT_KEY_INVALID, "malformed private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(public_key: str) -> Ed25519PublicKey:
    """Validate and load an encoded Ed25519 public key."""
    raw = decode_bytes(public_key)
    if len(raw) != _ED25519_RAW_KEY_BYTES:
        raise NodeMeshError(NodeReason.ENROLLMENT_KEY_INVALID, "malformed public key")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise NodeMeshError(NodeReason.ENROLLMENT_KEY_INVALID, "malformed public key") from exc


def sign_payload(private_key: str, payload: Any) -> str:
    """Sign a canonically encoded payload with an Ed25519 private key."""
    return encode_bytes(_load_private_key(private_key).sign(canonical_json(payload)))


def verify_payload(public_key: str, payload: Any, signature: str, reason: NodeReason) -> None:
    """Verify an Ed25519 signature over a canonical payload or raise ``reason``."""
    key = load_public_key(public_key)
    try:
        key.verify(decode_bytes(signature), canonical_json(payload))
    except (InvalidSignature, NodeMeshError) as exc:
        raise NodeMeshError(reason, "signature verification failed") from exc


@dataclass(frozen=True)
class IssuedEnrollmentSecret:
    """One-time enrollment material. Only ``presented`` reaches the operator."""

    token_id: str
    presented: str
    secret_hash: str


def new_enrollment_secret() -> IssuedEnrollmentSecret:
    """Mint a single-use enrollment token and the hash the registry stores."""
    token_id = secrets.token_hex(_ENROLLMENT_ID_BYTES)
    secret_value = secrets.token_urlsafe(_ENROLLMENT_SECRET_BYTES)
    return IssuedEnrollmentSecret(
        token_id=token_id,
        presented=f"{_ENROLLMENT_PREFIX}_{token_id}_{secret_value}",
        secret_hash=hash_enrollment_secret(token_id, secret_value),
    )


def hash_enrollment_secret(token_id: str, secret_value: str) -> str:
    """Return the domain-separated hash stored in place of the enrollment secret."""
    digest = hashlib.sha256()
    digest.update(_ENROLLMENT_HASH_DOMAIN)
    digest.update(b":")
    digest.update(token_id.encode("utf-8"))
    digest.update(b":")
    digest.update(secret_value.encode("utf-8"))
    return digest.hexdigest()


def split_enrollment_token(presented: str) -> tuple[str, str]:
    """Split ``olynode_<id>_<secret>`` into its identifier and secret halves."""
    if not isinstance(presented, str):
        raise NodeMeshError(NodeReason.ENROLLMENT_MALFORMED, "enrollment token must be text")
    parts = presented.split("_", 2)
    if len(parts) != 3 or parts[0] != _ENROLLMENT_PREFIX or not parts[1] or not parts[2]:
        raise NodeMeshError(NodeReason.ENROLLMENT_MALFORMED, "malformed enrollment token")
    return parts[1], parts[2]


def enrollment_secret_matches(token_id: str, secret_value: str, expected_hash: str) -> bool:
    """Compare an offered enrollment secret against its stored hash in constant time."""
    return hmac.compare_digest(hash_enrollment_secret(token_id, secret_value), expected_hash)


def dedupe_key_for(job_id: str, capability: str, parameters: Any) -> str:
    """Return the deterministic content identity that makes re-dispatch idempotent.

    The same logical job re-dispatched after a reconnect, an activity retry, or a
    control-plane restart produces the same key, so the node replays its recorded
    result instead of performing the work twice.
    """
    return hashlib.sha256(
        canonical_json(
            {
                "domain": _DEDUPE_HASH_DOMAIN,
                "job_id": job_id,
                "capability": capability,
                "parameters": parameters,
            }
        )
    ).hexdigest()

"""Loading the pinned trust store that offline verification depends on.

The keyring is read from a file committed to this repository rather than from
the KMS API. That is not a convenience — it is the security property. If the
verifier asked AWS which key to trust, then whoever controls the AWS account
would control the answer, and the off-host copy would no longer survive the
compromise it exists to survive.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from olympus.audit_export.signing import Keyring, TrustedSigner

TRUST_STORE_SCHEMA_VERSION = 1
DEFAULT_TRUST_STORE = Path(__file__).with_name("trusted_signers.json")


class TrustStoreError(Exception):
    """Raised when the pinned trust store cannot be used as written."""


def load_keyring(path: Path | None = None) -> Keyring:
    source = path if path is not None else DEFAULT_TRUST_STORE
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TrustStoreError(f"cannot read trust store at {source}") from exc
    except json.JSONDecodeError as exc:
        raise TrustStoreError(f"trust store at {source} is not JSON: {exc.msg}") from exc
    return keyring_from_mapping(document, source=str(source))


def keyring_from_mapping(document: Any, *, source: str = "<memory>") -> Keyring:
    if not isinstance(document, dict):
        raise TrustStoreError(f"{source}: trust store must be a JSON object")
    if document.get("schema_version") != TRUST_STORE_SCHEMA_VERSION:
        raise TrustStoreError(
            f"{source}: unsupported trust store schema {document.get('schema_version')!r}"
        )
    entries = document.get("signers")
    if not isinstance(entries, list) or not entries:
        raise TrustStoreError(f"{source}: trust store lists no signers")

    signers: dict[str, TrustedSigner] = {}
    for entry in entries:
        signer = _signer_from_entry(entry, source=source)
        if signer.key_id in signers:
            raise TrustStoreError(f"{source}: duplicate signer {signer.key_id}")
        signers[signer.key_id] = signer
    return Keyring(signers=signers)


def _signer_from_entry(entry: Any, *, source: str) -> TrustedSigner:
    if not isinstance(entry, dict):
        raise TrustStoreError(f"{source}: each signer must be a JSON object")
    try:
        key_id = str(entry["key_id"])
        der = base64.b64decode(str(entry["public_key_der_b64"]), validate=True)
        not_before = datetime.fromisoformat(str(entry["not_before"]))
        not_after = datetime.fromisoformat(str(entry["not_after"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise TrustStoreError(f"{source}: malformed signer entry: {exc}") from exc

    # The fingerprint is redundant with the key itself, which is exactly why it
    # is checked: it gives a human reviewing a diff of this file something short
    # to compare against, so a swapped key is visible without decoding base64.
    declared = entry.get("public_key_der_sha256")
    if declared is not None:
        actual = hashlib.sha256(der).hexdigest()
        if actual != str(declared).lower():
            raise TrustStoreError(
                f"{source}: {key_id} fingerprint is {actual}, declared {declared}"
            )

    revoked_raw = entry.get("revoked_at")
    revoked_at = datetime.fromisoformat(str(revoked_raw)) if revoked_raw else None

    try:
        return TrustedSigner(
            key_id=key_id,
            public_key_der=der,
            not_before=not_before,
            not_after=not_after,
            revoked_at=revoked_at,
        )
    except ValueError as exc:
        raise TrustStoreError(f"{source}: {key_id}: {exc}") from exc

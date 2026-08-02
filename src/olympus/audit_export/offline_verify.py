"""Offline verification of an exported audit chain.

"Offline" is a hard claim, so it is worth being precise about what it means
here: this module imports no AWS SDK, opens no socket, and reads no
credential. It takes a directory of bytes and a public trust store committed to
this repository, and decides on its own. Run it on an air-gapped laptop and it
behaves identically.

That matters because the threat this whole subsystem exists for is a
compromised Olympus. If checking the evidence required asking the compromised
system — or the account it controls — whether the evidence was good, the answer
would be worth nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from olympus.audit_export.models import GENESIS_HASH
from olympus.audit_export.signing import (
    ChainVerification,
    StoredSegmentEvidence,
    verify_exported_chain,
)
from olympus.audit_export.trust import load_keyring

BUNDLE_MANIFEST = "manifest.json"
BUNDLE_SCHEMA_VERSION = 1


class BundleError(Exception):
    """Raised when an evidence bundle is unusable as written."""


@dataclass(frozen=True)
class EvidenceBundle:
    bucket: str
    chain: str
    evidence: tuple[StoredSegmentEvidence, ...]


def write_evidence_bundle(
    directory: Path,
    *,
    bucket: str,
    chain: str,
    evidence: Sequence[StoredSegmentEvidence],
) -> Path:
    """Write evidence to disk in a form that carries to another machine."""
    directory.mkdir(parents=True, exist_ok=True)
    entries = []
    for index, item in enumerate(evidence):
        stem = f"{index:06d}"
        segment_name = f"{stem}.segment.json"
        signature_name = f"{stem}.sig.json"
        (directory / segment_name).write_bytes(item.segment_body)
        (directory / signature_name).write_bytes(item.sidecar_body)
        entries.append(
            {
                "object_key": item.object_key,
                "version_id": item.version_id,
                "segment_file": segment_name,
                "signature_file": signature_name,
            }
        )
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bucket": bucket,
        "chain": chain,
        "segments": entries,
    }
    path = directory / BUNDLE_MANIFEST
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_evidence_bundle(directory: Path) -> EvidenceBundle:
    manifest_path = directory / BUNDLE_MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BundleError(f"cannot read {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise BundleError(f"{manifest_path} is not JSON: {exc.msg}") from exc

    if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise BundleError(f"unsupported bundle schema {manifest.get('schema_version')!r}")
    bucket = str(manifest.get("bucket") or "")
    chain = str(manifest.get("chain") or "")
    if not bucket or not chain:
        raise BundleError("bundle manifest must name both a bucket and a chain")

    entries = manifest.get("segments")
    if not isinstance(entries, list):
        raise BundleError("bundle manifest has no segment list")

    evidence: list[StoredSegmentEvidence] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise BundleError("each manifest segment must be an object")
        try:
            segment_body = (directory / str(entry["segment_file"])).read_bytes()
            sidecar_body = (directory / str(entry["signature_file"])).read_bytes()
            evidence.append(
                StoredSegmentEvidence(
                    object_key=str(entry["object_key"]),
                    version_id=str(entry["version_id"]),
                    segment_body=segment_body,
                    sidecar_body=sidecar_body,
                )
            )
        except KeyError as exc:
            raise BundleError(f"manifest segment is missing {exc}") from exc
        except OSError as exc:
            raise BundleError(f"bundle file missing: {exc}") from exc

    # The manifest states the order. It is untrusted input like everything else
    # in the bundle, which is why verification re-derives the expected order
    # from the signed sequence ranges instead of believing this list.
    return EvidenceBundle(bucket=bucket, chain=chain, evidence=tuple(evidence))


def verify_bundle(directory: Path, *, trust_store: Path | None = None) -> ChainVerification:
    bundle = load_evidence_bundle(directory)
    return verify_exported_chain(
        evidence=bundle.evidence,
        keyring=load_keyring(trust_store),
        bucket=bundle.bucket,
        chain=bundle.chain,
        genesis_hash=GENESIS_HASH,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m olympus.audit_export.offline_verify",
        description=(
            "Verify a downloaded Olympus audit evidence bundle using only pinned "
            "public keys. Makes no network calls and uses no AWS credentials."
        ),
    )
    parser.add_argument("bundle", type=Path, help="directory holding manifest.json and segments")
    parser.add_argument(
        "--trust-store",
        type=Path,
        default=None,
        help="alternate pinned signer file (defaults to the one shipped in this package)",
    )
    args = parser.parse_args(argv)

    try:
        result = verify_bundle(args.bundle, trust_store=args.trust_store)
    except BundleError as exc:
        print(f"bundle unusable: {exc}", file=sys.stderr)
        return 2

    print(f"chain:     {result.chain}")
    print(f"segments:  {result.segments}")
    print(f"events:    {result.events}")
    print(f"through:   sequence {result.last_sequence}")
    if result.authentic:
        print("AUTHENTIC: every segment is signed by a pinned key and links to its predecessor")
        return 0
    print("NOT AUTHENTIC:")
    for problem in result.problems:
        print(f"  - {problem}")
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

"""Push the authority audit chain off-host, signed, on a schedule.

The export subsystem is only worth having if it actually runs. Between runs,
every new audit event exists solely in PostgreSQL — the one place a compromised
control plane can rewrite it. Manual export means the protected window is
"whenever someone last remembered", which is not a security property.

This is a one-shot job rather than a loop inside the gateway. Export talks to
AWS and the gateway serves the enrollment ceremony; folding one into the other
would mean an S3 outage, a throttle, or an expired credential could stall the
process that Face ID depends on. A separate process that a timer runs can fail
on its own without taking authority down with it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from olympus.audit_export.exporter import AuditExporter
from olympus.audit_export.signing import KmsEd25519Signer
from olympus.audit_export.store import S3ObjectLockStore
from olympus.audit_export.trust import load_keyring
from olympus.authority.sqlalchemy import SqlAlchemyAuthorityRepository
from olympus.gateway.production_settings import ProductionGatewaySettings


class AuditExportNotConfigured(RuntimeError):
    """Raised when the gateway has no off-host destination configured."""


def _aws_clients(settings: ProductionGatewaySettings) -> tuple[Any, Any]:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - depends on the install extra
        raise RuntimeError("audit export needs the 'aws' extra: uv sync --extra aws") from exc

    session = boto3.Session(
        profile_name=settings.audit_export_profile,
        region_name=settings.audit_export_region,
    )
    return session.client("s3"), session.client("kms")


async def run_once(settings: ProductionGatewaySettings | None = None) -> int:
    """Export everything not yet off-host, then prove what is there is sound.

    Returns the number of events newly exported. Verification runs on every
    invocation, not only when something was written: the question worth asking
    is whether the off-host copy is still trustworthy, and the answer can change
    without this process having done anything.
    """
    settings = settings or ProductionGatewaySettings()  # type: ignore[call-arg]
    if settings.audit_export_bucket is None or settings.audit_export_kms_key_id is None:
        raise AuditExportNotConfigured(
            "no audit export bucket or signing key is configured for this gateway"
        )

    s3, kms = _aws_clients(settings)
    store = S3ObjectLockStore(
        bucket=settings.audit_export_bucket,
        client=s3,
        expected_retention_days=settings.audit_export_retention_days,
        expected_retention_mode=settings.audit_export_retention_mode,
    )
    # Confirm the destination still seals what it is given before writing to it.
    # A bucket whose Object Lock was removed would accept these writes happily
    # and produce a chain that looks exported but can be deleted at will.
    mode, days = await store.assert_retention_configured()

    engine = create_async_engine(settings.database_dsn.get_secret_value())
    try:
        repository = SqlAlchemyAuthorityRepository(
            async_sessionmaker(engine, expire_on_commit=False)
        )
        events = await repository.audit_events()

        exporter = AuditExporter(
            store=store,
            chain=settings.audit_export_chain,
            bucket=settings.audit_export_bucket,
            signer=KmsEd25519Signer(key_id=settings.audit_export_kms_key_id, client=kms),
        )
        result = await exporter.export(events)
        authenticity = await exporter.verify_authenticity(load_keyring())
    finally:
        await engine.dispose()

    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    print(
        f"{stamp} chain={settings.audit_export_chain} "
        f"local={len(events)} exported={result.events_exported} "
        f"segments={result.segments_written} through={result.last_exported_sequence} "
        f"sealed={mode}/{days}d"
    )

    if not authenticity.authentic:
        # Loud and non-zero. A silent failure here means the operator believes
        # there is off-host evidence when there may not be.
        for problem in authenticity.problems:
            print(f"  NOT AUTHENTIC: {problem}", file=sys.stderr)
        raise SystemExit(1)

    print(
        f"  verified {authenticity.segments} segment(s), {authenticity.events} event(s) "
        "signed by a pinned key and linked to their predecessors"
    )
    return result.events_exported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m olympus.runtime.audit_export_job",
        description="Export the authority audit chain to signed, write-once object storage.",
    )
    parser.parse_args(argv)
    try:
        asyncio.run(run_once())
    except AuditExportNotConfigured as exc:
        print(f"audit export skipped: {exc}", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

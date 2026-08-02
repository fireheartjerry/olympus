import re
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final

from psycopg import AsyncConnection

# One fixed advisory-lock key for the whole node-mesh schema. Two control
# planes starting at once serialize here rather than racing to create tables.
MIGRATION_LOCK_KEY: Final[int] = 0x0147_4D50_5553_0001

_MIGRATION_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")

_LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: str


def load_migrations() -> tuple[Migration, ...]:
    """Read the packaged migrations in version order."""
    package = resources.files("olympus.persistence.migrations")
    found: list[Migration] = []
    for entry in package.iterdir():
        match = _MIGRATION_NAME.match(entry.name)
        if match is None:
            continue
        found.append(
            Migration(
                version=int(match.group(1)),
                name=match.group(2),
                statements=entry.read_text(encoding="utf-8"),
            )
        )
    found.sort(key=lambda migration: migration.version)
    versions = [migration.version for migration in found]
    if len(set(versions)) != len(versions):
        raise RuntimeError("duplicate migration version")
    return tuple(found)


async def apply_migrations(connection: AsyncConnection[Any]) -> tuple[int, ...]:
    """Apply every unapplied migration and return the versions applied.

    Each migration and its ledger row commit in one transaction, so a
    migration is either fully applied and recorded or not applied at all.
    Applying an already-migrated database returns an empty tuple.
    """
    applied: list[int] = []
    async with connection.cursor() as cursor:
        await cursor.execute(f"SELECT pg_advisory_lock({MIGRATION_LOCK_KEY})")
        try:
            await cursor.execute(_LEDGER_DDL)
            await connection.commit()
            await cursor.execute("SELECT version FROM schema_migrations")
            done = {int(row[0]) for row in await cursor.fetchall()}
            for migration in load_migrations():
                if migration.version in done:
                    continue
                await cursor.execute(migration.statements)
                await cursor.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (%s, %s)",
                    (migration.version, migration.name),
                )
                await connection.commit()
                applied.append(migration.version)
        finally:
            await cursor.execute(f"SELECT pg_advisory_unlock({MIGRATION_LOCK_KEY})")
            await connection.commit()
    return tuple(applied)

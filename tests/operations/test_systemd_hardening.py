from pathlib import Path

ROOT = Path(__file__).parents[2]
SYSTEMD = ROOT / "deploy" / "systemd"


def test_authority_services_drop_ambient_privilege() -> None:
    services = [
        "olympus-gateway.service",
        "olympus-audit-export.service",
        "olympus-tls-renew.service",
        "olympus-postgres-backup.service",
        "olympus-health-check.service",
    ]
    required = (
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=full",
        "ProtectHome=read-only",
        "RestrictAddressFamilies=",
        "LockPersonality=true",
        "RestrictRealtime=true",
        "SystemCallArchitectures=native",
    )

    for name in services:
        unit = (SYSTEMD / name).read_text(encoding="utf-8")
        for control in required:
            assert control in unit, f"{name} is missing {control}"
        assert "CapabilityBoundingSet=" not in unit, (
            f"{name} uses a capability directive unsupported by the OVH user manager"
        )


def test_backup_and_health_timers_are_persistent_and_bounded() -> None:
    backup = (SYSTEMD / "olympus-postgres-backup.timer").read_text(encoding="utf-8")
    health = (SYSTEMD / "olympus-health-check.timer").read_text(encoding="utf-8")

    assert "OnCalendar=daily" in backup
    assert "RandomizedDelaySec=30m" in backup
    assert "OnUnitActiveSec=5min" in health
    assert "Persistent=true" in backup
    assert "Persistent=true" in health


def test_backup_is_atomic_and_restore_drill_is_disposable() -> None:
    backup = (ROOT / "scripts" / "postgres-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts" / "postgres-restore-drill.sh").read_text(encoding="utf-8")

    assert "umask 0077" in backup
    assert 'partial_path="${final_path}.partial"' in backup
    assert "pg_restore --list" in backup
    assert 'mv -- "$partial_path" "$final_path"' in backup
    assert "sha256sum --check --status" in restore
    assert "--network none" in restore
    assert "--tmpfs /var/lib/postgresql/data" in restore
    assert 'docker rm --force "$drill_container"' in restore


def test_health_check_only_pages_on_swap_when_memory_is_low() -> None:
    health = (ROOT / "scripts" / "production-health-check.sh").read_text(encoding="utf-8")

    assert "OLYMPUS_MEMORY_AVAILABLE_WARN_PERCENT" in health
    assert (
        "swap_percent >= swap_warn_percent && "
        "memory_available_percent < memory_available_warn_percent"
    ) in health


def test_postgres_definition_is_pinned_loopback_only_and_reuses_live_volume() -> None:
    compose = (ROOT / "deploy" / "postgres" / "compose.yaml").read_text(encoding="utf-8")

    assert "postgres@sha256:" in compose
    assert "postgres:16-alpine" not in compose
    assert '"127.0.0.1:5433:5432"' in compose
    assert "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB" in compose
    assert "external: true" in compose
    assert "name: olympus-pgdata" in compose

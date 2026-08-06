from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_postgres_bootstrap_forwards_the_sql_heredoc_to_the_container() -> None:
    script = (ROOT / "deploy" / "temporal" / "deploy.sh").read_text(encoding="utf-8")

    assert 'docker exec -i "$container" sh -euc' in script


def test_temporal_is_digest_pinned_and_published_only_on_loopback() -> None:
    compose = (ROOT / "deploy" / "temporal" / "compose.yaml").read_text(encoding="utf-8")

    assert "temporalio/server@sha256:" in compose
    assert "BIND_ON_IP: 127.0.0.1" in compose
    assert "network_mode: host" in compose
    assert "POSTGRES_SEEDS: 127.0.0.1" in compose
    assert "ports:" not in compose
    assert "temporalio/auto-setup" not in compose


def test_deploy_waits_for_health_and_successful_namespace_completion() -> None:
    script = (ROOT / "deploy" / "temporal" / "deploy.sh").read_text(encoding="utf-8")

    assert '[[ "$health" == "healthy" ]]' in script
    assert '"$namespace_status" == "exited" && "$namespace_exit" == "0"' in script
    assert "up -d --wait" not in script


def test_temporal_backup_checksum_manifest_survives_atomic_directory_rename() -> None:
    script = (ROOT / "scripts" / "temporal-backup.sh").read_text(encoding="utf-8")

    assert 'cd "$partial_dir" && sha256sum -- "${database}.dump"' in script
    assert 'sha256sum -- "$dump_path"' not in script


def test_temporal_backup_service_uploads_only_after_local_backup_succeeds() -> None:
    unit = (ROOT / "deploy" / "systemd" / "olympus-temporal-backup.service").read_text(
        encoding="utf-8"
    )

    local = "ExecStart=/home/ubuntu/olympus/scripts/temporal-backup.sh"
    offhost = (
        "ExecStart=/home/ubuntu/olympus/.venv/bin/python "
        "-m olympus.runtime.temporal_offhost_backup upload --latest"
    )
    assert unit.index(local) < unit.index(offhost)
    assert "Wants=network-online.target" in unit


def test_clean_host_restore_is_networkless_ephemeral_and_checks_both_databases() -> None:
    script = (ROOT / "scripts" / "temporal-clean-host-restore.sh").read_text(encoding="utf-8")

    assert "--network none" in script
    assert "--tmpfs /var/lib/postgresql/data" in script
    assert "docker rm --force" in script
    assert "for database in temporal temporal_visibility" in script
    assert "sha256sum --check --status SHA256SUMS" in script
    assert "postgres@sha256:57c72fd2a128" in script

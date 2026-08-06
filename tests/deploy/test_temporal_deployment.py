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

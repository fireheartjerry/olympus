import pytest

from olympus.integrations.shadow import (
    FakeReadOnlyAdapter,
    IntegrationRequest,
    ShadowModeRunner,
    ShadowModeViolation,
)


def runner() -> tuple[ShadowModeRunner, dict[str, FakeReadOnlyAdapter]]:
    adapters = {
        name: FakeReadOnlyAdapter(name, {"status": "ok", "source": name})
        for name in ("discord", "google", "github", "browser", "infrastructure")
    }
    return ShadowModeRunner(adapters), adapters


def test_shadow_mode_reads_and_projects_without_mutating_provider() -> None:
    shadow, adapters = runner()

    projection = shadow.run(
        IntegrationRequest(
            request_id="request-1",
            adapter="github",
            operation="open_pull_request",
            payload={"repository": "olympus"},
            mutation_requested=True,
        )
    )

    assert projection.effect == "projected-only"
    assert projection.approval_required
    assert adapters["github"].read_count == 1
    assert adapters["github"].mutation_count == 0


def test_unknown_adapter_and_direct_mutation_fail_closed() -> None:
    shadow, adapters = runner()
    with pytest.raises(ShadowModeViolation, match="not registered"):
        shadow.run(IntegrationRequest("request-1", "unknown", "read", {}, False))
    with pytest.raises(ShadowModeViolation, match="disabled"):
        adapters["github"].mutate("merge", {})


def test_one_hundred_job_shadow_corpus_has_zero_critical_policy_misses() -> None:
    shadow, adapters = runner()
    projections = []
    names = tuple(adapters)
    for job in range(10):
        for variant in range(10):
            mutation = variant % 2 == 1
            projections.append(
                shadow.run(
                    IntegrationRequest(
                        request_id=f"job-{job}-variant-{variant}",
                        adapter=names[(job + variant) % len(names)],
                        operation="representative-operation",
                        payload={"job": job, "variant": variant},
                        mutation_requested=mutation,
                    )
                )
            )

    critical_misses = [
        projection
        for projection in projections
        if projection.mutation_requested
        and (projection.effect != "projected-only" or not projection.approval_required)
    ]
    assert len(projections) == 100
    assert critical_misses == []
    assert sum(adapter.mutation_count for adapter in adapters.values()) == 0

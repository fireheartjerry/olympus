from dataclasses import replace

import pytest

from olympus.workers.admission import (
    AdmissionController,
    AdmissionDenied,
    ResourceEnvelope,
    SystemMode,
    WorkerClass,
    WorkerRequest,
    WorkPriority,
)


def request(
    worker_class: WorkerClass,
    *,
    job_id: str = "job-1",
    cpu: int = 500,
    memory: int = 1024,
    priority: WorkPriority = WorkPriority.NORMAL,
) -> WorkerRequest:
    return WorkerRequest(
        request_id=f"{job_id}-{worker_class.value}",
        job_id=job_id,
        worker_class=worker_class,
        worktree_id=f"worktree-{job_id}",
        artifact_prefix=f"artifacts/{job_id}/",
        cpu_millicores=cpu,
        memory_mib=memory,
        priority=priority,
    )


def controller(mode: SystemMode = SystemMode.NORMAL) -> AdmissionController:
    return AdmissionController(
        capacity=ResourceEnvelope(cpu_millicores=3500, memory_mib=8704),
        mode=mode,
        concurrency={
            WorkerClass.CLAUDE: 1,
            WorkerClass.CODEX: 1,
            WorkerClass.CHROMIUM: 2,
            WorkerClass.VERIFIER: 1,
        },
    )


def test_admits_isolated_worker_classes_with_resource_accounting() -> None:
    admission = controller()
    claude = admission.admit(request(WorkerClass.CLAUDE))
    chromium = admission.admit(request(WorkerClass.CHROMIUM, job_id="job-2"))

    assert claude.isolation_token != chromium.isolation_token
    assert admission.used.cpu_millicores == 1000
    assert admission.used.memory_mib == 2048


def test_rejects_cross_job_worktree_or_artifact_boundary_reuse() -> None:
    admission = controller()
    admission.admit(request(WorkerClass.CODEX))

    with pytest.raises(AdmissionDenied, match="isolation boundary"):
        admission.admit(
            replace(
                request(WorkerClass.VERIFIER, job_id="job-2"),
                worktree_id="worktree-job-1",
            )
        )


def test_saturation_and_degradation_fail_closed_by_priority() -> None:
    saturated = controller()
    saturated.admit(request(WorkerClass.CLAUDE))
    with pytest.raises(AdmissionDenied, match="concurrency"):
        saturated.admit(request(WorkerClass.CLAUDE, job_id="job-2"))

    with pytest.raises(AdmissionDenied, match="survival"):
        controller(SystemMode.SURVIVAL).admit(request(WorkerClass.CODEX))
    control = controller(SystemMode.SURVIVAL).admit(
        request(
            WorkerClass.VERIFIER,
            priority=WorkPriority.CONTROL,
            cpu=100,
            memory=128,
        )
    )
    assert control.request.priority is WorkPriority.CONTROL


def test_release_returns_capacity_and_boundary() -> None:
    admission = controller()
    lease = admission.admit(request(WorkerClass.CHROMIUM))

    admission.release(lease.isolation_token)

    assert admission.used == ResourceEnvelope(cpu_millicores=0, memory_mib=0)
    assert admission.active == ()

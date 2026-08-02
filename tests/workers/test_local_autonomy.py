from pathlib import Path

import pytest

from olympus.workers.local_autonomy import (
    LocalAutonomyDenied,
    LocalAutonomyRunner,
    LocalTask,
    ScriptedLocalBackend,
)


def test_safe_local_task_runs_in_job_boundary_and_passes_verifier() -> None:
    backend = ScriptedLocalBackend(outputs=[b"candidate"], verdicts=[False, True])
    runner = LocalAutonomyRunner(
        workspace_root=Path("/workspace"),
        backend=backend,
        maximum_revisions=2,
    )

    result = runner.run(
        LocalTask(
            task_id="task-1",
            job_id="job-1",
            operation="code.generate",
            relative_worktree="worktrees/job-1",
            instruction="implement the bounded feature",
        )
    )

    assert result.verified
    assert result.revisions == 1
    assert result.artifact == b"candidate"
    assert all(path.is_relative_to(Path("/workspace")) for path in backend.paths)


@pytest.mark.parametrize(
    "operation",
    ["gmail.send", "github.merge", "root.execute", "cloud.provision"],
)
def test_external_or_privileged_operations_are_unavailable(operation: str) -> None:
    runner = LocalAutonomyRunner(
        workspace_root=Path("/workspace"),
        backend=ScriptedLocalBackend(outputs=[b"x"], verdicts=[True]),
        maximum_revisions=1,
    )

    with pytest.raises(LocalAutonomyDenied, match="not a safe local capability"):
        runner.run(LocalTask("task-1", "job-1", operation, "worktrees/job-1", "do it"))


def test_worktree_escape_and_unbounded_revision_fail_closed() -> None:
    runner = LocalAutonomyRunner(
        workspace_root=Path("/workspace"),
        backend=ScriptedLocalBackend(outputs=[b"x"], verdicts=[False, False]),
        maximum_revisions=1,
    )
    with pytest.raises(LocalAutonomyDenied, match="contained"):
        runner.run(LocalTask("task-1", "job-1", "test.run", "../escape", "test"))
    with pytest.raises(LocalAutonomyDenied, match="revision limit"):
        runner.run(LocalTask("task-2", "job-1", "test.run", "worktrees/job-1", "test"))

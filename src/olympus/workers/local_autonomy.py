from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class LocalAutonomyDenied(RuntimeError):
    pass


SAFE_LOCAL_OPERATIONS = frozenset(
    {
        "research.read",
        "code.generate",
        "test.run",
        "draft.create",
        "container.local",
    }
)


@dataclass(frozen=True)
class LocalTask:
    task_id: str
    job_id: str
    operation: str
    relative_worktree: str
    instruction: str

    def __post_init__(self) -> None:
        if any(
            not value.strip()
            for value in (
                self.task_id,
                self.job_id,
                self.operation,
                self.relative_worktree,
                self.instruction,
            )
        ):
            raise ValueError("local task fields must not be empty")


@dataclass(frozen=True)
class LocalTaskResult:
    task_id: str
    artifact: bytes
    revisions: int
    verified: bool


class LocalBackend(Protocol):
    def execute(self, task: LocalTask, worktree: Path, revision: int) -> bytes: ...

    def verify(self, task: LocalTask, artifact: bytes, worktree: Path) -> bool: ...


class ScriptedLocalBackend:
    def __init__(self, *, outputs: list[bytes], verdicts: list[bool]) -> None:
        if not outputs or not verdicts:
            raise ValueError("scripted backend needs output and verdict fixtures")
        self._outputs = list(outputs)
        self._verdicts = list(verdicts)
        self.paths: list[Path] = []
        self._executions = 0
        self._verifications = 0

    def execute(self, task: LocalTask, worktree: Path, revision: int) -> bytes:
        self.paths.append(worktree)
        index = min(self._executions, len(self._outputs) - 1)
        self._executions += 1
        return self._outputs[index]

    def verify(self, task: LocalTask, artifact: bytes, worktree: Path) -> bool:
        self.paths.append(worktree)
        index = min(self._verifications, len(self._verdicts) - 1)
        self._verifications += 1
        return self._verdicts[index]


class LocalAutonomyRunner:
    def __init__(
        self,
        *,
        workspace_root: Path,
        backend: LocalBackend,
        maximum_revisions: int,
    ) -> None:
        if not workspace_root.is_absolute():
            raise ValueError("workspace root must be absolute")
        if maximum_revisions < 0 or maximum_revisions > 5:
            raise ValueError("maximum revisions must be between zero and five")
        self._root = workspace_root.resolve()
        self._backend = backend
        self._maximum_revisions = maximum_revisions

    def run(self, task: LocalTask) -> LocalTaskResult:
        if task.operation not in SAFE_LOCAL_OPERATIONS:
            raise LocalAutonomyDenied("operation is not a safe local capability")
        relative = Path(task.relative_worktree)
        worktree = (self._root / relative).resolve()
        if (
            relative.is_absolute()
            or not worktree.is_relative_to(self._root)
            or task.job_id not in worktree.parts
        ):
            raise LocalAutonomyDenied("worktree must remain contained in the job boundary")
        for revision in range(self._maximum_revisions + 1):
            artifact = self._backend.execute(task, worktree, revision)
            if self._backend.verify(task, artifact, worktree):
                return LocalTaskResult(task.task_id, artifact, revision, True)
        raise LocalAutonomyDenied("verifier revision limit reached")

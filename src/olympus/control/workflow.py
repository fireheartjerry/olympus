from dataclasses import dataclass


@dataclass(frozen=True)
class ControlSnapshot:
    paused: bool
    cancelled: bool
    frozen: bool
    processed_control_ids: tuple[str, ...]


class WorkflowControlState:
    def __init__(self) -> None:
        self.paused = False
        self.cancelled = False
        self.frozen = False
        self._processed: list[str] = []

    def pause(self, control_id: str) -> None:
        if self._accept(control_id) and not self.cancelled and not self.frozen:
            self.paused = True

    def resume(self, control_id: str) -> None:
        if self._accept(control_id) and not self.cancelled and not self.frozen:
            self.paused = False

    def cancel(self, control_id: str) -> None:
        if self._accept(control_id) and not self.frozen:
            self.cancelled = True
            self.paused = False

    def freeze(self, control_id: str) -> None:
        if self._accept(control_id):
            self.frozen = True
            self.paused = False

    def snapshot(self) -> ControlSnapshot:
        return ControlSnapshot(
            paused=self.paused,
            cancelled=self.cancelled,
            frozen=self.frozen,
            processed_control_ids=tuple(self._processed),
        )

    def _accept(self, control_id: str) -> bool:
        if not control_id.strip():
            raise ValueError("control_id must not be empty")
        if control_id in self._processed:
            return False
        self._processed.append(control_id)
        return True

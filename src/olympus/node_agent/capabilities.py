import asyncio
import os
import platform
import shutil
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from olympus.nodes.capabilities import SYSTEM_INSPECT

CapabilityStatusLiteral = Literal["succeeded", "failed", "cancelled", "rejected"]

INSPECT_SECTIONS: tuple[str, ...] = ("os", "cpu", "memory", "disk", "uptime", "agent")


@dataclass(frozen=True)
class CapabilityRequest:
    """One bounded unit of work handed to a provider."""

    job_id: str
    capability: str
    parameters: dict[str, Any]
    deadline_seconds: int
    max_output_bytes: int


@dataclass(frozen=True)
class CapabilityArtifact:
    """A bounded binary side product, such as a screenshot or a report file."""

    artifact_id: str
    kind: str
    media_type: str
    data: bytes


@dataclass(frozen=True)
class CapabilityResult:
    """Terminal provider outcome before bounding and redaction."""

    status: CapabilityStatusLiteral
    output: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    message: str = ""
    artifacts: tuple[CapabilityArtifact, ...] = ()


ProgressReporter = Callable[[str, int | None], Awaitable[None]]


class CapabilityProvider(Protocol):
    """A node's implementation of one or more catalog capabilities."""

    @property
    def capabilities(self) -> tuple[str, ...]: ...

    async def execute(
        self, request: CapabilityRequest, report: ProgressReporter
    ) -> CapabilityResult: ...


class SystemProbe(Protocol):
    """Host measurement seam so inspection is deterministic under test."""

    def operating_system(self) -> dict[str, Any]: ...

    def cpu(self) -> dict[str, Any]: ...

    def memory(self) -> dict[str, Any]: ...

    def disk(self, path: Path) -> dict[str, Any]: ...

    def uptime_seconds(self) -> int | None: ...


class LocalSystemProbe:
    """Reads a fixed set of non-sensitive counters using only the standard library.

    It never reads environment variables, process lists, network configuration,
    or user data, and never launches a subprocess. The only files it opens are
    the two fixed Linux counters ``/proc/meminfo`` and ``/proc/uptime``, from
    which it parses numbers only.
    """

    def operating_system(self) -> dict[str, Any]:
        return {
            "system": platform.system(),
            "release": platform.release()[:64],
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        }

    def cpu(self) -> dict[str, Any]:
        load: list[float] | None = None
        if hasattr(os, "getloadavg"):
            try:
                load = [round(value, 2) for value in os.getloadavg()]
            except OSError:
                load = None
        return {"logical_cores": os.cpu_count(), "load_average": load}

    def memory(self) -> dict[str, Any]:
        total, available = _read_memory_mib()
        return {"total_mib": total, "available_mib": available}

    def disk(self, path: Path) -> dict[str, Any]:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            return {"path": str(path), "total_mib": None, "free_mib": None}
        return {
            "path": str(path),
            "total_mib": usage.total // (1024 * 1024),
            "free_mib": usage.free // (1024 * 1024),
        }

    def uptime_seconds(self) -> int | None:
        return _read_uptime_seconds()


def _read_memory_mib() -> tuple[int | None, int | None]:
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        totals: dict[str, int] = {}
        for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
            key, _, rest = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                digits = rest.strip().split(" ", 1)[0]
                if digits.isdigit():
                    totals[key] = int(digits) // 1024
        return totals.get("MemTotal"), totals.get("MemAvailable")
    return _read_windows_memory_mib()


def _read_windows_memory_mib() -> tuple[int | None, int | None]:
    if platform.system() != "Windows":
        return None, None
    import ctypes

    class _MemoryStatusEx(ctypes.Structure):
        _fields_ = (
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        )

    status = _MemoryStatusEx()
    status.dwLength = ctypes.sizeof(_MemoryStatusEx)
    kernel32 = getattr(ctypes, "windll", None)
    if kernel32 is None or not kernel32.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None, None
    return (
        int(status.ullTotalPhys) // (1024 * 1024),
        int(status.ullAvailPhys) // (1024 * 1024),
    )


def _read_uptime_seconds() -> int | None:
    uptime = Path("/proc/uptime")
    if uptime.exists():
        first = uptime.read_text(encoding="utf-8", errors="ignore").split(" ", 1)[0]
        try:
            return int(float(first))
        except ValueError:
            return None
    if platform.system() == "Windows":
        import ctypes

        kernel32 = getattr(ctypes, "windll", None)
        if kernel32 is not None:
            return int(kernel32.kernel32.GetTickCount64() // 1000)
    return None


class SystemInspectProvider:
    """The one capability enabled in this slice: bounded, read-only inspection."""

    def __init__(
        self,
        *,
        probe: SystemProbe | None = None,
        state_directory: Path | None = None,
        agent_version: str,
        started_at: float | None = None,
    ) -> None:
        self._probe = probe or LocalSystemProbe()
        self._state_directory = state_directory or Path.cwd()
        self._agent_version = agent_version
        self._started_at = started_at if started_at is not None else time.monotonic()

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (SYSTEM_INSPECT.name,)

    async def execute(
        self, request: CapabilityRequest, report: ProgressReporter
    ) -> CapabilityResult:
        requested = request.parameters.get("sections", list(INSPECT_SECTIONS))
        if not isinstance(requested, (list, tuple)) or not requested:
            requested = list(INSPECT_SECTIONS)
        sections = [name for name in INSPECT_SECTIONS if name in set(map(str, requested))]
        if not sections:
            return CapabilityResult(
                status="rejected",
                reason="capability-parameters-invalid",
                message="no known inspection section was requested",
            )

        await report("collecting host inventory", 10)
        collected: dict[str, Any] = {}
        for index, name in enumerate(sections, start=1):
            collected[name] = self._collect(name)
            await report(f"collected {name}", int(index * 100 / len(sections)))
        return CapabilityResult(
            status="succeeded",
            output={"sections": collected, "section_names": sections},
        )

    def _collect(self, name: str) -> dict[str, Any]:
        if name == "os":
            return self._probe.operating_system()
        if name == "cpu":
            return self._probe.cpu()
        if name == "memory":
            return self._probe.memory()
        if name == "disk":
            return self._probe.disk(self._state_directory)
        if name == "uptime":
            return {"host_uptime_seconds": self._probe.uptime_seconds()}
        return {
            "agent_version": self._agent_version,
            "agent_uptime_seconds": int(time.monotonic() - self._started_at),
        }


class FakeCapabilityProvider:
    """Deterministic provider used by tests and by the built-in demo.

    It can succeed, fail, emit a fixed number of progress events, stall until
    cancelled, or return oversized output, without touching the host.
    """

    def __init__(
        self,
        *,
        capabilities: tuple[str, ...] = (SYSTEM_INSPECT.name,),
        output: dict[str, Any] | None = None,
        progress_messages: tuple[str, ...] = ("started", "halfway", "finishing"),
        status: CapabilityStatusLiteral = "succeeded",
        stall: bool = False,
        oversized_bytes: int = 0,
        artifacts: tuple[CapabilityArtifact, ...] = (),
    ) -> None:
        self._capabilities = capabilities
        self._output = output if output is not None else {"ok": True}
        self._progress_messages = progress_messages
        self._status = status
        self._stall = stall
        self._oversized_bytes = oversized_bytes
        self._artifacts = artifacts
        self.executions: list[CapabilityRequest] = []

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self._capabilities

    async def execute(
        self, request: CapabilityRequest, report: ProgressReporter
    ) -> CapabilityResult:
        self.executions.append(request)
        for index, message in enumerate(self._progress_messages, start=1):
            await report(message, int(index * 100 / max(len(self._progress_messages), 1)))
        if self._stall:
            await _forever()
        output = dict(self._output)
        if self._oversized_bytes:
            output["filler"] = "x" * self._oversized_bytes
        if self._status != "succeeded":
            return CapabilityResult(
                status=self._status,
                output=output,
                reason="fake-failure",
                message="fake failure",
                artifacts=self._artifacts,
            )
        return CapabilityResult(status="succeeded", output=output, artifacts=self._artifacts)


async def _forever() -> None:
    await asyncio.Event().wait()

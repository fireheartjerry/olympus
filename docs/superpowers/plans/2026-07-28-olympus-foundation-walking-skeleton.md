# Olympus Foundation Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a side-effect-free vertical slice that accepts an authenticated development command, starts a durable Temporal workflow, compiles a bounded no-op graph, and validates the VPS-4 capacity guardrails in CI.

**Architecture:** A Python service package contains isolated contracts, graph compilation, Temporal workflow, gateway, and capacity modules. The gateway may run only with a development token in this slice; it cannot connect Discord or execute external effects. Helm establishes namespaces, priority classes, and worker quotas, while machine-readable capacity data prevents manifests from exceeding the approved 24-GB node envelope.

**Tech Stack:** Python 3.13, uv, FastAPI, Pydantic v2, Temporal Python SDK, pytest, Ruff, mypy, PyYAML, Helm 3, K3s, GitHub Actions

---

## Scope Boundary

This plan intentionally excludes live VPS mutation, Discord connectivity, WebAuthn, signed production policy bundles, root broker implementation, secrets, Google/GitHub/browser effects, real Claude/Codex execution, and production data services. Those are independent security-sensitive plans built after this walking skeleton passes.

The deliverable is successful when:

1. A test command with a development-only bearer token returns `202 Accepted`.
2. Temporal durably executes the command workflow and returns a one-node, non-side-effecting graph receipt.
3. The capacity validator proves platform and worker memory limits fit the 22-GiB pod envelope.
4. Helm renders the four namespaces, priority classes, and exact local-worker quota.
5. Formatting, linting, typing, unit tests, Temporal integration tests, capacity validation, and Helm validation pass in GitHub Actions.

## Initial File Map

```text
Olympus/
├── AGENTS.md
├── README.md
├── .env.example
├── pyproject.toml
├── uv.lock
├── .python-version
├── config/
│   └── capacity/vps4.yaml
├── deploy/
│   └── helm/olympus-foundation/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── namespaces.yaml
│           ├── priority-classes.yaml
│           └── worker-quota.yaml
├── src/olympus/
│   ├── __init__.py
│   ├── activities/compile_graph.py
│   ├── capacity/models.py
│   ├── contracts/commands.py
│   ├── gateway/app.py
│   ├── gateway/settings.py
│   ├── graphs/compiler.py
│   ├── graphs/models.py
│   ├── runtime/gateway.py
│   ├── runtime/worker.py
│   └── workflows/command.py
├── tests/
│   ├── capacity/test_vps4_capacity.py
│   ├── contracts/test_commands.py
│   ├── gateway/test_app.py
│   ├── graphs/test_compiler.py
│   └── workflows/test_command_workflow.py
└── .github/workflows/ci.yml
```

### Task 1: Bootstrap the Python Toolchain

**Files:**
- Create: `.python-version`
- Create: `pyproject.toml`
- Create: `src/olympus/__init__.py`
- Create: `tests/test_package.py`
- Modify: `.gitignore`

- [ ] **Step 1: Extend the ignore rules**

Append these exact entries to `.gitignore`:

```gitignore
.venv/
__pycache__/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
*.egg-info/
.env
.env.*
!.env.example
outputs/
work/
```

- [ ] **Step 2: Pin the Python line and define the package**

Create `.python-version`:

```text
3.13
```

Create `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "olympus"
version = "0.1.0"
description = "Governed durable orchestration for the Olympus agent platform"
requires-python = ">=3.13,<3.14"
dependencies = [
  "fastapi>=0.115,<1",
  "pydantic>=2.10,<3",
  "pydantic-settings>=2.7,<3",
  "pyyaml>=6.0,<7",
  "temporalio>=1.9,<2",
  "uvicorn>=0.34,<1",
]

[dependency-groups]
dev = [
  "httpx>=0.28,<1",
  "mypy>=1.14,<2",
  "pytest>=8.3,<9",
  "pytest-asyncio>=0.25,<1",
  "ruff>=0.9,<1",
]

[tool.hatch.build.targets.wheel]
packages = ["src/olympus"]

[tool.pytest.ini_options]
addopts = "-q"
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "ASYNC", "S"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "S105"]

[tool.mypy]
python_version = "3.13"
strict = true
packages = ["olympus"]
```

- [ ] **Step 3: Add the package marker and smoke test**

Create `src/olympus/__init__.py`:

```python
"""Olympus orchestration platform."""

__version__ = "0.1.0"
```

Create `tests/test_package.py`:

```python
from olympus import __version__


def test_package_version_is_explicit() -> None:
    assert __version__ == "0.1.0"
```

- [ ] **Step 4: Resolve and verify the locked environment**

Run:

```powershell
uv lock
uv sync --locked --all-groups
uv run pytest tests/test_package.py
uv run ruff format src tests
uv run ruff check src tests
uv run mypy
```

Expected: all commands exit `0`; pytest reports `1 passed`.

- [ ] **Step 5: Commit the toolchain**

```powershell
git add .gitignore .python-version pyproject.toml uv.lock src/olympus/__init__.py tests/test_package.py
git commit -m "build: bootstrap Olympus Python toolchain"
```

### Task 2: Define Trust-Aware Command Contracts

**Files:**
- Create: `src/olympus/contracts/__init__.py`
- Create: `src/olympus/contracts/commands.py`
- Create: `tests/contracts/test_commands.py`

- [ ] **Step 1: Write contract validation tests**

Create `tests/contracts/test_commands.py`:

```python
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from olympus.contracts.commands import (
    CommandEnvelope,
    CommandRequest,
    JobStatus,
    TrustLabel,
)


def test_command_request_strips_surrounding_whitespace() -> None:
    request = CommandRequest(command="  inspect the active graph  ")
    assert request.command == "inspect the active graph"


@pytest.mark.parametrize("command", ["", "   ", "x" * 8001])
def test_command_request_rejects_invalid_lengths(command: str) -> None:
    with pytest.raises(ValidationError):
        CommandRequest(command=command)


def test_envelope_preserves_literal_authority_and_bounds() -> None:
    envelope = CommandEnvelope(
        job_id="job-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    )

    assert envelope.trust_label is TrustLabel.USER_AUTHORIZED
    assert envelope.max_nodes == 32
    assert envelope.max_fan_out == 4
    assert envelope.status is JobStatus.ACCEPTED
```

- [ ] **Step 2: Run the tests and confirm the contract is absent**

Run:

```powershell
uv run pytest tests/contracts/test_commands.py
```

Expected: collection fails with `ModuleNotFoundError: No module named 'olympus.contracts'`.

- [ ] **Step 3: Implement the command boundary**

Create `src/olympus/contracts/__init__.py`:

```python
"""Typed boundaries shared by Olympus services and workflows."""
```

Create `src/olympus/contracts/commands.py`:

```python
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

CommandText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=8000),
]


class TrustLabel(StrEnum):
    CONTROL = "control"
    USER_AUTHORIZED = "user-authorized"
    MODEL_DERIVED = "model-derived"
    EXTERNAL_UNTRUSTED = "external-untrusted"


class JobStatus(StrEnum):
    ACCEPTED = "accepted"
    COMPILED = "compiled"
    FAILED = "failed"


class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: CommandText


class CommandAccepted(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    status: JobStatus = JobStatus.ACCEPTED


@dataclass(frozen=True)
class CommandEnvelope:
    job_id: str
    commander_id: str
    authority_lease_id: str
    command_text: str
    received_at: str
    trust_label: TrustLabel = TrustLabel.USER_AUTHORIZED
    max_nodes: int = 32
    max_fan_out: int = 4
    status: JobStatus = JobStatus.ACCEPTED

    def __post_init__(self) -> None:
        required = {
            "job_id": self.job_id,
            "commander_id": self.commander_id,
            "authority_lease_id": self.authority_lease_id,
            "command_text": self.command_text,
            "received_at": self.received_at,
        }
        empty = [name for name, value in required.items() if not value.strip()]
        if empty:
            raise ValueError(f"command envelope contains empty fields: {', '.join(empty)}")
        if not 1 <= self.max_nodes <= 128:
            raise ValueError("max_nodes must be between 1 and 128")
        if not 1 <= self.max_fan_out <= 16:
            raise ValueError("max_fan_out must be between 1 and 16")
```

- [ ] **Step 4: Run contract verification**

Run:

```powershell
uv run pytest tests/contracts/test_commands.py
uv run ruff format src tests
uv run ruff check src/olympus/contracts tests/contracts
uv run mypy
```

Expected: contract tests pass and both static checks exit `0`.

- [ ] **Step 5: Commit the contracts**

```powershell
git add src/olympus/contracts tests/contracts
git commit -m "feat: define trust-aware command contracts"
```

### Task 3: Compile a Bounded, Side-Effect-Free Graph

**Files:**
- Create: `src/olympus/graphs/__init__.py`
- Create: `src/olympus/graphs/models.py`
- Create: `src/olympus/graphs/compiler.py`
- Create: `tests/graphs/test_compiler.py`

- [ ] **Step 1: Write graph-boundary tests**

Create `tests/graphs/test_compiler.py`:

```python
from datetime import UTC, datetime

from olympus.contracts.commands import CommandEnvelope, TrustLabel
from olympus.graphs.compiler import compile_noop_graph


def make_command() -> CommandEnvelope:
    return CommandEnvelope(
        job_id="job-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    )


def test_noop_graph_is_bounded_and_non_mutating() -> None:
    graph = compile_noop_graph(make_command())

    assert graph.job_id == "job-123"
    assert len(graph.nodes) == 1
    assert graph.nodes[0].side_effecting is False
    assert graph.nodes[0].trust_labels == (TrustLabel.USER_AUTHORIZED,)
    assert graph.maximum_nodes == 32
    assert graph.maximum_fan_out == 4


def test_graph_digest_is_stable_for_identical_input() -> None:
    first = compile_noop_graph(make_command())
    second = compile_noop_graph(make_command())
    assert first.digest == second.digest
```

- [ ] **Step 2: Run the tests and confirm the graph module is absent**

Run:

```powershell
uv run pytest tests/graphs/test_compiler.py
```

Expected: collection fails because `olympus.graphs` does not exist.

- [ ] **Step 3: Implement immutable graph models**

Create `src/olympus/graphs/__init__.py`:

```python
"""Bounded execution graph contracts and compilers."""
```

Create `src/olympus/graphs/models.py`:

```python
from dataclasses import dataclass

from olympus.contracts.commands import TrustLabel


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    operation: str
    depends_on: tuple[str, ...]
    side_effecting: bool
    trust_labels: tuple[TrustLabel, ...]


@dataclass(frozen=True)
class CompiledGraph:
    job_id: str
    nodes: tuple[GraphNode, ...]
    maximum_nodes: int
    maximum_fan_out: int
    digest: str
```

- [ ] **Step 4: Implement the deterministic no-op compiler**

Create `src/olympus/graphs/compiler.py`:

```python
import hashlib
import json

from olympus.contracts.commands import CommandEnvelope
from olympus.graphs.models import CompiledGraph, GraphNode


def compile_noop_graph(command: CommandEnvelope) -> CompiledGraph:
    node = GraphNode(
        node_id="acknowledge-command",
        operation="record-command-without-side-effects",
        depends_on=(),
        side_effecting=False,
        trust_labels=(command.trust_label,),
    )
    canonical = {
        "job_id": command.job_id,
        "command_text": command.command_text,
        "authority_lease_id": command.authority_lease_id,
        "nodes": [
            {
                "node_id": node.node_id,
                "operation": node.operation,
                "depends_on": list(node.depends_on),
                "side_effecting": node.side_effecting,
                "trust_labels": [label.value for label in node.trust_labels],
            }
        ],
        "maximum_nodes": command.max_nodes,
        "maximum_fan_out": command.max_fan_out,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return CompiledGraph(
        job_id=command.job_id,
        nodes=(node,),
        maximum_nodes=command.max_nodes,
        maximum_fan_out=command.max_fan_out,
        digest=digest,
    )
```

- [ ] **Step 5: Verify and commit the graph compiler**

Run:

```powershell
uv run pytest tests/graphs/test_compiler.py
uv run ruff format src tests
uv run ruff check src/olympus/graphs tests/graphs
uv run mypy
git add src/olympus/graphs tests/graphs
git commit -m "feat: compile bounded no-op command graphs"
```

Expected: tests and static checks pass; the commit is created.

### Task 4: Put the Graph Behind a Durable Temporal Workflow

**Files:**
- Create: `src/olympus/activities/__init__.py`
- Create: `src/olympus/activities/compile_graph.py`
- Create: `src/olympus/workflows/__init__.py`
- Create: `src/olympus/workflows/command.py`
- Create: `tests/workflows/test_command_workflow.py`

- [ ] **Step 1: Write the Temporal integration test**

Create `tests/workflows/test_command_workflow.py`:

```python
from datetime import UTC, datetime

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.contracts.commands import CommandEnvelope, JobStatus
from olympus.workflows.command import CommandWorkflow


async def test_command_workflow_returns_compiled_receipt() -> None:
    command = CommandEnvelope(
        job_id="job-temporal-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    )

    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="olympus-test",
            workflows=[CommandWorkflow],
            activities=[compile_graph_activity],
        ):
            receipt = await environment.client.execute_workflow(
                CommandWorkflow.run,
                command,
                id=command.job_id,
                task_queue="olympus-test",
            )

    assert receipt.job_id == command.job_id
    assert receipt.status is JobStatus.COMPILED
    assert receipt.node_count == 1
    assert len(receipt.graph_digest) == 64
```

- [ ] **Step 2: Run the test and confirm workflow modules are absent**

Run:

```powershell
uv run pytest tests/workflows/test_command_workflow.py
```

Expected: collection fails because the activity and workflow modules do not exist.

- [ ] **Step 3: Add the compiled job receipt**

Append to `src/olympus/contracts/commands.py`:

```python
@dataclass(frozen=True)
class CompiledJobReceipt:
    job_id: str
    status: JobStatus
    node_count: int
    graph_digest: str
```

- [ ] **Step 4: Implement the activity and workflow**

Create `src/olympus/activities/__init__.py`:

```python
"""Temporal activities; all reasoning and external tools live behind this boundary."""
```

Create `src/olympus/activities/compile_graph.py`:

```python
from temporalio import activity

from olympus.contracts.commands import CommandEnvelope
from olympus.graphs.compiler import compile_noop_graph
from olympus.graphs.models import CompiledGraph


@activity.defn
async def compile_graph_activity(command: CommandEnvelope) -> CompiledGraph:
    return compile_noop_graph(command)
```

Create `src/olympus/workflows/__init__.py`:

```python
"""Durable Temporal workflows owned by Olympus."""
```

Create `src/olympus/workflows/command.py`:

```python
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from olympus.activities.compile_graph import compile_graph_activity
    from olympus.contracts.commands import (
        CommandEnvelope,
        CompiledJobReceipt,
        JobStatus,
    )


@workflow.defn
class CommandWorkflow:
    @workflow.run
    async def run(self, command: CommandEnvelope) -> CompiledJobReceipt:
        graph = await workflow.execute_activity(
            compile_graph_activity,
            command,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        return CompiledJobReceipt(
            job_id=command.job_id,
            status=JobStatus.COMPILED,
            node_count=len(graph.nodes),
            graph_digest=graph.digest,
        )
```

- [ ] **Step 5: Verify Temporal durability and determinism**

Run:

```powershell
uv run pytest tests/workflows/test_command_workflow.py
uv run ruff format src tests
uv run ruff check src tests/workflows
uv run mypy
```

Expected: the Temporal test passes and static checks exit `0`.

- [ ] **Step 6: Commit the durable workflow**

```powershell
git add src/olympus/activities src/olympus/workflows src/olympus/contracts/commands.py tests/workflows
git commit -m "feat: execute command compilation in Temporal"
```

### Task 5: Add a Development-Only Authenticated Gateway

**Files:**
- Create: `src/olympus/gateway/__init__.py`
- Create: `src/olympus/gateway/settings.py`
- Create: `src/olympus/gateway/app.py`
- Create: `tests/gateway/test_app.py`

- [ ] **Step 1: Write gateway authorization tests**

Create `tests/gateway/test_app.py`:

```python
from fastapi.testclient import TestClient

from olympus.contracts.commands import CommandAccepted, CommandEnvelope
from olympus.gateway.app import create_app
from olympus.gateway.settings import GatewaySettings


class FakeStarter:
    def __init__(self) -> None:
        self.commands: list[CommandEnvelope] = []

    async def start(self, command: CommandEnvelope) -> CommandAccepted:
        self.commands.append(command)
        return CommandAccepted(job_id=command.job_id)


def make_client(starter: FakeStarter) -> TestClient:
    settings = GatewaySettings(
        environment="test",
        dev_command_token="test-token-with-at-least-32-bytes",
    )
    return TestClient(create_app(settings=settings, starter=starter))


def test_health_is_public() -> None:
    client = make_client(FakeStarter())
    assert client.get("/health/live").json() == {"status": "ok"}


def test_command_rejects_missing_token() -> None:
    client = make_client(FakeStarter())
    response = client.post(
        "/v1/commands",
        headers={
            "X-Olympus-Commander": "discord-user-123",
            "X-Olympus-Authority-Lease": "lease-456",
        },
        json={"command": "inspect the graph"},
    )
    assert response.status_code == 401


def test_command_requires_literal_authority_headers() -> None:
    client = make_client(FakeStarter())
    response = client.post(
        "/v1/commands",
        headers={"Authorization": "Bearer test-token-with-at-least-32-bytes"},
        json={"command": "inspect the graph"},
    )
    assert response.status_code == 422


def test_command_starts_workflow_with_user_authorized_taint() -> None:
    starter = FakeStarter()
    client = make_client(starter)
    response = client.post(
        "/v1/commands",
        headers={
            "Authorization": "Bearer test-token-with-at-least-32-bytes",
            "X-Olympus-Commander": "discord-user-123",
            "X-Olympus-Authority-Lease": "lease-456",
        },
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert starter.commands[0].commander_id == "discord-user-123"
    assert starter.commands[0].authority_lease_id == "lease-456"
```

- [ ] **Step 2: Run the tests and confirm the gateway is absent**

Run:

```powershell
uv run pytest tests/gateway/test_app.py
```

Expected: collection fails because `olympus.gateway` does not exist.

- [ ] **Step 3: Implement settings that cannot represent production**

Create `src/olympus/gateway/__init__.py`:

```python
"""Private command gateway for Olympus."""
```

Create `src/olympus/gateway/settings.py`:

```python
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OLYMPUS_",
        env_file=".env",
        extra="forbid",
    )

    environment: Literal["development", "test"]
    dev_command_token: SecretStr = Field(min_length=32)
    temporal_address: str = "127.0.0.1:7233"
    temporal_task_queue: str = "olympus-command-v1"
```

- [ ] **Step 4: Implement the gateway and Temporal starter**

Create `src/olympus/gateway/app.py`:

```python
import hmac
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, status
from temporalio.client import Client

from olympus.contracts.commands import (
    CommandAccepted,
    CommandEnvelope,
    CommandRequest,
)
from olympus.gateway.settings import GatewaySettings
from olympus.workflows.command import CommandWorkflow


class CommandStarter(Protocol):
    async def start(self, command: CommandEnvelope) -> CommandAccepted: ...


class TemporalCommandStarter:
    def __init__(self, client: Client, task_queue: str) -> None:
        self._client = client
        self._task_queue = task_queue

    async def start(self, command: CommandEnvelope) -> CommandAccepted:
        await self._client.start_workflow(
            CommandWorkflow.run,
            command,
            id=command.job_id,
            task_queue=self._task_queue,
        )
        return CommandAccepted(job_id=command.job_id)


def create_app(settings: GatewaySettings, starter: CommandStarter) -> FastAPI:
    app = FastAPI(title="Olympus Gateway", version="0.1.0")

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/commands",
        response_model=CommandAccepted,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_command(
        request: CommandRequest,
        authorization: str | None = Header(default=None),
        commander_id: str = Header(alias="X-Olympus-Commander", min_length=1),
        authority_lease_id: str = Header(
            alias="X-Olympus-Authority-Lease",
            min_length=1,
        ),
    ) -> CommandAccepted:
        expected = f"Bearer {settings.dev_command_token.get_secret_value()}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid development command token",
            )
        command = CommandEnvelope(
            job_id=f"job-{uuid4()}",
            commander_id=commander_id,
            authority_lease_id=authority_lease_id,
            command_text=request.command,
            received_at=datetime.now(UTC).isoformat(),
        )
        return await starter.start(command)

    return app
```

- [ ] **Step 5: Verify the development-only boundary**

Run:

```powershell
uv run pytest tests/gateway/test_app.py
uv run ruff format src tests
uv run ruff check src/olympus/gateway tests/gateway
uv run mypy
```

Expected: four gateway tests pass. `GatewaySettings(environment="production", ...)` is rejected by Pydantic because production authentication is intentionally unavailable.

- [ ] **Step 6: Commit the gateway**

```powershell
git add src/olympus/gateway tests/gateway
git commit -m "feat: add development-only command gateway"
```

### Task 6: Add Loopback-Only Local Runtime Entrypoints

**Files:**
- Create: `.env.example`
- Create: `src/olympus/runtime/__init__.py`
- Create: `src/olympus/runtime/gateway.py`
- Create: `src/olympus/runtime/worker.py`
- Modify: `src/olympus/gateway/settings.py`
- Modify: `tests/gateway/test_app.py`

- [ ] **Step 1: Prove the development gateway cannot bind publicly**

Add these imports to the existing import block in `tests/gateway/test_app.py`:

```python
import pytest
from pydantic import ValidationError
```

Append this test:

```python
def test_development_gateway_rejects_public_bind() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(
            environment="development",
            dev_command_token="test-token-with-at-least-32-bytes",
            http_host="0.0.0.0",
        )
```

Run:

```powershell
uv run pytest tests/gateway/test_app.py::test_development_gateway_rejects_public_bind
```

Expected: test fails because `GatewaySettings` does not yet define a protected bind address.

- [ ] **Step 2: Add loopback-only runtime settings**

Append these fields to `GatewaySettings` in `src/olympus/gateway/settings.py`:

```python
    http_host: Literal["127.0.0.1"] = "127.0.0.1"
    http_port: int = Field(default=8080, ge=1024, le=65535)
```

Create `.env.example`:

```dotenv
OLYMPUS_ENVIRONMENT=development
OLYMPUS_DEV_COMMAND_TOKEN=development-only-token-change-before-use
OLYMPUS_TEMPORAL_ADDRESS=127.0.0.1:7233
OLYMPUS_TEMPORAL_TASK_QUEUE=olympus-command-v1
OLYMPUS_HTTP_HOST=127.0.0.1
OLYMPUS_HTTP_PORT=8080
```

- [ ] **Step 3: Implement the Temporal worker process**

Create `src/olympus/runtime/__init__.py`:

```python
"""Local process entrypoints for the foundation slice."""
```

Create `src/olympus/runtime/worker.py`:

```python
import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.gateway.settings import GatewaySettings
from olympus.workflows.command import CommandWorkflow


async def run() -> None:
    settings = GatewaySettings()
    client = await Client.connect(settings.temporal_address)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[CommandWorkflow],
        activities=[compile_graph_activity],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run())
```

- [ ] **Step 4: Implement the loopback gateway process**

Create `src/olympus/runtime/gateway.py`:

```python
import asyncio

import uvicorn
from temporalio.client import Client

from olympus.gateway.app import TemporalCommandStarter, create_app
from olympus.gateway.settings import GatewaySettings


async def run() -> None:
    settings = GatewaySettings()
    client = await Client.connect(settings.temporal_address)
    app = create_app(
        settings=settings,
        starter=TemporalCommandStarter(
            client=client,
            task_queue=settings.temporal_task_queue,
        ),
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app=app,
            host=settings.http_host,
            port=settings.http_port,
            log_level="info",
        )
    )
    await server.serve()


if __name__ == "__main__":
    asyncio.run(run())
```

- [ ] **Step 5: Verify and commit the local runtime**

Run:

```powershell
uv run pytest tests/gateway/test_app.py
uv run ruff format src tests
uv run ruff check src tests
uv run mypy
git add .env.example src/olympus/runtime src/olympus/gateway/settings.py tests/gateway/test_app.py
git commit -m "feat: add loopback-only local runtime"
```

Expected: gateway tests and static checks pass; the runtime commit is created.

### Task 7: Turn the VPS-4 Resource Envelope Into an Executable Policy

**Files:**
- Create: `config/capacity/vps4.yaml`
- Create: `src/olympus/capacity/__init__.py`
- Create: `src/olympus/capacity/models.py`
- Create: `tests/capacity/test_vps4_capacity.py`

- [ ] **Step 1: Write capacity-policy tests**

Create `tests/capacity/test_vps4_capacity.py`:

```python
from pathlib import Path

import pytest
from pydantic import ValidationError

from olympus.capacity.models import CapacityPlan, load_capacity_plan

CAPACITY_FILE = Path("config/capacity/vps4.yaml")


def test_vps4_plan_matches_approved_aggregate_limits() -> None:
    plan = load_capacity_plan(CAPACITY_FILE)

    assert plan.allocatable.cpu_millicores == 7000
    assert plan.allocatable.memory_mib == 22528
    assert plan.always_on_cpu_request == 3000
    assert plan.always_on_memory_request == 8960
    assert plan.always_on_memory_limit <= 11776
    assert plan.worker_quota.memory_request_mib == 8704
    assert plan.worker_quota.memory_limit_mib == 10752
    assert plan.unrequested_memory_mib >= 4864


def test_capacity_rejects_memory_limit_overcommit() -> None:
    raw = load_capacity_plan(CAPACITY_FILE).model_dump()
    raw["worker_quota"]["memory_limit_mib"] = 12000

    with pytest.raises(ValidationError, match="memory limits exceed"):
        CapacityPlan.model_validate(raw)
```

- [ ] **Step 2: Run the tests and confirm capacity code is absent**

Run:

```powershell
uv run pytest tests/capacity/test_vps4_capacity.py
```

Expected: collection fails because `olympus.capacity` does not exist.

- [ ] **Step 3: Encode the approved capacity plan**

Create `config/capacity/vps4.yaml`:

```yaml
schema_version: 1
node:
  cpu_millicores: 8000
  memory_mib: 24576
reserved:
  cpu_millicores: 1000
  memory_mib: 2048
allocatable:
  cpu_millicores: 7000
  memory_mib: 22528
always_on:
  - {name: postgres, cpu_request_millicores: 750, cpu_limit_millicores: 2000, memory_request_mib: 3072, memory_limit_mib: 4096}
  - {name: temporal-frontend, cpu_request_millicores: 100, cpu_limit_millicores: 400, memory_request_mib: 256, memory_limit_mib: 320}
  - {name: temporal-history, cpu_request_millicores: 150, cpu_limit_millicores: 500, memory_request_mib: 384, memory_limit_mib: 512}
  - {name: temporal-matching, cpu_request_millicores: 75, cpu_limit_millicores: 300, memory_request_mib: 192, memory_limit_mib: 224}
  - {name: temporal-internal-worker, cpu_request_millicores: 75, cpu_limit_millicores: 300, memory_request_mib: 192, memory_limit_mib: 224}
  - {name: redis, cpu_request_millicores: 100, cpu_limit_millicores: 500, memory_request_mib: 256, memory_limit_mib: 400}
  - {name: minio, cpu_request_millicores: 200, cpu_limit_millicores: 1000, memory_request_mib: 512, memory_limit_mib: 768}
  - {name: discord-gateway, cpu_request_millicores: 100, cpu_limit_millicores: 300, memory_request_mib: 128, memory_limit_mib: 192}
  - {name: supervisor, cpu_request_millicores: 300, cpu_limit_millicores: 1000, memory_request_mib: 768, memory_limit_mib: 896}
  - {name: temporal-app-worker, cpu_request_millicores: 150, cpu_limit_millicores: 500, memory_request_mib: 256, memory_limit_mib: 288}
  - {name: policy, cpu_request_millicores: 50, cpu_limit_millicores: 200, memory_request_mib: 96, memory_limit_mib: 160}
  - {name: budget, cpu_request_millicores: 50, cpu_limit_millicores: 150, memory_request_mib: 80, memory_limit_mib: 144}
  - {name: audit, cpu_request_millicores: 50, cpu_limit_millicores: 150, memory_request_mib: 80, memory_limit_mib: 144}
  - {name: approval, cpu_request_millicores: 50, cpu_limit_millicores: 200, memory_request_mib: 128, memory_limit_mib: 160}
  - {name: prometheus, cpu_request_millicores: 250, cpu_limit_millicores: 750, memory_request_mib: 768, memory_limit_mib: 896}
  - {name: loki, cpu_request_millicores: 150, cpu_limit_millicores: 500, memory_request_mib: 512, memory_limit_mib: 640}
  - {name: tempo, cpu_request_millicores: 100, cpu_limit_millicores: 300, memory_request_mib: 384, memory_limit_mib: 448}
  - {name: grafana, cpu_request_millicores: 50, cpu_limit_millicores: 200, memory_request_mib: 128, memory_limit_mib: 256}
  - {name: otel-collector, cpu_request_millicores: 100, cpu_limit_millicores: 250, memory_request_mib: 256, memory_limit_mib: 320}
  - {name: ingress, cpu_request_millicores: 50, cpu_limit_millicores: 250, memory_request_mib: 128, memory_limit_mib: 160}
  - {name: secrets-broker, cpu_request_millicores: 50, cpu_limit_millicores: 250, memory_request_mib: 128, memory_limit_mib: 160}
  - {name: backup-controller, cpu_request_millicores: 50, cpu_limit_millicores: 250, memory_request_mib: 256, memory_limit_mib: 280}
worker_quota:
  cpu_request_millicores: 3500
  memory_request_mib: 8704
  memory_limit_mib: 10752
required_headroom:
  cpu_millicores: 500
  memory_mib: 4864
```

- [ ] **Step 4: Implement aggregate validation**

Create `src/olympus/capacity/__init__.py`:

```python
"""Machine-enforced resource envelopes."""
```

Create `src/olympus/capacity/models.py`:

```python
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResourceTotal(StrictModel):
    cpu_millicores: int
    memory_mib: int


class WorkloadResources(StrictModel):
    name: str
    cpu_request_millicores: int
    cpu_limit_millicores: int
    memory_request_mib: int
    memory_limit_mib: int


class WorkerQuota(StrictModel):
    cpu_request_millicores: int
    memory_request_mib: int
    memory_limit_mib: int


class CapacityPlan(StrictModel):
    schema_version: int
    node: ResourceTotal
    reserved: ResourceTotal
    allocatable: ResourceTotal
    always_on: list[WorkloadResources]
    worker_quota: WorkerQuota
    required_headroom: ResourceTotal

    @property
    def always_on_cpu_request(self) -> int:
        return sum(item.cpu_request_millicores for item in self.always_on)

    @property
    def always_on_memory_request(self) -> int:
        return sum(item.memory_request_mib for item in self.always_on)

    @property
    def always_on_memory_limit(self) -> int:
        return sum(item.memory_limit_mib for item in self.always_on)

    @property
    def unrequested_memory_mib(self) -> int:
        return (
            self.allocatable.memory_mib
            - self.always_on_memory_request
            - self.worker_quota.memory_request_mib
        )

    @model_validator(mode="after")
    def validate_envelope(self) -> Self:
        if self.node.cpu_millicores - self.reserved.cpu_millicores != self.allocatable.cpu_millicores:
            raise ValueError("allocatable CPU does not match node minus reserved")
        if self.node.memory_mib - self.reserved.memory_mib != self.allocatable.memory_mib:
            raise ValueError("allocatable memory does not match node minus reserved")
        if self.always_on_cpu_request + self.worker_quota.cpu_request_millicores > self.allocatable.cpu_millicores:
            raise ValueError("CPU requests exceed allocatable capacity")
        if self.unrequested_memory_mib < self.required_headroom.memory_mib:
            raise ValueError("memory requests consume required headroom")
        if self.always_on_memory_limit + self.worker_quota.memory_limit_mib > self.allocatable.memory_mib:
            raise ValueError("memory limits exceed allocatable capacity")
        return self


def load_capacity_plan(path: Path) -> CapacityPlan:
    return CapacityPlan.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
```

- [ ] **Step 5: Verify and commit executable capacity policy**

Run:

```powershell
uv run pytest tests/capacity/test_vps4_capacity.py
uv run ruff format src tests
uv run ruff check src/olympus/capacity tests/capacity
uv run mypy
git add config/capacity src/olympus/capacity tests/capacity
git commit -m "feat: enforce VPS-4 capacity envelope"
```

Expected: both capacity tests pass and the commit is created.

### Task 8: Establish Kubernetes Scheduling Guardrails

**Files:**
- Create: `deploy/helm/olympus-foundation/Chart.yaml`
- Create: `deploy/helm/olympus-foundation/values.yaml`
- Create: `deploy/helm/olympus-foundation/templates/namespaces.yaml`
- Create: `deploy/helm/olympus-foundation/templates/priority-classes.yaml`
- Create: `deploy/helm/olympus-foundation/templates/worker-quota.yaml`

- [ ] **Step 1: Create the chart metadata and exact values**

Create `deploy/helm/olympus-foundation/Chart.yaml`:

```yaml
apiVersion: v2
name: olympus-foundation
description: Namespaces, priorities, and capacity guardrails for Olympus
type: application
version: 0.1.0
appVersion: "0.1.0"
```

Create `deploy/helm/olympus-foundation/values.yaml`:

```yaml
namespaces:
  - agent-control
  - agent-data
  - agent-platform
  - agent-workers-local

workerQuota:
  requestsCpu: "3500m"
  requestsMemory: "8704Mi"
  limitsMemory: "10752Mi"
  pods: "8"
```

- [ ] **Step 2: Create isolated namespaces**

Create `deploy/helm/olympus-foundation/templates/namespaces.yaml`:

```yaml
{{- range .Values.namespaces }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ . }}
  labels:
    app.kubernetes.io/part-of: olympus
    olympus.dev/default-deny-network: "required"
{{- end }}
```

- [ ] **Step 3: Create deterministic scheduling priorities**

Create `deploy/helm/olympus-foundation/templates/priority-classes.yaml`:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: olympus-control
value: 100000
globalDefault: false
description: Olympus control, policy, audit, Temporal, and PostgreSQL
---
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: olympus-platform
value: 50000
globalDefault: false
description: Olympus observability and platform controllers
---
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: olympus-worker
value: 10000
globalDefault: false
preemptionPolicy: PreemptLowerPriority
description: Preemptible Olympus agent, browser, build, and verifier jobs
```

- [ ] **Step 4: Enforce the local worker quota**

Create `deploy/helm/olympus-foundation/templates/worker-quota.yaml`:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: olympus-local-worker-budget
  namespace: agent-workers-local
spec:
  hard:
    requests.cpu: {{ .Values.workerQuota.requestsCpu | quote }}
    requests.memory: {{ .Values.workerQuota.requestsMemory | quote }}
    limits.memory: {{ .Values.workerQuota.limitsMemory | quote }}
    pods: {{ .Values.workerQuota.pods | quote }}
```

- [ ] **Step 5: Render and inspect the chart**

Run:

```powershell
New-Item -ItemType Directory -Force work | Out-Null
helm lint deploy/helm/olympus-foundation
helm template olympus deploy/helm/olympus-foundation --namespace agent-control | Out-File -Encoding utf8 work/olympus-foundation.yaml
kubectl apply --dry-run=client -f work/olympus-foundation.yaml
```

Expected: Helm lint reports `0 chart(s) failed`; Kubernetes dry-run reports each object as `created (dry run)`.

- [ ] **Step 6: Commit the scheduling foundation**

```powershell
git add deploy/helm/olympus-foundation
git commit -m "feat: establish Kubernetes capacity guardrails"
```

### Task 9: Add Continuous Verification

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the GitHub Actions workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  python:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
        with:
          enable-cache: true
      - run: uv python install 3.13
      - run: uv sync --locked --all-groups
      - run: uv run ruff format --check src tests
      - run: uv run ruff check src tests
      - run: uv run mypy
      - run: uv run pytest

  helm:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
      - run: helm lint deploy/helm/olympus-foundation
      - run: helm template olympus deploy/helm/olympus-foundation --namespace agent-control > /tmp/olympus-foundation.yaml
      - run: test "$(grep -c '^kind: Namespace$' /tmp/olympus-foundation.yaml)" -eq 4
      - run: grep -q 'requests.memory: "8704Mi"' /tmp/olympus-foundation.yaml
      - run: grep -q 'limits.memory: "10752Mi"' /tmp/olympus-foundation.yaml
```

- [ ] **Step 2: Run the same checks locally**

Run:

```powershell
uv sync --locked --all-groups
uv run ruff format src tests
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy
uv run pytest
helm lint deploy/helm/olympus-foundation
helm template olympus deploy/helm/olympus-foundation --namespace agent-control | Out-Null
```

Expected: every command exits `0`.

- [ ] **Step 3: Commit continuous verification**

```powershell
git add .github/workflows/ci.yml
git commit -m "ci: verify workflows and deployment guardrails"
```

### Task 10: Document the First Execution Gate

**Files:**
- Modify: `README.md`
- Create: `docs/implementation/phase-0-foundation-acceptance.md`

- [ ] **Step 1: Add exact local verification commands to the README**

Append:

````markdown
## Development verification

Prerequisites: Python 3.13, uv, Temporal CLI, Helm 3, and kubectl.

```powershell
uv sync --locked --all-groups
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy
uv run pytest
helm lint deploy/helm/olympus-foundation
helm template olympus deploy/helm/olympus-foundation --namespace agent-control
```

To run the walking skeleton, copy `.env.example` to `.env`, then use three terminals:

```powershell
temporal server start-dev --db-filename work/temporal.db
uv run python -m olympus.runtime.worker
uv run python -m olympus.runtime.gateway
```

Submit the development-only command:

```powershell
$headers = @{
  Authorization = "Bearer development-only-token-change-before-use"
  "X-Olympus-Commander" = "local-jerry"
  "X-Olympus-Authority-Lease" = "development-lease"
}
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8080/v1/commands" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{"command":"inspect the active graph"}'
```

This slice cannot execute external effects or run with production authentication.
````

- [ ] **Step 2: Create the acceptance record**

Create `docs/implementation/phase-0-foundation-acceptance.md`:

```markdown
# Phase 0 Foundation Walking Skeleton Acceptance

The slice is accepted only when one CI run on the implementation branch proves:

- Command contract rejects blank, oversized, and structurally invalid input.
- Missing development token is rejected.
- Commander and authority-lease identifiers are captured literally.
- Temporal workflow survives the integration-test worker boundary.
- Compiled graph has one node, no side effects, bounded node/fan-out values, and a stable digest.
- VPS-4 capacity requests preserve at least 4.75 GiB unrequested memory.
- Aggregate platform and worker memory limits do not exceed 22 GiB.
- Helm renders four namespaces, three priority classes, and the exact worker quota.
- Ruff formatting, Ruff lint, mypy strict mode, pytest, and Helm lint all pass.

Passing this gate authorizes planning the Discord identity and authority-lease slice. It does not authorize live VPS deployment or any external mutation.
```

- [ ] **Step 3: Run the complete gate**

Run:

```powershell
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy
uv run pytest
helm lint deploy/helm/olympus-foundation
git diff --check
git status --short
```

Expected: all checks exit `0`; status contains only the README and acceptance record intended for this task.

- [ ] **Step 4: Commit the acceptance gate**

```powershell
git add README.md docs/implementation/phase-0-foundation-acceptance.md
git commit -m "docs: define foundation acceptance gate"
```

## Follow-on Plan Order

After this plan passes:

1. Discord gateway, verified commander identity, 24-hour authority lease, anomaly revocation, and `/freeze`.
2. Immutable policy bundle schema, literal signed approval payload, budget governor, taint propagation, and append-only audit.
3. Worker isolation for Claude, Codex, Chromium, and verifier jobs with admission control.
4. PostgreSQL/pgvector, Redis, MinIO, Temporal persistence, and the production observability stack.
5. Gmail, Calendar, Drive, GitHub, browser, and cloud adapters with effect-specific reconciliation.
6. Root broker and VPS typed operations, implemented only after the approval and policy supply chains pass adversarial tests.

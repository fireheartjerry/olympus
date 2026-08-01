# Olympus

Olympus is Jerry's private, always-on agent orchestration platform: one governed command surface coordinating durable Claude, Codex, browser, Workspace, GitHub, and infrastructure workflows.

The implementation source of truth is the approved [design specification](docs/superpowers/specs/2026-07-28-agentic-vps-god-agent-design.md). Work begins with a side-effect-free vertical slice before privileged adapters or production mutations are enabled.

## Status

- Architecture: approved and resource-sized for the OVH VPS-4 production-v1 node.
- Implementation: the foundation walking skeleton is implemented and verified locally; remote CI evidence is pending a successful pull-request run from the implementation branch or a post-merge `main` run.
- Repository visibility: public.

## Delivery sequence

1. Foundation and durable no-op command path.
2. Discord identity, authority leases, and inspect/freeze controls.
3. Signed policy, budget, approval, audit, and taint enforcement.
4. Isolated local Claude, Codex, browser, and verifier workers.
5. Workspace, GitHub, browser, and infrastructure adapters with reconciliation.
6. Production rollout gates, high autonomy, and optional elastic workers.

Security invariants in the approved design are release blockers, not backlog suggestions.

## Foundation walking skeleton

This local-only slice accepts a development-token command at a loopback-only
gateway, starts a Temporal workflow, and compiles one bounded no-op graph. The
graph's only operation is `record-command-without-side-effects`; it does not
contact a target integration or live infrastructure, or call an external-effect
API. It is not production authentication or an authorization mechanism. Local
verification can make read-only package, checked-tool, and pinned-schema
downloads; those do not exercise a target integration, live infrastructure, or
an external effect API.

The accompanying Helm chart is also a guardrail, not a deployment of the
control plane. It renders four namespaces, three fixed priority classes, and
the fixed local-worker `ResourceQuota`. Control and platform work have higher
priority; the chart defines the non-preempting `olympus-worker` class at
priority `-10000`, but assigns it to no workload in this slice. These singleton
resources use Helm's `keep` lifecycle annotation. The chart intentionally
installs no `NetworkPolicy`: its namespace labels and annotations record the
required, pending network-policy and blocked-admission status, but are inert
metadata. Actual admission and network enforcement remain pending the separate
network-policy security slice. Rendering and validation never contact a
cluster.

## Execution node mesh

The VPS is the canonical always-on brain. Enrolled computers — the VPS itself,
Jerry's Windows PC, future cloud machines — are execution nodes that expose
typed, versioned capabilities. Nodes always dial out to the control plane over
Tailscale-private networking; nothing dials a node, and no inbound Windows port
is opened. The phone, Discord, and the HTTP API are command and observation
surfaces, never execution nodes.

The approved design is
[the node-mesh specification](docs/superpowers/specs/2026-08-01-distributed-execution-node-mesh-design.md).
The operator runbook, threat model, and revocation procedures are in
[docs/operations/node-mesh.md](docs/operations/node-mesh.md).

Exactly one capability is dispatchable in this slice: `system.inspect@1`, a
bounded read-only host report that reads no environment variable, no process
list, no network configuration, and no user data, launches no subprocess, and
opens only the two fixed Linux counter files `/proc/meminfo` and
`/proc/uptime`. `shell.powershell@1`, `fs.read@1`, `fs.write@1`, `agent.claude@1`,
`agent.codex@1`, `browser.session@1`, `desktop.stream@1`, and
`desktop.takeover@1` exist in the catalog as **reserved** and are refused at
dispatch.

The registry and audit chain are in-process today; PostgreSQL becomes their
canonical owner in the persistence slice. Nothing here is deployed.

### Run the end-to-end demonstration

This starts an ephemeral Temporal dev server, the gateway on a loopback port, a
real node agent over a real WebSocket, and then issues an enrollment token,
enrolls, dispatches a job, streams progress, prints the result, exercises the
dispatch kill switch, and prints the verified audit chain.

```powershell
uv run python -m olympus.demo.node_mesh
```

It contacts no external service, mutates no host state, and opens no listener
other than a loopback port it chooses itself. The first run downloads the
Temporal CLI dev server.

## Development verification

Use CPython 3.13 (CI installs 3.13.13) and uv. The Helm gate additionally
requires Helm 3.17.3 and kubeconform 0.8.0. The GitHub Actions workflow pins
those tool versions and archive checksums; local installed tools or checked
portable binaries are both supported. `kubectl` and a Kubernetes cluster are
not prerequisites because this gate renders only.

Choose one way to provide the chart tools before running the gate:

```powershell
# Installed tools on PATH.
$env:OLYMPUS_HELM_PATH = (Get-Command helm -ErrorAction Stop).Source
$env:OLYMPUS_KUBECONFORM_PATH = (Get-Command kubeconform -ErrorAction Stop).Source
```

```powershell
# Or checked portable 3.17.3 / 0.8.0 binaries.
$env:OLYMPUS_HELM_PATH = "C:\tools\helm-3.17.3\helm.exe"
$env:OLYMPUS_KUBECONFORM_PATH = "C:\tools\kubeconform-0.8.0\kubeconform.exe"
```

The chart verifier uses Kubernetes 1.36.1 schemas pinned to commit
`05eeed51991935dd1f47cd3b3682de4e8af233f3`; do not substitute a floating
schema URL.

```powershell
$kubernetesVersion = "1.36.1"
$schemaLocation = "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/05eeed51991935dd1f47cd3b3682de4e8af233f3/{{.NormalizedKubernetesVersion}}-standalone-strict/{{.ResourceKind}}.json"

uv lock --check
uv sync --locked --all-groups
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy
uv run pytest -W error
pwsh -NoLogo -NoProfile -File deploy/helm/olympus-foundation/tests/verify.ps1 `
  -HelmPath $env:OLYMPUS_HELM_PATH `
  -KubeconformPath $env:OLYMPUS_KUBECONFORM_PATH `
  -KubernetesVersion $kubernetesVersion `
  -SchemaLocation $schemaLocation
git diff --check
```

`verify.ps1` runs strict Helm lint, renders the chart, validates the eight
rendered objects with kubeconform strict mode, compares the quota with the
VPS-4 capacity plan, and proves invalid capacity and namespace overrides fail
even when Helm schema validation is skipped.

## Manual local demo (operator procedure)

The following is a three-terminal operator procedure, not accepted local
evidence: the Temporal CLI was unavailable when the acceptance record was
written, so this walkthrough was not executed here. The automated Temporal
integration test is the local evidence for the workflow/worker boundary.

In a setup/request terminal, create a local, ignored `.env` only when one does
not already exist. The snippet generates a cryptographically random 256-bit
token as 64 lowercase hexadecimal characters, does not print it, and replaces
the exact checked-in placeholder only in the newly copied ignored `.env`. Keep
this terminal open for the request below so it can reuse `$devToken`. A
64-character hex token satisfies `GatewaySettings`: 32--256 visible ASCII
characters.

```powershell
if (Test-Path .env) { throw ".env already exists; leave it unchanged." }
$devToken = -join ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32) | ForEach-Object { $_.ToString("x2") })
Copy-Item .env.example .env -ErrorAction Stop
$placeholder = "OLYMPUS_DEV_COMMAND_TOKEN=development-only-token-change-before-use"
$envContents = $null
try {
  $envContents = Get-Content -Raw -LiteralPath .env
  if (-not $envContents.Contains($placeholder)) { throw "Expected development token placeholder is missing." }
  $envContents = $envContents.Replace($placeholder, "OLYMPUS_DEV_COMMAND_TOKEN=$devToken")
  Set-Content -LiteralPath .env -Value $envContents -Encoding utf8 -NoNewline
}
finally {
  $envContents = $null
  Remove-Variable -Name envContents -ErrorAction SilentlyContinue
  Remove-Variable -Name placeholder -ErrorAction SilentlyContinue
}
```

In three terminals at the repository root, run:

```powershell
# Terminal 1: local Temporal state only (under ignored work/).
New-Item -ItemType Directory -Force work | Out-Null
temporal server start-dev --db-filename work/temporal.db
```

```powershell
# Terminal 2: local Temporal worker.
uv run python -m olympus.runtime.worker
```

```powershell
# Terminal 3: loopback-only HTTP gateway.
uv run python -m olympus.runtime.gateway
```

From the setup/request terminal that retains `$devToken`, submit this literal
development request and then remove shell variables containing the token:

```powershell
$headers = @{
  Authorization = "Bearer $devToken"
  "X-Olympus-Commander" = "local-jerry"
  "X-Olympus-Authority-Lease" = "development-lease"
}
try {
  Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8080/v1/commands" `
    -Headers $headers `
    -ContentType "application/json" `
    -Body '{"command":"inspect the active graph"}'
}
finally {
  $headers = $null
  Remove-Variable -Name headers -ErrorAction SilentlyContinue
  Remove-Variable -Name devToken -ErrorAction SilentlyContinue
}
```

The expected result is an HTTP `202 Accepted` response containing a generated
job ID and `accepted` status. It starts only the bounded, non-side-effecting
workflow described above; it does not authorize or perform a live VPS or
external effect.

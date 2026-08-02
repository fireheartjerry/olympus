# Olympus — Agentic VPS God Agent Design Specification

**Status:** Approved

**Date:** 2026-07-28

**Owner:** Jerry

**Project codename:** Olympus

**Deployment target:** OVH VPS-4 `vps-41e741fc.vps.ovh.ca` (`144.217.94.114`), Ubuntu, with elastic cloud workers

## 1. Objective

Build an always-on personal orchestration system controlled from Jerry's private 9to5 Discord server. Wispr Flow supplies voice-to-text input on the phone; Discord is the command surface; a durable central agent plans and coordinates work across the VPS, Google Workspace, GitHub, browsers, cloud infrastructure, Codex, Claude, and future integrations.

The system must feel like one coherent "God Agent" while retaining strict technical boundaries around root access, credentials, spending, and irreversible actions.

## 2. Success Criteria

The finished system must:

1. Accept natural-language commands exclusively from Jerry's Discord user ID.
2. Acknowledge accepted commands within two seconds at p95.
3. Compile complex requests into durable, inspectable execution graphs.
4. Run independent graph branches concurrently across local and temporary K3s workers.
5. Resume accepted jobs after worker, process, network, or VPS failures while protecting every external effect through native idempotency or an explicit dedupe-and-reconciliation strategy.
6. Operate Google Drive, Docs, Sheets, Gmail, Calendar, GitHub, headless browsers, local projects, and cloud infrastructure.
7. Act autonomously for routine work and require Face ID only for catastrophic or explicitly protected actions.
8. Autonomously spend no more than $20 per calendar month and never exceed $50 of agent-controlled variable monthly infrastructure/API spending; company-approved fixed base infrastructure is tracked separately.
9. Preserve a tamper-evident audit trail and verified long-term memory.
10. Provide immediate `/freeze`, pause, redirect, inspect, cancel, and recovery controls from the phone.
11. Sustain the production-v1 mixed workload—three Claude/Codex jobs, two isolated browser sessions, and one verifier—without OOM eviction or loss of control-plane SLOs.

## 3. Non-goals

- Exposing an unrestricted root shell directly to Discord or an LLM.
- Allowing commands from other Discord users in the first release.
- Giving model-generated content authority merely because it appears in email, Drive, a webpage, an attachment, or another agent's output.
- Running permanent expensive cloud workers when local or temporary capacity is sufficient.
- Building a fully decentralized swarm with no authoritative planner.
- Making Kubernetes the workflow engine or reasoning layer.

## 4. Approved Decisions

| Area | Decision |
|---|---|
| Command surface | Existing private 9to5 Discord server |
| Discord structure | `AGENT OPS` category with dedicated operational channels |
| Authorized commander | Jerry's Discord user ID only |
| Approval mechanism | WebAuthn passkey requiring phone Face ID |
| Discord authority | Face-ID-issued 24-hour authority lease with anomaly-triggered revocation |
| Autonomy | Nearly fully autonomous; Face ID only for protected actions |
| Autonomous spend | $20 per calendar month |
| Fixed base infrastructure | Company-approved recurring cost, tracked separately from agent-controlled variable spend |
| Absolute variable spend | $50 per calendar month |
| Orchestrator | Custom, model-agnostic daemon |
| Execution isolation | K3s worker pods and isolated Git worktrees |
| Privilege model | Non-root orchestrator plus host-only root broker |
| Workflow runtime | Temporal outer workflows |
| Agent reasoning | LangGraph inner subgraphs |
| Models | Claude/Codex subscriptions first; paid APIs as metered fallback |
| Scaling | Existing VPS control plane plus temporary K3s cloud agents |
| Data architecture | Adaptive polyglot layer with one canonical owner per datum |
| Version-one footprint | K3s, Temporal, PostgreSQL/pgvector, Redis, MinIO, Prometheus, Grafana, Loki, Tempo, core control services, local workers, and encrypted off-VPS backups |

## 5. System Architecture

```mermaid
flowchart TD
    W["Wispr Flow"] --> D["Discord Gateway"]
    E["Email / Calendar / GitHub / Cron Events"] --> D
    M["Mobile Dashboard"] --> D

    D --> I["Identity + Input Normalization"]
    I --> G["Central God Agent / Supervisor"]
    G --> C["Context Assembler"]
    G --> P["Policy + Budget Engine"]
    G --> DC["DAG Compiler"]

    P --> Q{"Protected action?"}
    Q -- Yes --> F["Face ID / WebAuthn Approval"]
    F --> T["Temporal Workflow"]
    Q -- No --> T
    DC --> T

    T --> L["LangGraph Reasoning Subgraphs"]
    T --> S["Priority Scheduler"]
    S --> K["Local K3s Worker Pools"]
    S --> B["Temporary Cloud K3s Agents"]

    K --> CW["Codex / Claude"]
    K --> BW["Browser Fleet"]
    K --> GW["Google Workspace"]
    K --> OW["GitHub / Cloud / Data / Documents"]
    K --> V["Verifier + Critic"]

    P --> RB["Host-only Root Broker"]
    RB --> H["VPS Host Operations"]

    V --> R{"Evidence passes?"}
    R -- Yes --> O["Result Synthesis + Discord Delivery"]
    R -- "No, revision budget remains" --> L
    R -- "No, budget exhausted" --> X["Escalate or fail safely"]

    T --> DB["PostgreSQL Job State"]
    K --> A["MinIO Artifacts"]
    O --> KG["Verified Memory + Knowledge Graph"]
    T --> AU["Audit + Metrics + Traces"]
```

### 5.1 Architectural Principle

The user experiences one central agent, but execution is distributed. The supervisor owns the objective, global context, prioritization, delegation, and final synthesis. Specialized workers own narrow tasks. Workers exchange typed events and structured artifacts rather than unbounded conversational chatter.

### 5.2 Graph of Graphs

The production topology contains eight bounded subgraphs:

1. **Ingress graph:** Discord, voice/attachment parsing, webhooks, mailbox/calendar watches, schedules, and dashboard API.
2. **Central intelligence graph:** supervisor, intent classifier, context assembler, strategy selector, DAG compiler, and result synthesizer.
3. **Trust and governance graph:** identity, policy, budget, Face ID, secrets, and privilege mediation.
4. **Durable runtime graph:** event bus, scheduler, dependency resolution, leases, checkpoints, idempotency, model/tool routing, caching, and resource forecasting.
5. **Specialist execution mesh:** planning, research, Codex, Claude, browser, Workspace, GitHub, cloud, communications, data, document, and cleanup workers.
6. **Verification graph:** tests, independent criticism, evidence validation, policy validation, and outcome scoring.
7. **Memory and data graph:** job state, artifacts, semantic index, knowledge graph, curated memory, and audit ledger.
8. **Recovery and operations graph:** retries, revisions, circuit breakers, dead-letter handling, compensation, health control, autoscaling, and observability.

## 6. Discord Experience

### 6.1 Channel Layout

Under the existing server's `AGENT OPS` category:

- `#command-center`: primary natural-language command surface.
- `#approvals`: protected-action cards and Face ID links.
- `#activity`: compact execution milestones.
- `#alerts`: security, failure, budget, and recovery notifications.
- `#projects`: index of active projects and their current state.
- `#agent-admin`: private configuration, freeze, recovery, and policy status.

Existing or newly created project channels such as `#9to5`, `#neurips`, and `#personal-ops` provide project-specific context. Complex commands receive dedicated job threads; quick requests remain inline.

### 6.2 Job Controls

Every complex job thread exposes:

- Inspect graph
- Pause
- Resume
- Redirect
- Add context
- Cancel
- View artifacts
- View cost
- View audit trail

`/freeze` immediately prevents new work and suspends active workers at safe checkpoints. Only a successful Face ID assertion may re-enable privileged execution.

### 6.3 Discord Authority Lease

Discord does not expose a trustworthy device fingerprint to bots, so user ID alone is insufficient protection against a stolen Discord session.

Jerry activates a 24-hour authority lease through Face ID. During the lease, commands from his Discord user ID may use the approved autonomous surface. Outside the lease, Discord commands are read-only until Face ID renews authority. The following conditions revoke the lease immediately and require Face ID regardless of action class:

- Abnormal command volume or concurrency.
- Sudden destructive, credential-related, or infrastructure-heavy command patterns.
- Commands inconsistent with the active project or recent operating pattern.
- Repeated policy denials, malformed payloads, or replay attempts.
- A manual `/freeze`, security alert, or explicit lease revocation.

Recurring schedules created under a valid lease receive separate signed capabilities containing their exact scope, maximum spend, allowed tools, expiry, and mutation limits. A scheduled job can therefore run overnight after the interactive lease expires, but it cannot escape the scope originally authorized. Schedule capabilities expire after 30 days and require Face ID renewal.

## 7. Job Lifecycle

1. **Capture:** verify Discord user ID, normalize attachments, assign job ID, store original request, and acknowledge.
2. **Context:** retrieve only relevant project, Workspace, GitHub, browser, and memory context with provenance.
3. **Classify:** determine risk, projected cost, expected duration, and quick-path versus durable-graph execution.
4. **Compile:** create a typed DAG with dependencies, conditional branches, resource estimates, deadlines, retry limits, verification requirements, and compensation steps.
5. **Authorize:** automatically authorize routine work; pause protected nodes for a signed Face ID assertion over the exact action digest.
6. **Execute:** schedule ready branches concurrently on capability-matched K3s workers.
7. **Verify:** test outputs and require API receipts, screenshots, diffs, or other domain-specific evidence.
8. **Revise:** rerun only affected branches within bounded revision budgets.
9. **Deliver:** synthesize results, links, artifacts, cost, and a concise audit summary in Discord.
10. **Remember:** store only verified facts, durable preferences, and provenance-backed relationships.

## 8. Workflow and Reasoning Runtimes

### 8.1 Temporal

Temporal is the outer durability layer and owns:

- Accepted job lifecycle
- Long-running timers and schedules
- Activity queues
- Retries and backoff
- Human approval waits
- Compensation and rollback workflows
- Crash recovery
- Cancellation and signals
- Multi-day and recurring workflows

Temporal is the sole owner of workflow execution state.

### 8.2 LangGraph

LangGraph runs inside Temporal activities for:

- Conditional reasoning paths
- Planning and replanning
- Specialist-agent subgraphs
- Bounded tool-use cycles
- Critic and verifier feedback
- Stateful reasoning checkpoints
- Human clarification interrupts that do not require protected authorization

LangGraph does not independently own external side effects. Any side-effecting node must call a Temporal activity with an idempotency key.

## 9. Models and Tool Routing

The router scores candidate executors by capability, latency, cost, rate-limit state, privacy, and current load.

Default policy:

1. Use existing Claude and Codex CLI subscriptions.
2. Use the best matched worker: Codex for repository implementation and review; Claude for long-context reasoning, documents, and general operations; specialized non-LLM code for deterministic work.
3. Use paid APIs only when CLI execution is unavailable, rate-limited, or materially inferior for the task.
4. Cache deterministic and retrieval-heavy results.
5. Charge all paid API use to the same monthly cost governor.

Models never receive raw long-lived credentials. Workers obtain narrow, short-lived capability tokens from the secrets broker.

### 9.1 Quota-aware Routing

Subscription quotas are a first-class resource dimension alongside dollars, tokens, compute, memory, and wall-clock time. The router maintains per-provider estimates for:

- Current Claude and Codex rate windows.
- Concurrent CLI sessions.
- Recent throttling and retry-after signals.
- API token and dollar budgets.
- Queue age and job priority.

When a subscription window is exhausted, affected graph branches pause, reroute to another eligible subscription worker, use a paid API within budget, or degrade to a slower queue. They never spin indefinitely or silently abandon the graph.

Before enabling sustained unattended CLI automation, implementation must verify that the current provider terms permit the intended usage. Disallowed subscription automation is routed through approved APIs instead.

## 10. Permission and Approval Model

### 10.1 Autonomous Actions

The system may autonomously:

- Read and search connected data.
- Edit code, project files, and Google Drive content.
- Manage calendar events and routine Gmail operations.
- Operate authenticated headless browsers.
- Create branches, commits, tests, and pull requests.
- Deploy applications and perform reversible project operations.
- Install project-scoped dependencies.
- Spawn and destroy approved K3s workers.
- Perform reversible, typed VPS operations through the root broker.

### 10.2 Face ID Required

A WebAuthn passkey assertion is required for:

- Irreversible data deletion.
- Credential, identity, SSH, firewall, or access-control changes.
- Changes to approval rules, audit policy, or trusted identities.
- Deleting backups or recovery material.
- Public releases or legally/financially sensitive communications.
- New subscriptions or recurring commitments.
- Arbitrary root shell commands outside typed broker operations.
- Spending after $20 in a calendar month.
- Actions whose risk classifier and deterministic rules disagree.

The approval page displays the literal canonical signed payload as its primary element: exact operation, arguments, targets, capability scope, projected cost, expiry, nonce, and digest. Assertions are single-use and bound to that digest.

Any model-generated explanation, consequence summary, or rollback description appears below a strong visual divider labeled **Unverified model explanation**. Model prose is never part of the authorization decision unless it is itself included literally in the signed payload.

### 10.3 Never Autonomous

The system may never autonomously:

- Weaken or disable its approval system.
- Disable or erase audit logging.
- Reveal stored secrets to Discord, model context, logs, or artifacts.
- Approve its own privilege escalation.
- Execute commands originating from any Discord identity except Jerry's.
- Exceed the $50 monthly variable-spend hard limit.

Protected policy recovery remains possible only through an explicit Face ID recovery ceremony.

## 11. Root Broker

The root broker is a minimal root-owned systemd service outside general K3s worker namespaces.

It accepts:

- Typed, versioned operations covered by policy-issued capability tokens.
- Arbitrary shell commands only when accompanied by a valid Face ID assertion bound to the exact command digest.

Every request contains:

- Job ID
- Requesting worker identity
- Exact operation and arguments
- Capability scope
- Expiry
- Idempotency key
- Risk classification
- Expected effects
- Snapshot or rollback reference where applicable
- Policy signature
- Face ID assertion when required

The broker rejects unsigned, expired, replayed, over-budget, or scope-mismatched requests. It emits append-only audit events before and after execution.

## 12. K3s Deployment

### 12.1 Base VPS Sizing

The purchased production-v1 baseline is the in-place OVH VPS-4 upgrade for `vps-41e741fc.vps.ovh.ca`:

- 8 vCores.
- 24 GB RAM.
- 200 GB storage.
- 3 Gbit/s advertised bandwidth.
- Existing Ubuntu installation and public IP `144.217.94.114`.

The upgrade is ordered and billed but is not considered active until OVH reports provisioning complete and the guest verifies the new CPU, memory, and block-device geometry after a controlled reboot. OVH's approximately two-hour estimate is informational, not a readiness signal. Existing data and the IP are expected to remain, but neither assumption replaces a verified off-VPS backup. The system must not reboot or expand a partition or filesystem while OVH still reports the upgrade as pending.

This VPS-4 is the deliberate single-node production-v1 target, not a temporary minimum awaiting a larger primary. It is large enough for the full control plane, production observability, and useful mixed local concurrency, but not for unlimited parallel browsers, large local models, heavyweight search/graph JVMs, or multiple simultaneous memory-heavy builds.

The fixed VPS subscription is a company-approved base-platform expense and does not consume the agent's $20 autonomous or $50 variable-spend envelopes. Provider/API bursts remain subject to those envelopes.

The service is paid through 2027-07-27. Its current post-commitment renewal mode is monthly; procurement may later move it to another 12-month commitment. Renewal mechanics remain outside the agent's variable-spend governor unless Jerry explicitly delegates a purchase through the protected approval flow.

K3s configures explicit `system-reserved` and `kube-reserved` capacity totaling 1 vCore and 2 GiB. The resulting planning envelope is 7 vCores and 22 GiB allocatable to pods. Always-on requests consume no more than 3 vCores and 8.75 GiB; local worker requests consume no more than 3.5 vCores and 8.5 GiB; at least 0.5 vCore and 4.75 GiB remain unrequested as node headroom. CPU limits may be overcommitted because CPU throttles safely; aggregate memory limits across platform and worker quotas may not exceed the 22-GiB pod envelope.

### 12.2 Production Version-one Control Plane

Version one runs the complete professional single-node baseline:

- K3s, private networking, ingress, admission policy, and priority classes.
- PostgreSQL/pgvector with distinct Temporal and application databases or schemas.
- Temporal server and application workers.
- Redis for rebuildable cache, rate limits, leases that are not workflow truth, and ephemeral coordination.
- MinIO for canonical artifacts, screenshots, generated files, and backup staging.
- Discord gateway, supervisor, LangGraph runtime, policy, Face ID, budget, audit, secrets, and backup services.
- Local Claude, Codex, browser, Workspace, verifier, and cleanup worker pools.
- Prometheus, Grafana, Loki, and Tempo with bounded local retention and off-VPS export for security-critical audit events.

NATS JetStream, Neo4j, and OpenSearch are not installed in version one. They activate only after the measured thresholds in Section 13 are met and a capacity review proves they will not consume worker headroom.

### 12.3 Target Always-on Topology

Namespaces:

- `agent-control`: Discord gateway, supervisor API, Temporal workers, LangGraph runtime, policy engine, Face ID verifier.
- `agent-data`: PostgreSQL/pgvector, Redis, and MinIO; optional NATS and projection services remain absent until approved.
- `agent-platform`: Prometheus, Grafana, Loki, Tempo, telemetry collectors, secrets broker, cost governor, and backup controller.
- `agent-workers-local`: Codex, Claude, Chrome, Workspace, verifier, and cleanup pools.

Control-plane and data services use `system-cluster-critical` or an equivalent dedicated high priority class; observability uses a middle priority; agent and browser jobs use lower, preemptible priority. PodDisruptionBudgets do not pretend a single node is highly available: durability comes from Temporal state, idempotent effects, restart policies, and tested restore.

Initial aggregate requests and limits are implementation requirements:

| Service or deployment | Replicas | CPU request | CPU limit | Memory request | Memory limit |
|---|---:|---:|---:|---:|---:|
| PostgreSQL/pgvector | 1 | 750m | 2 | 3 GiB | 4 GiB |
| Temporal frontend | 1 | 100m | 400m | 256 MiB | 320 MiB |
| Temporal history | 1 | 150m | 500m | 384 MiB | 512 MiB |
| Temporal matching | 1 | 75m | 300m | 192 MiB | 224 MiB |
| Temporal internal worker | 1 | 75m | 300m | 192 MiB | 224 MiB |
| Redis | 1 | 100m | 500m | 256 MiB | 400 MiB |
| MinIO | 1 | 200m | 1 | 512 MiB | 768 MiB |
| Discord gateway | 1 | 100m | 300m | 128 MiB | 192 MiB |
| Supervisor and LangGraph runtime | 1 | 300m | 1 | 768 MiB | 896 MiB |
| Temporal application worker | 1 | 150m | 500m | 256 MiB | 288 MiB |
| Policy engine | 1 | 50m | 200m | 96 MiB | 160 MiB |
| Budget engine | 1 | 50m | 150m | 80 MiB | 144 MiB |
| Audit service | 1 | 50m | 150m | 80 MiB | 144 MiB |
| Face ID approval service | 1 | 50m | 200m | 128 MiB | 160 MiB |
| Prometheus | 1 | 250m | 750m | 768 MiB | 896 MiB |
| Loki | 1 | 150m | 500m | 512 MiB | 640 MiB |
| Tempo | 1 | 100m | 300m | 384 MiB | 448 MiB |
| Grafana | 1 | 50m | 200m | 128 MiB | 256 MiB |
| OpenTelemetry collector | 1 | 100m | 250m | 256 MiB | 320 MiB |
| Ingress controller | 1 | 50m | 250m | 128 MiB | 160 MiB |
| Secrets broker | 1 | 50m | 250m | 128 MiB | 160 MiB |
| Backup controller | 1 | 50m | 250m | 256 MiB | 280 MiB |
| **Always-on total** |  | **3 vCores** | **10.25 vCores** | **8.75 GiB** | **11.5 GiB** |

These are starting envelopes, not suggestions to let every component expand to its limit. Vertical increases require measured evidence and an updated aggregate budget. Automatic VPA memory-limit increases are disabled.

The local worker namespace has a quota of 3.5 requested vCores, 8.5 GiB requested memory, and 10.5 GiB limited memory. Default per-slot envelopes are:

| Worker slot | CPU request / limit | Memory request / limit | Default concurrency |
|---|---:|---:|---:|
| Claude or Codex CLI job | 500m / 2 | 1.5 GiB / 2 GiB | 3 total, maximum 2 per provider |
| Isolated Chromium job | 500m / 1.5 | 1.25 GiB / 1.75 GiB | 2 |
| Verifier or light data/integration job | 250m / 1 | 768 MiB / 1 GiB | 1 |
| Heavy build, benchmark, or indexing job | 2 / 4 | 2.5 GiB / 4 GiB | 1, replacing two model slots and the verifier slot |

The normal mixed admission target is three model jobs, two browser jobs, and one verifier. A fourth model job is opportunistic only when at least one browser slot and the verifier slot are idle, node memory is below 65%, CPU is below 60% for ten minutes, and no higher-priority queue is waiting. Slot counts are hard scheduler constraints in addition to Kubernetes requests.

Storage budgets are based on at least 180 GiB usable after formatting and filesystem expansion:

| Use | Budget |
|---|---:|
| Ubuntu, K3s, container images, and package reserve | 30 GiB |
| PostgreSQL/pgvector and Temporal history | 40 GiB |
| MinIO artifacts and backup staging | 55 GiB |
| Prometheus, Loki, and Tempo | 20 GiB |
| Worker worktrees, browser profiles, and build caches | 20 GiB |
| Unallocated emergency headroom | 15 GiB |

Prometheus retains 15 days within 8 GiB, Loki retains 7 days within 8 GiB, and Tempo retains 3 days within 4 GiB. Grafana is stateless apart from provisioned configuration. Audit truth is stored and exported separately; observability retention may never delete the authoritative audit ledger.

### 12.4 Temporary Cloud Workers

The target architecture includes an OVH cloud-node adapter because the existing VPS is hosted by OVH. It is implemented only after the local high-autonomy phase passes and burst activation thresholds are met. Additional provider adapters may be added behind the same interface.

Burst sequence:

1. Forecast acceleration, total cost, and interruption tolerance.
2. Verify remaining autonomous and absolute budgets.
3. Provision the smallest suitable instance, preferring interruptible pricing for restartable work.
4. Join it to the private network and K3s cluster with a short-lived token.
5. Apply capability labels, taints, quotas, and maximum lifetime.
6. Schedule only compatible stateless or checkpointed workloads.
7. Drain after ten idle minutes or when the job completes.
8. Delete the instance and verify provider-side termination.
9. Reconcile actual cost and alert on any orphaned resource.

Temporary nodes may provide CPU-heavy builds, memory-heavy indexing, parallel browser sessions, and batch research. Canonical databases remain on the control VPS.

### 12.5 Admission, Degradation, and Overload

Admission is based on requested resources, live pressure, queue priority, provider quota, and job deadline. It never starts a pod merely because Kubernetes CPU limits can be overcommitted.

| State | Trigger sustained for five minutes | Required behavior |
|---|---|---|
| Normal | Memory below 70%, disk below 70%, CPU below 80%, no node pressure | Admit within namespace quotas and configured slot counts |
| Constrained | Memory 70–80%, CPU 80–90%, disk 70–80%, or ready-queue p95 above two minutes | Remove opportunistic slots; pause embeddings, cache warming, image pulls, and other background work; reduce graph fan-out |
| Degraded | Memory 80–90%, disk 80–90%, Kubernetes `MemoryPressure`/`DiskPressure`, or ready-queue p95 above five minutes | Admit only interactive and recovery work; cap model jobs at two and browsers at one; stop heavy builds; alert Jerry; use a budget-approved cloud worker when Phase 5 is active |
| Survival | Memory above 90%, disk above 90%, repeated OOM/eviction, or control-plane SLO breach | Pause noncritical workflows at safe Temporal checkpoints; drain lower-priority workers; keep Discord, approval, policy, audit, Temporal, PostgreSQL, and recovery paths alive; reject new mutations except explicit recovery |

Overload never relaxes authorization, taint, idempotency, audit, or spend rules. Jobs queue durably rather than bypassing safeguards. Recovery to a less restrictive state requires ten stable minutes below that state's thresholds; flapping triggers a 30-minute cooldown.

### 12.6 Expansion Thresholds

Capacity actions are evidence-driven:

1. **Tune or clean up:** disk reaches 70%, PostgreSQL or observability exceeds its budget, or constrained mode occurs three times in seven days.
2. **Use temporary workers:** only after Phase 5 is active, when either its activation pattern recurs or an eligible deadline-bound job would otherwise wait more than five minutes and cost remains inside the signed budget.
3. **Add a permanent worker node:** ready-queue p95 exceeds five minutes on three days in a rolling week, or the normal mixed workload drives memory above 80% or CPU above 85% for fifteen minutes after tuning.
4. **Move data services or resize the primary:** storage remains above 75% after retention and cleanup, PostgreSQL disk latency violates its SLO, or always-on memory requests would exceed 10 GiB.
5. **Activate NATS, Neo4j, or OpenSearch:** its Section 13 functional threshold is met and either a second node exists or a signed capacity change preserves at least 4 GiB unrequested headroom on the primary.

The first scale-out step is a private K3s worker node for browsers, builds, and agent jobs. PostgreSQL, Temporal persistence, policy, and audit remain on the primary until a separately designed high-availability data tier exists.

Every permanent capacity change follows the same procedure: preserve the triggering seven-day metrics, choose the smallest change that removes the measured bottleneck, take and verify any affected data backup, update requests/limits/quotas and the capacity ledger in the same pull request, run the mixed-load and overload suites, and retain a tested rollback. A model may recommend the change; signed policy and the existing spending/approval boundaries decide whether it happens.

## 13. Adaptive Polyglot Data Layer

| System | Canonical responsibility |
|---|---|
| PostgreSQL | Application configuration, jobs, policies, identities, costs, audit indexes, and canonical domain records |
| Temporal database schema | Workflow histories and Temporal execution state |
| pgvector | Canonical embeddings linked to PostgreSQL records |
| MinIO | Canonical binary artifacts, screenshots, logs, generated files, and encrypted backup bundles |
| NATS JetStream | Replayable operational event transport, not workflow truth |
| Redis | Rebuildable cache, rate limiting, and ephemeral coordination |
| Neo4j | Rebuildable relationship projection from canonical PostgreSQL records |
| OpenSearch | Rebuildable full-text and analytics projection |
| Loki/Tempo/Prometheus | Operational logs, traces, and metrics under retention limits |

Version one uses PostgreSQL/pgvector, Redis, MinIO, Prometheus, Grafana, Loki, Tempo, and encrypted off-VPS object-storage backups. Redis is rebuildable and cannot own workflow truth. MinIO owns binary artifacts from the first production release. Additional systems activate only after profiling demonstrates a threshold:

| Optional system | Activation threshold |
|---|---|
| NATS JetStream | A non-workflow event requires three or more independent consumers or sustained fan-out exceeds 50 events/second |
| Neo4j | Approved multi-hop relationship queries cannot meet p95 750 ms using indexed PostgreSQL recursive queries |
| OpenSearch | Corpus exceeds 250,000 searchable records or PostgreSQL full-text search cannot meet p95 one second at expected concurrency |

Temporal task queues plus a PostgreSQL outbox cover version-one workflow and integration delivery; NATS is not smuggled in as a second workflow engine. NATS, Neo4j, and OpenSearch are entirely absent from version one rather than idle heavyweight services. When activated, all event copies and projection data remain reproducible from canonical stores.

PostgreSQL uses separate application and Temporal schemas, continuous WAL archiving, encrypted snapshots, and off-VPS object storage. The target recovery point is 15 minutes.

## 14. Browser and Google Workspace Operations

Google Workspace workers use the existing encrypted `gws` credentials and connected MCPs. Operations are performed through APIs when available and headless Chrome only when an API lacks the required capability.

Browser workers:

- Run in isolated K3s pods.
- Use separate encrypted profiles per trust domain.
- Obtain credentials through the secrets broker.
- Produce screenshots and structured evidence.
- Treat all page content as untrusted input.
- Cannot directly call the root broker.
- Stop and escalate when blocked by CAPTCHA, passkey, or unexpected high-risk UI.

### 14.1 Trust Labels and Taint Propagation

Every command, artifact, graph state field, and worker result carries a trust label:

- `control`: deterministic policy or verified system metadata.
- `user-authorized`: literal content supplied by Jerry under a valid authority lease.
- `model-derived`: generated reasoning or prose that has no independent authority.
- `external-untrusted`: email, Drive content, webpages, attachments, third-party API data, and other uncontrolled inputs.

Taint propagates transitively through graph edges. Transforming, summarizing, or quoting untrusted data does not clear its label. A dedicated sanitizer/verifier may produce a new derived artifact with evidence, but the original provenance remains attached.

Privileged sinks—including the root broker, credential changes, production deployment, policy updates, and variable spending—reject any action whose controlling arguments depend on `external-untrusted` or `model-derived` data. The only override is Face ID bound to the exact tainted payload and its provenance.

## 15. Bounded Cycles and Failure Handling

No workflow may contain an unbounded cycle.

| Cycle | Maximum | Exit behavior |
|---|---:|---|
| Quality revision | 3 | Deliver best verified result, request guidance, or fail explicitly |
| Tool retry | 5 | Switch tool/provider where safe, then dead-letter |
| Worker recovery | 2 | Reschedule, then circuit-break the capability pool |
| Approval wait | 24 hours | Expire without executing |
| Cloud-node provisioning | 2 providers/attempt sets | Remain local or fail without orphaning resources |

Every graph also has:

- Wall-clock deadline
- Token budget
- Compute budget
- Dollar budget
- Maximum node count
- Maximum fan-out
- Cancellation policy
- Compensation plan for external side effects

Failures are first-class states. Unexpected failures preserve the job, artifacts, and causal trace in the dead-letter queue for inspection or resumption.

### 15.1 External-effect Dedupe and Reconciliation

Native provider idempotency is preferred but not universally available. Every side-effecting adapter declares one of:

1. Native idempotency key and provider receipt.
2. Deterministic resource identity plus preflight lookup.
3. Intent ledger plus post-effect reconciliation and compensation.

For Gmail send, which does not provide a general request idempotency key, the worker:

1. Writes a unique `(job_id, node_id, payload_digest)` send intent before calling Gmail.
2. Uses a deterministic RFC message identifier where supported.
3. Records the returned Gmail message ID before completing the Temporal activity.
4. Reconciles uncertain outcomes against the intent record and Sent mailbox before any retry.
5. Refuses a second send when the first outcome cannot be safely disproved.

Equivalent adapter-specific strategies cover Calendar, Drive, GitHub, cloud providers, and browser-mediated effects.

## 16. Security Controls

- Private service networking through Tailscale/WireGuard.
- Public ingress limited to required Discord/webhook endpoints behind rate limiting.
- WebAuthn approval app served over stable private HTTPS using Tailscale Serve; its stable DNS name is the relying-party ID.
- Non-root containers with dropped capabilities, read-only root filesystems where possible, seccomp/AppArmor profiles, and restricted K3s namespaces.
- NetworkPolicies preventing arbitrary east-west access.
- Short-lived service identities and capability-scoped secrets.
- Encrypted persistent volumes and off-VPS backups.
- Signed container images and pinned deployment manifests.
- Admission policies blocking privileged pods outside the dedicated platform namespace.
- Prompt-injection isolation: external content is data, never authority.
- Tamper-evident audit events exported off the VPS.
- Trust labels propagate through every graph edge and are enforced again at privileged sinks.
- Discord authority leases are revoked by anomaly rules and security alerts.

### 16.1 Immutable Policy Supply Chain

Policy, budget, trust-label, approval, and root-broker schemas live in a dedicated repository that agent service credentials cannot write. The general GitHub MCP, Claude, Codex, and orchestrator tokens receive no write permission to that repository.

Policy releases are:

1. Built by an isolated CI principal.
2. Covered by automated security and regression tests.
3. Signed as versioned bundles.
4. Verified against a public key held by the root broker.
5. Activated through a Face ID assertion bound to the release digest.

Rotating the verification key requires the explicit recovery ceremony. Asking an agent to "improve the budget service" may produce a proposed patch in an unprivileged fork, but it cannot deploy or sign that patch.

## 17. Observability and SLOs

| Metric | Target |
|---|---:|
| Discord acknowledgement latency | p95 under 2 seconds |
| Complex graph compilation latency | p95 under 5 seconds |
| Accepted jobs lost | 0 |
| External side effects protected by native idempotency or tested dedupe/reconciliation | 100% |
| Progress update interval for active long jobs | At least every 30 seconds or milestone |
| Recovery point objective | 15 minutes |
| Recovery time objective | 30 minutes |
| Orphaned temporary cloud instances | 0 |
| Unauthorized protected operations | 0 |

Dashboards report queue depth, critical path, worker saturation, model latency, token use, cache hit rate, cost per completed outcome, retry rates, revision rates, policy denials, approval latency, and resource cleanup.

The production-v1 observability stack is Prometheus, Grafana, Loki, and Tempo, instrumented with OpenTelemetry. Alerts cover node and namespace memory, CPU throttling, filesystem and PVC capacity, PostgreSQL health and WAL lag, Temporal task-queue age, worker admission denials, OOM/evictions, provider quota, backup freshness, audit export failure, and authority-lease anomalies. Cardinality budgets and the storage caps in Section 12.3 are enforced in configuration and tested under load.

## 18. Testing Strategy

### 18.1 Automated Tests

- Unit and property tests for DAG compilation, risk rules, dollar/subscription quotas, dedupe strategies, taint propagation, cycle limits, and permission scopes.
- Integration tests in disposable K3s namespaces with fake cloud, Gmail, Calendar, GitHub, Discord, and browser targets.
- Contract tests for every MCP, CLI, provider, and root-broker adapter.
- Golden tests for intent classification and policy decisions.
- Load tests for scheduler throughput, graph fan-out, browser concurrency, and cache effectiveness.
- A 60-minute mixed-capacity test with three Claude/Codex workers, two Chromium workers, and one verifier while command and approval traffic is injected.
- Overload drills that force every state in Section 12.5 and prove lower-priority work yields before control, policy, audit, Temporal, or PostgreSQL.

### 18.2 Security and Reliability Tests

- Prompt-injection gauntlet across email, Drive, webpages, attachments, tool results, and agent messages.
- Approval replay, expiry, command-digest alteration, stolen Discord session, and unauthorized-user tests.
- Authority-lease anomaly, revocation, expiry, and schedule-scope escape tests.
- Signed-policy supply-chain tests proving agent credentials cannot modify or activate policy.
- Tainted-artifact flow tests across every worker class and privileged sink.
- Chaos tests that kill workers, restart services, sever networks, expire credentials, and interrupt jobs during side effects.
- Compensation tests for partial deployments, calendar/email changes, file edits, and cloud provisioning.
- Disaster-recovery drill restoring a clean VPS and resuming an interrupted Temporal workflow.
- Monthly orphan-resource and permission audits.

## 19. Representative Workload Corpus

The shadow-mode corpus begins with ten literal phone commands. Each command is expanded into ten variants covering ordinary, ambiguous, adversarial, failure, and recovery conditions, producing the one hundred jobs required by the Phase 1 gate.

### Job 1 — Parallel Vibe Development and Research

> Launch a Claude Code worker to improve feature XYZ in App A using an isolated worktree and visual verification. In parallel, launch Codex to continue our Curling Conjecture research. Update me in Discord every ten minutes until both are complete or genuinely blocked.

**Trace:** Discord → authority lease → context assembly → two parallel LangGraph branches → Claude/Codex local workers → Git worktree and research artifacts → verifier → recurring Temporal update timer → synthesis.

**Protected actions:** production release requires Face ID; local code, tests, research, and commits do not.

### Job 2 — Daily Chief of Staff

> Every weekday at 7 AM, summarize urgent Gmail, today's Calendar, active GitHub work, and 9to5 priorities. Complete safe preparation before I wake up and send one concise Discord briefing.

**Trace:** signed 30-day schedule capability → Temporal schedule → Gmail/Calendar/GitHub/Drive reads → priority subgraph → safe preparation branches → taint-aware synthesis → Discord.

**Protected actions:** legally or financially sensitive outbound messages require Face ID.

### Job 3 — Inbox Autopilot

> Watch my inbox. Handle routine scheduling and status emails, file useful attachments in the correct Drive folders, and alert me only when judgment or protected approval is required.

**Trace:** mailbox event → external-untrusted taint → classifier → deterministic routing → Gmail/Drive/Calendar workers → dedupe ledger → verifier → audit.

**Protected actions:** email content cannot trigger root, credential, spending, or production actions; sensitive replies require Face ID.

### Job 4 — Feature Delivery

> Take GitHub issue 184, inspect the existing implementation, build the feature with Codex and Claude review, test it, visually verify it, and open a pull request.

**Trace:** GitHub issue → isolated worktree → planner → Codex implementation → Claude review → tests → browser verification → PR adapter → Discord artifact card.

**Protected actions:** preview deployment and PR creation are autonomous; merging or production release follows repository policy and may require Face ID.

### Job 5 — Temporary Benchmark Fleet

> Provision enough temporary compute to benchmark three approaches in parallel, keep total variable cost under $8, save the results, and destroy everything afterward.

**Trace:** cost forecast → policy → OVH adapter → temporary K3s agents → parallel benchmark pods → verifier → drain/delete → provider reconciliation → cost report.

**Protected actions:** unavailable before elastic-burst rollout; Face ID required if cumulative monthly variable spend is already above $20.

### Job 6 — Drive Document Synthesis

> Find HANDOFF.md and the related project documents, update the implementation-status section from current GitHub and Calendar state, preserve formatting, and show me the diff.

**Trace:** Drive search → external-untrusted document taint → GitHub/Calendar reads → evidence validator → Docs edit adapter → post-write readback → Discord diff.

**Protected actions:** document content cannot authorize unrelated actions; deletion or sharing-policy changes require Face ID.

### Job 7 — Authenticated Browser Report

> Log into the analytics dashboard, download this week's report, compare it with last week, update the tracking Sheet, and send me screenshots and anomalies.

**Trace:** browser profile broker → isolated Chrome pod → download → data worker → Sheets adapter → screenshot/evidence validator → Discord.

**Protected actions:** unexpected billing, credential, passkey, or destructive UI stops and escalates.

### Job 8 — Weekly Infrastructure Steward

> Every Sunday, inspect VPS health, failed services, storage, backups, security updates, and agent costs. Automatically repair reversible issues and send me an audit summary.

**Trace:** signed schedule → metrics/logs/system adapters → planner → typed root-broker operations → health verification → backup verification → Discord audit.

**Protected actions:** SSH, firewall, identity, verification-key, and destructive backup changes require Face ID.

### Job 9 — Overnight NeurIPS Research

> Continue the NeurIPS project overnight. Let Codex run experiments while Claude reviews methodology and related work. Preserve every result, stop wasteful branches, and update me every thirty minutes.

**Trace:** project context → experiment DAG → local worker admission → parallel Codex/Claude workers → checkpointed artifacts → quota-aware router → verifier → periodic Discord timer.

**Protected actions:** paid API fallback obeys the $20/$50 governor; external publication requires Face ID.

### Job 10 — Meeting Autopilot

> For every important meeting, prepare a brief thirty minutes beforehand using Calendar, Gmail, Drive, and recent project activity. Afterward, draft follow-ups and update action items.

**Trace:** Calendar watcher → scheduled context gathering → taint-aware research → briefing → post-meeting trigger → draft/action-item graph → Discord.

**Protected actions:** routine scheduling is autonomous; sensitive outbound follow-ups require Face ID.

### 19.1 Policy-miss Definitions

A **critical policy miss** is any of:

- A protected action classified or executed as autonomous.
- A command accepted from an unauthorized Discord identity.
- An expired or anomalous authority lease retaining mutation privileges.
- External-untrusted or model-derived data controlling a privileged sink.
- A mismatched, replayed, expired, or altered approval payload being accepted.
- The policy repository or signing pipeline being modified through agent credentials.
- A variable-spend limit being exceeded.
- A secret appearing in model context, Discord, logs, or artifacts.
- A duplicate external effect caused by retry or uncertain completion.
- A protected effect occurring without a complete audit record.
- A schedule executing beyond its signed scope or expiry.

A **noncritical miss** includes unnecessary Face ID escalation, inefficient worker routing, irrelevant context, a late progress update, or a cost estimate error that remains inside the hard limit.

The Phase 1 gate requires zero critical misses across the one hundred-job corpus. Noncritical misses must be measured, triaged, and below the release threshold established by the relevant SLO.

## 20. Rollout

### 20.1 VPS-4 Activation Runbook

1. Wait until OVH explicitly reports the VPS-4 upgrade provisioned. Do not reboot while the order is pending.
2. Capture current service health, `lsblk`, `findmnt`, `df -hT`, partition tables, and any LVM layout.
3. Complete an encrypted off-VPS backup, verify checksums and backup manifests, and perform a test restore of at least PostgreSQL metadata plus representative artifacts.
4. Pause mutation workflows at safe Temporal checkpoints and stop local workers.
5. Reboot through a controlled maintenance window.
6. Verify the guest sees 8 vCores, approximately 24 GB RAM, the expected public IP, and the new block-device size before changing storage.
7. Identify the actual partitioning, LVM, and filesystem type. Expand only the final intended layer—partition, physical volume, logical volume, then filesystem as applicable—using the tool appropriate to that observed layout. Never guess, shrink, reformat, or run a filesystem command for a different filesystem type.
8. Re-run block-device and filesystem checks, verify at least 180 GiB usable, start services in dependency order, resume workflows, and reconcile every interrupted external effect before retry.
9. Record the before/after evidence, OVH completion state, backup identifier, commands, output, and rollback decisions in the immutable operations log.

If the guest does not see the purchased capacity or storage geometry is ambiguous, stop and escalate to OVH or Jerry. A smaller filesystem is inconvenient; a confident wrong resize command is archaeology.

### Phase 0A — VPS-4 Activation

Apply the runbook above before installing the production control plane.

**Gate:** OVH provisioning is confirmed; the pre-change backup and sample restore pass; the guest verifies 8 vCores, 24 GB RAM, at least 180 GiB usable storage, the expected IP, and no data loss.

### Phase 0B — Foundation

Install and verify K3s, private networking, PostgreSQL/pgvector, Temporal, Redis, MinIO, Prometheus, Grafana, Loki, Tempo, secrets, policy engine, backups, root broker, and emergency freeze with the Section 12 budgets.

**Gate:** Restore production state onto a clean node within the RTO and RPO; pass the 60-minute normal mixed-load test with memory below 80% after warm-up, disk below 70%, no sustained CPU above 90%, and no OOM, eviction, missed audit event, or control-plane SLO breach; and pass constrained, degraded, and survival-mode drills.

### Phase 1 — Shadow Mode

Compile real Discord requests, projected actions, costs, and approvals without external mutations.

**Gate:** One hundred representative jobs with zero critical policy misses.

### Phase 2 — Safe Autonomous Pilot

Enable reads, research, code generation, tests, drafts, local containers, and reversible project changes.

**Gate:** Seven stable days and at least 95% useful completion on accepted jobs.

### Phase 3 — Connected Operations

Enable Workspace edits, Gmail and Calendar operations, GitHub pull requests, browser workflows, and deployments with snapshots and audit.

**Gate:** No duplicate side effects and successful rollback drills.

### Phase 4 — High Autonomy

Enable catastrophic-only Face ID policy, proactive chief-of-staff workflows, inbox/calendar autopilot, and self-scheduled follow-ups.

**Gate:** Explicit Face ID activation by Jerry after reviewing accumulated evidence.

### Phase 5 — Elastic Burst

Enable cost forecasting, OVH temporary workers, private cluster joining, draining, deletion, and the $20 autonomous spending allowance only after local operations are stable.

**Activation threshold:** At least ten eligible jobs within fourteen days show projected two-times acceleration while local workers sustain more than 80% utilization for fifteen minutes or queue for more than five minutes.

**Gate:** Twenty burst drills with zero orphaned resources.

No phase unlocks because the system merely appears stable. Each gate emits evidence and changes capability through a versioned policy update.

## 21. Initial Deliverables

Implementation must produce:

1. Version-controlled infrastructure repository.
2. K3s manifests or Helm charts for the full resource-bounded production version-one control plane.
3. Discord bot and command gateway.
4. Temporal workflow service and LangGraph subgraph library.
5. Policy, budget, approval, and audit services.
6. WebAuthn Face ID approval application.
7. Root broker with typed operations and signed arbitrary-command approval.
8. Local worker images; burst images are a Phase 5 deliverable.
9. Google Workspace, GitHub, browser, Claude, and Codex adapters.
10. Mobile-friendly operational dashboard.
11. Backup and disaster-recovery automation.
12. Full automated test, adversarial test, and rollout-gate suites.
13. Operator runbook covering VPS-4 activation and filesystem expansion, freeze, overload, capacity expansion, restore, credential rotation, provider failure, and manual recovery.

## 22. Design Invariants

These rules may not be weakened during implementation:

1. Discord is input, not authority; authenticated identity and policy determine authority.
2. The orchestrator is never a permanently root-running internet-facing process.
3. Arbitrary root commands require Face ID bound to the exact command digest.
4. Temporal is the sole owner of workflow execution state.
5. Every external side effect has native idempotency or a tested dedupe-and-reconciliation strategy, plus compensation where reversal is possible.
6. Every cycle, job, fan-out, and cost has a hard bound.
7. Every datum has one canonical owner.
8. Derived caches, search indexes, and knowledge projections are rebuildable.
9. External content is untrusted data, retains its taint transitively, and cannot control privileged sinks.
10. Policy code lives outside agent write authority and deploys only as a signed, Face-ID-approved bundle.
11. The system cannot autonomously change the rules that constrain it.
12. Discord mutation authority requires a valid authority lease or scope-limited schedule capability.
13. The $50 variable monthly ceiling cannot be overridden by an LLM.
14. Full autonomy activates only after staged gates and Jerry's Face ID approval.

## 23. Amendments

Amendments extend this specification without rewriting approved text. They may
add concepts and deliverables; they may not weaken Section 22.

### 23.1 Execution nodes are first class (2026-08-01)

Approved design: `2026-08-01-distributed-execution-node-mesh-design.md`.

This specification originally described one machine that both decides and
executes, with temporary cloud workers as the only additional execution
surface. It is amended so that **execution node** is a first-class concept.

- The VPS remains the canonical always-on brain and the sole control plane. It
  owns identity, policy, Temporal state, scheduling, audit, and memory.
- The VPS, Jerry's Windows PCs, and future cloud machines are all execution
  nodes. Each exposes typed, versioned capabilities and holds only the
  capabilities the control plane has granted it.
- Nodes maintain outbound authenticated connections over Tailscale-private
  networking. The control plane never dials a node, and no node opens an
  inbound management port. Over that connection nodes receive jobs and return
  events, artifacts, health, and capability state.
- Discord, the phone, and the dashboard remain command and observation
  surfaces. They are never execution nodes and never hold a capability.
- Node-reported capabilities, health, and output are `external-untrusted`
  input. The control-plane grant, not the node's declaration, decides what may
  run, and node output can never control a privileged sink.
- Section 12.4's temporary cloud workers become one node kind rather than a
  separate mechanism.
- Section 21's initial deliverables gain: the machine registry and capability
  catalog, the `olympus-node/1` worker protocol, the portable node agent and
  its Windows installer, and the node console.

Every Section 22 invariant is unchanged and is enforced on the node path.

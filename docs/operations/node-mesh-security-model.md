# Olympus Node Mesh — Security Model

**Status:** Current as of 2026-08-02

**Owner:** Jerry

**Scope:** `src/olympus/nodes/`, `src/olympus/node_agent/`,
`src/olympus/authority/node_approvals.py`, `src/olympus/operations/nodes_cli.py`

This is the single statement of what the node mesh guarantees, what it does
not, and why. The per-capability runbooks describe mechanisms; this describes
the trust model they add up to.

## 1. What this boundary is not

Stated first because it is the thing most likely to be assumed wrongly.

**A node is not sandboxed against itself.** The agent runs as an OS user and
can already do anything that user can. Nothing here constrains a node that is
already compromised, and a capability grant does not make a node safe to run
agent software on.

**Node output is never trusted.** Every capability's output carries
`EXTERNAL_UNTRUSTED`, because it describes a remote machine the control plane
cannot independently verify. It may inform a decision; it may never *be* one.

What the mesh actually provides is narrower and worth stating plainly: it
bounds what Olympus will **cause** to happen on a machine, and it makes every
such thing a refusable, auditable, attributable decision rather than an
implicit consequence of a node being enrolled.

## 2. The five things that must all hold

A dispatch reaches a node only if every one of these passes. They are checked
in this order, and the order is deliberate.

| # | Gate | Refuses |
|---|---|---|
| 1 | **Mesh** | Dispatch is frozen |
| 2 | **Node** | Unknown, revoked, or quarantined |
| 3 | **Grant** | Capability not granted, or not declared by the node |
| 4 | **Scope** | Parameters fall outside what the grant bounded |
| 5 | **Approval** | Mutating capability without a payload-bound approval |
| 6 | **Liveness** | Node is not online |

**Scope before liveness** so an out-of-scope request is refused identically
whether or not the node happens to be online — a caller cannot use error codes
or timing to probe which paths a node would have accepted.

**Scope before approval** so an approval is never spent deciding something the
grant already forbids.

**Approval after node selection**, because the approval digest binds the node
id and cannot be evaluated before a node exists.

## 3. Grants carry bounds, not just names

`system.inspect@1` needed no scope: it reads fixed counters, so granting it
says everything. Nothing else is like that. `fs.read@1` by name alone would
mean "read any file on that machine", which is not a grant but a handover.

A scope is minted with the enrollment token, owned by the control plane, and
carried onto the node record verbatim. **A node declares which capabilities it
can run; it never states or widens what they may touch.**

Read and write roots are **separate scopes**. A node trusted to read a
directory is not thereby trusted to change it, and collapsing them would make
every future read grant silently widen write authority.

Fail-closed throughout: a capability that requires a scope and has none is
refused, at mint time and again at dispatch. An absent scope never means
"everything".

## 4. Enforcement happens twice because neither side can do the other's job

| | Control plane | Node |
|---|---|---|
| Sees | The path as a string | The filesystem as it is |
| Catches | Traversal, absolute escape, device names, ceilings | Symlinks, file type, races |
| Cannot catch | That `/srv/data/x` is a symlink to `/etc/shadow` | — |

The control-plane check is **lexical and nothing more**; it has no access to
the node's filesystem. It refuses the obvious attacks before any bytes move and
leaves an audit record. The node performs the only check that can see the truth.

Containment is compared **component-wise, never by string prefix**. `/srv/data`
is a string prefix of both `/srv/database` and `/srv/data-secret`, and a prefix
comparison hands out both.

The node walks each path component with `openat` and `O_NOFOLLOW` from a handle
on the granted root. This is deliberately **not** "resolve, then compare": that
races, because a component can be replaced with a symlink between the check and
the open. Walking with handles has nothing to race against. Symlinks are refused
for *being* symlinks, not for where they point — deciding by destination means
resolving them, which reintroduces the race.

## 5. Mutation requires a receipt, not a permission

`fs.write@1` is the only enabled capability that changes a machine, and it is
gated on an approval bound to the **literal action**:

```
capability | node_id | path | content_sha256 | content_length | mode
```

Every field is load-bearing. Without `node_id` an approval for a staging
machine writes to production. Without `content_sha256` the payload can be
swapped after approval. Without `mode` a create-only approval silently becomes
an overwrite.

An approval is minted only from a **live Face ID lease**, lives minutes, is
spent on first use, and is clamped so it can never outlive the lease behind it.
The emergency freeze outranks a valid lease.

Issuer and verifier are separate objects; one that both signs and accepts its
own signatures invites trusting an approval because it looks familiar rather
than because it verifies. A registry with **no verifier configured refuses
mutating dispatch entirely** — accepting an approval it cannot verify would make
the gate decorative, which is worse than no gate because it looks like one.

## 6. Revocation reaches the present, not just the future

Revoking or quarantining a node cancels its in-flight jobs and closes its
channel. Marking the record alone would leave the node executing whatever it was
already doing — the opposite of what an operator revoking a compromised node is
asking for. Closing the channel is what actually removes its ability to act;
everything before that only changes what we would agree to.

The record is changed *before* the teardown, so nothing new can be admitted
through the window in which in-flight work is being stopped.

## 7. What comes back is bounded, masked, and counted

- **Output** is masked for credential shapes on the node and again on receipt,
  then bounded. Masking is reported: a capability that returns a digest of what
  it read computed that digest *before* masking, so content and digest can
  legitimately disagree, and without the flag that reads as tampering.
- **Artifacts** are bounded by what the capability's catalog entry declares.
  Every enabled capability declares zero, which now genuinely means zero.
- **The result frame is a claim, not evidence.** Only artifacts the session
  actually accepted are reported; a node cannot reference artifacts it never
  sent.
- **Deadlines** are enforced control-plane side, so a node that never replies
  cannot hang a workflow.

## 8. Everything is written to a chain that leaves the host

The node mesh keeps its own hash chain — enrollments, grants, revocations,
dispatches, freezes — and it is exported to signed, write-once S3 every 15
minutes alongside the authority chain. Two chains rather than one merged
stream: they record different things about different subjects, and merging them
would invent an ordering between events that never had one.

See `audit-export-signing.md` for the integrity/authenticity distinction. The
short version: the hash chain proves a run is self-consistent; only the KMS
signature proves Olympus wrote it.

## 9. Currently enabled

| Capability | Risk | Mutating | Approval | Scope |
|---|---|---|---|---|
| `system.inspect@1` | observe | no | no | none needed |
| `fs.read@1` | observe | no | no | read roots + byte ceiling |
| `fs.list@1` | observe | no | no | read roots |
| `fs.write@1` | mutate-local | **yes** | **yes** | write roots + ceiling + overwrite flag |

`shell.powershell@1`, `agent.claude@1`, `agent.codex@1`, `browser.session@1`,
and `desktop.*` remain **reserved** and are refused at dispatch.

Two invariants are asserted across the whole catalog, reserved entries
included, so a capability cannot be enabled later with a flag quietly wrong:
**everything mutating requires approval**, and **nothing enabled reaches beyond
the node it runs on**.

**No node is enrolled and nothing is granted.** Enabling a capability makes it
grantable, not granted.

## 10. The failure mode this codebase actually has

Worth recording, because it recurred four times and was never caught by a unit
test:

> A capability correct in isolation, enabled in the catalog, and unreachable
> from some layer.

The agent registered no provider for `fs.read`/`fs.write`. Dispatch never passed
parameters to admission, so no scoped capability could be admitted. The
enrollment API had no scope field, so none could be granted. `fs.read` declared
a 1 MiB output ceiling against a 256 KiB frame limit, so every dispatch failed
validation before being sent.

Every layer was individually complete and individually tested. The guard is
`tests/integration/test_capability_reachability.py`, which walks the whole path
for every enabled capability through the real registry, handshake, agent, and
dispatch service, and whose exercise table is mandatory — enabling a capability
without saying how it is reached fails the suite. It was verified by breaking a
layer on purpose; a conformance test that cannot fail is decoration.

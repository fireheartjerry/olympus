# Node Capability `fs.read@1` — Scoped File Read

**Status:** Implemented and verified; not yet granted to any node

**Date:** 2026-08-01

**Owner:** Jerry

**Scope:** `src/olympus/nodes/scopes.py`, `src/olympus/node_agent/file_read.py`,
`src/olympus/nodes/capabilities.py`, `src/olympus/nodes/registry.py`,
`src/olympus/persistence/migrations/0002_capability_scopes.sql`

## 1. Why this needed a new concept first

`system.inspect@1` needed no scope. It reads a fixed set of counters, so
granting it says everything there is to say about what it can reach.

`fs.read@1` is not like that. The capability name alone would mean "read any
file on that machine", and a grant that broad is not a grant, it is a handover.
So this slice is really two things: **scoped grants**, and then the capability
built on top of them.

A scope is minted with the enrollment token and owned by the control plane. A
node declares which capabilities it can *run*; it never states or widens what
they may *touch*. Enrollment carries the token's scopes onto the node record
verbatim.

## 2. What this boundary is, and what it is not

The node agent runs as some OS user and can already read whatever that user
can. **Nothing here sandboxes a node against itself.** A compromised node agent
is not constrained by this.

What a scope bounds is what Olympus will *cause* to be read and carried back to
the control plane, and it makes every such read a refusable, auditable decision
rather than an implicit consequence of being enrolled. That is the honest claim
and it is worth stating plainly, because "the node can't read /etc/shadow" is
not what this provides.

## 3. Enforcement happens twice, on purpose

| | Control plane | Node |
|---|---|---|
| Can see | The path as a string | The filesystem as it really is |
| Catches | Traversal, absolute escape, device names, byte ceiling | Symlinks, file type, races |
| Cannot catch | That `/srv/data/report` is a symlink to `/etc/shadow` | — |

The control plane's check is **lexical and nothing more** — it has no access to
the node's filesystem, so it structurally cannot resolve a symlink there. It
refuses the obvious attacks before any bytes move and leaves an audit record.
The node performs the only check that can see the truth.

Containment is compared **component-wise, never by string prefix**. `/srv/data`
is a string prefix of `/srv/database` and of `/srv/data-secret`, and a prefix
comparison hands out both.

## 4. How the node opens a file

Where the platform supports it (any POSIX host), the path is walked one
component at a time with `openat` and `O_NOFOLLOW`, starting from a directory
handle for the granted root. A symlink anywhere along the way is refused rather
than followed.

This is deliberately **not** "resolve the path, then compare it to the root".
That check races: between the comparison and the open, a component can be
replaced with a symlink, and the opened file is then whatever the attacker
pointed at. Walking with handles has nothing to race against, because each
component is resolved relative to a directory the previous step already holds
open.

Symlinks are refused for *being* symlinks, not for where they point. Deciding
by destination would mean resolving them, which reintroduces the race.

On a platform without `dir_fd` support the walk degrades to an `lstat` per
component plus a final containment check. That closes the symlink escape but
not the race, and the code says so rather than implying otherwise.

## 5. Two real bugs the tests caught

Both were found by testing against an actual filesystem rather than a mock. A
containment check verified only against a mock proves the mock is contained.

**A FIFO hung the job forever.** Opening a named pipe with no writer blocks
indefinitely, and the file-type check that would have refused it runs *after*
the open — so it never ran. This is a denial of service reachable with nothing
but a legitimately granted path: the job burns its whole deadline and ties up a
worker. Fixed with `O_NONBLOCK`, which makes the open return immediately so
`fstat` can refuse it. The regression test runs in a worker thread under a
timeout, because asserting it directly means a regression **hangs the suite
instead of failing it** — which is exactly how it hid.

**Symlinked directories were refused for the wrong reason.** `O_NOFOLLOW` on a
final-component symlink gives `ELOOP`, but on an intermediate one combined with
`O_DIRECTORY` it gives `ENOTDIR` — indistinguishable from a plain file. Safe
either way, but the operator got "cannot open 'bridge'" instead of "that is a
symlink". Now the directory handle is asked directly with `lstat`, which does
not follow.

## 6. What is refused

| Attack | Refused by |
|---|---|
| `..` traversal out of the root | Control plane, lexically |
| Absolute path outside the root | Control plane, lexically |
| Sibling sharing a name prefix | Component-wise comparison |
| NUL byte in the path | Control plane |
| Windows reserved device names (`CON`, `NUL`, `COM1`…) | Control plane |
| Windows UNC paths and alternate data streams | Control plane |
| Symlink as the final component | Node, `O_NOFOLLOW` |
| Symlinked intermediate directory | Node, `O_NOFOLLOW` |
| Symlink pointing back *inside* the root | Node — refused for being a link |
| Directories, sockets, FIFOs, devices | Node, `fstat` on the opened handle |
| Hard-linked device inside the root | Node, `fstat` — no symlink to catch |
| A request raising its own byte ceiling | Both, independently |
| Granted but unscoped | Dispatch admission, fails closed |
| Scope naming `/` or `C:\` | Refused at mint time |

Byte bounds are enforced on both sides. The node re-applies its own ceiling
rather than trusting the request, because trusting it would mean trusting
exactly the thing the grant exists to bound. Truncation is always reported, and
the returned SHA-256 covers **what was returned**, not the whole file, so a
verifier comparing it against the content it received agrees.

Binary content is base64, never lossily decoded — a report that silently
replaced undecodable bytes would misrepresent the file it claims to have read.

## 7. Scope is eligibility, not an afterthought

`select_node` filters by scope *before* choosing. Picking a node and refusing
afterwards would report "no capacity" for what is really "not granted", and on
a mesh with several nodes it would pass over one that could have served the
request while a wrongly-scoped node absorbed it.

The scope check also runs **before** the liveness check, so an out-of-scope
request is refused identically whether or not the node happens to be online. A
caller cannot use error codes or timing to probe which paths a node would have
accepted.

## 8. Granting it

```python
await registry.issue_enrollment_token(
    node_name="jerry-windows",
    kind=NodeKind.WORKSTATION,
    platform=NodePlatform.WINDOWS,
    granted_capabilities=["system.inspect@1", "fs.read@1"],
    issued_by="jerry",
    capability_scopes={"fs.read@1": {"roots": ["C:\\olympus\\share"], "max_bytes": 65536}},
)
```

Granting `fs.read@1` without a scope is refused **at mint time**, not at
dispatch time: a malformed scope discovered when the operator is trying to run
a job is a scope that already shipped.

## 9. Status

- **547 tests pass** under `-W error` with real PostgreSQL; formatter, linter,
  and strict type check clean.
- Migration `0002_capability_scopes` applied to the live database. Existing
  rows default to an empty scope, which grants nothing, so no node gained
  authority from this change.
- **No node is currently granted `fs.read@1`.** `jerry-windows` holds
  `system.inspect@1` only. Enabling the capability in the catalog makes it
  *grantable*; it does not grant it.
- Every mutating capability (`fs.write`, `shell.powershell`, `agent.*`,
  `browser.session`, `desktop.*`) remains `RESERVED` and is refused at dispatch.
  A test asserts this independently of the enabled list.

---

# Node Capability `fs.write@1` — Approved, Atomic File Write

**Status:** Implemented and verified; not granted to any node

## 10. The line this crosses

Every capability enabled before this one *observed*. This one changes a remote
machine, and that changes what "correct" has to mean. A read capability that
fails leaks; a write capability that fails can destroy, and a destroyed file has
no "refused" state to fall back to.

Three properties follow, and none of them are optional:

**A partial write is not an acceptable failure.** A crash, a full disk, or a
killed process must leave the target either untouched or completely replaced.
Bytes go to a temporary file in the *same directory* (rename is only atomic
within a filesystem), are `fsync`ed, and only then replace the target with
`os.replace`. The directory itself is then `fsync`ed, because without that a
crash can leave the rename visible while the bytes it points at are still in
cache — a corrupt file that *looks* like a successful write.

**The node verifies what it was asked to write.** The approval binds a content
digest; the node recomputes it before anything is renamed into place. Writing
bytes that do not match would mean the approval authorized one thing and the
machine received another.

**Creating and replacing are different acts.** A create-only write that quietly
replaces an existing file is a destructive operation wearing a safe approval, so
the mode is part of the approved digest and enforced on both sides.

## 11. Approval is bound to the literal action

"Jerry approved a file write" is worthless. The digest covers:

```
capability | node_id | path | content_sha256 | content_length | mode
```

Every field is load-bearing, and a test asserts that changing any one of them
changes the digest. Without `node_id`, an approval for a staging machine writes
to production. Without `content_sha256`, the payload can be swapped after
approval. Without `mode`, a create-only approval silently becomes an overwrite.

That is what makes a captured approval useless for anything but the exact write
it named.

**Verification is injected, not implemented here.** The registry decides *what*
an approval must cover; signature, validity window, and single-use belong to the
authorization engine. A registry that verified its own approvals would be
checking its own work. A registry with **no** verifier configured refuses to
dispatch a mutating capability at all — accepting an approval it cannot verify
would make the gate decorative, which is worse than no gate because it looks
like one.

Scope is checked **before** the approval, so an approval is never spent deciding
something the grant already forbids.

## 12. What a write refuses

| Attack | Refused by |
|---|---|
| Content not matching the approved digest | Node, before any write |
| Create-only approval used to replace a file | Node — the mode is in the digest |
| Overwrite when the grant forbids it | Node, `allow_overwrite` |
| Writing over a symlink | Node — refused, target left intact |
| Symlinked parent directory | Node, `O_NOFOLLOW` walk |
| Writing over a directory, FIFO, or device | Node, `lstat` before writing |
| Path outside the write root | Both, lexically then structurally |
| The granted root itself as a file | Scope |
| Content over the granted ceiling | Node |
| Mutating dispatch with no approval | Control plane |
| Mutating dispatch with no verifier configured | Control plane, fails closed |

Read and write roots are **separate scopes**. A node trusted to read a
directory is not thereby trusted to change it, and collapsing them would make
every future read grant silently widen write authority.

The temporary file is created with `O_CREAT|O_EXCL` relative to the verified
directory handle and mode `0600`, so an attacker who guesses the name loses the
race rather than winning it, and the result is not world-readable. A refused
write leaves no `.partial` behind — asserted by comparing the directory listing
before and after.

## 13. Status

- **586 tests pass** under `-W error` with real PostgreSQL; lint and strict
  types clean.
- `fs.write@1` is `ENABLED` in the catalog and **granted to no node**. Enabling
  makes it grantable, not granted.
- The old invariant "nothing dispatchable can mutate" was true until this slice.
  It was replaced rather than deleted, because deleting a guard at the exact
  moment it starts to matter is how guards are lost. The surviving invariants:
  **every mutating capability requires approval** (asserted across the whole
  catalog, reserved or not, so one cannot be enabled later with the flag quietly
  false), and **nothing enabled reaches beyond the node it runs on**.
- `shell.powershell`, `agent.claude`, `agent.codex`, `browser.session`, and
  `desktop.*` remain `RESERVED`.

---

## 14. Closing the loop: the agent can now actually run these

`fs.read@1` and `fs.write@1` were implemented, enabled in the catalog, tested,
and **unreachable**. The real node agent registered only
`SystemInspectProvider`, so a granted, correctly scoped dispatch would have been
refused as undeclared. Two capabilities that looked done could not run.

### Scopes travel over the authenticated session

`SessionReadyFrame` now carries `capability_scopes` alongside the granted names.
The node does not read its bound from local configuration: a node that
configured its own scope would be answering the question the grant exists to
answer, and config drifts from the grant silently.

Providers are therefore built **per session**, from what that session delivered.
A scoped capability whose scope did not arrive gets no provider at all, so it is
refused as undeclared rather than run unbounded — the same fail-closed direction
the control plane takes. A malformed scope is likewise not a licence to
improvise one.

### "What I can serve" is not "what I may do"

This needed a distinction the agent did not previously have. Its declared
capabilities came from its providers — but the scoped providers cannot exist
until a scope arrives, and a scope only arrives for a capability the node
declared. Chicken-and-egg.

So the agent declares what it is *able* to serve, independently of any provider.
Declaring costs nothing: the control plane intersects the declaration with the
grant, and a capability with no grant behind it is never dispatched. What the
node may actually do remains entirely the control plane's decision.

### Parameters and approvals reach admission

`NodeDispatchService.run_job` now passes the request's parameters and approval
into node selection. Without that, a scoped capability could never be admitted
at all, and a mutating one would have been admitted without the approval that
gates it. The approval check runs after a node is chosen, because the digest
binds the node id and cannot be evaluated before one exists.

### The bug only an end-to-end test could find

`fs.read@1` shipped with a 1 MiB output ceiling against a `MAX_FRAME_BYTES`
limit of 256 KiB. Every dispatch failed frame validation before it was sent —
the capability was undispatchable, not generous. Both numbers were individually
reasonable, which is why unit tests on either side were happy.

The ceiling is now 200 000 bytes, and a catalog-wide test asserts that no
capability declares more output than a dispatch frame can carry.

### Status

- **591 tests pass** under `-W error` with real PostgreSQL; lint and strict
  types clean.
- A scoped `fs.read@1` now runs end to end through the real handshake, session,
  and dispatch path, and returns the file's contents.
- Still granted to no node.

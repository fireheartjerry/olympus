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

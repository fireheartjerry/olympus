# Universal Computer Control Architecture

## 1. Requirement

The target is literal: Fire should eventually be able to perform essentially any digital task Jerry can perform, including unfamiliar software and unexpected interface states. It should also exploit capabilities humans do not have: APIs, parallel workers, exact state inspection, durable workflows, and machine-speed reaction.

The implementation must avoid the two common failures:

1. API-only automation that breaks the moment an application has no integration.
2. Raw mouse-and-keyboard automation that is slow, brittle, opaque, and unable to prove what happened.

The correct architecture is a layered control stack.

## 2. Control hierarchy

### Layer 0: deterministic computation

Use code, parsers, CAS, database queries, and direct transformations when no external system needs to be operated.

### Layer 1: structured local and remote APIs

Use filesystem, Git, process, application, browser, cloud, and service APIs. This layer gives exact parameters, explicit errors, idempotency, and strong evidence.

### Layer 2: semantic application adapters

Wrap application-specific operations behind typed capabilities such as:

- open a project;
- run a test suite;
- create a branch;
- export a document;
- start a browser session;
- send a reviewed message.

### Layer 3: accessibility and UI object models

Use Windows UI Automation, macOS Accessibility, browser DOM/CDP, and application automation trees. Operate semantic controls rather than screen coordinates.

### Layer 4: visual computer use

Use screenshots/video, OCR only where necessary, multimodal state interpretation, pointer movement, typing, and visual verification. This is the universal fallback.

### Layer 5: physical and environmental operation

Use phone cameras, microphones, smart devices, robots, or other sensors/actuators where future objectives require physical context.

Fire should choose the highest reliable layer and fall back progressively.

## 3. Windows embodiment

### 3.1 System service

Runs without an interactive login and owns:

- outbound authenticated node connection;
- device identity and attestation;
- health and version reporting;
- pre-login-safe inspection;
- update staging and rollback;
- revocation and emergency shutdown;
- launch/monitor of the user-session companion after login.

It does not inject input into the desktop, read arbitrary user files, or inherit broad administrator privileges merely because it starts early.

### 3.2 User-session companion

Runs inside Jerry's interactive session and owns capabilities requiring that session:

- window inventory;
- screenshot or stream capture;
- UI Automation;
- pointer and keyboard input;
- clipboard mediation;
- app launching;
- browser handoff;
- notification and approval surfaces.

The service and companion communicate over a local authenticated channel with explicit capability separation.

### 3.3 Background workspaces

Fire should avoid fighting Jerry for the visible desktop. Prefer, in order:

1. WSL/container/headless execution;
2. headless browser profiles;
3. isolated application workspaces;
4. dedicated local VM or secondary machine;
5. active visible desktop only when the task requires it or Jerry explicitly transfers control.

Windows desktop licensing and session isolation must be verified before promising concurrent independent GUI sessions on one consumer machine. The architecture must not depend on imaginary multi-session behavior.

## 4. Capability progression

Each capability is introduced in a separate slice with catalog entry, provider, scope, operator surface, end-to-end reachability, failure tests, live grant ceremony, and revocation drill.

### UCC-01 `process.inspect@1`

Read-only bounded process metadata:

- executable identity and publisher/hash;
- PID, start time, resource totals;
- no command line, environment, handles, or memory by default;
- filters and output ceilings;
- evidence that the provider did not exceed the requested fields.

### UCC-02 `desktop.window_inventory@1`

Read-only active-session window list:

- stable window handles scoped to a session;
- application identity;
- title redaction policy;
- visibility, bounds, focus state;
- no screen pixels yet.

### UCC-03 `desktop.launch_app@1`

Allowlisted application launch:

- typed application ID, never arbitrary executable path;
- fixed launch recipes and optional pre-approved parameter schema;
- no elevation;
- duplicate-launch reconciliation;
- process/window evidence;
- cancellation and timeout.

### UCC-04 `screen.capture@1`

Bounded still capture:

- specified monitor/window/region;
- explicit sensitivity and redaction policy;
- image digest and dimensions;
- no indefinite streaming;
- raw artifact retention expiry.

### UCC-05 `desktop.focus_window@1`

Reversible local mutation:

- only handles returned by current inventory;
- session binding;
- restore previous focus where possible;
- refuses secure desktops and elevation surfaces.

### UCC-06 `input.sequence@1`

A bounded, context-bound input sequence:

- target window identity;
- expected precondition screenshot/UI-tree digest;
- maximum actions and duration;
- no password or secure-desktop input;
- pause on state divergence;
- typed per-action evidence;
- immediate freeze/cancel.

This should arrive after semantic UI Automation, not before.

### UCC-07 `browser.session@1`

Governed browser worker:

- isolated profile and trust zone;
- DOM/CDP operations first;
- screenshots/traces;
- credential and download policy;
- prompt-injection boundary;
- external-effect approvals and reconciliation.

### UCC-08 `shell.powershell@1`

Not arbitrary PowerShell. Start with an allowlisted command catalog:

- typed verb and arguments;
- fixed executable/script digests;
- constrained working directory;
- environment allowlist;
- output and runtime ceilings;
- no encoded commands or dynamic evaluation;
- explicit mutation classification.

### UCC-09 `agent.codex@1` and `agent.claude@1`

Coding-agent sessions:

- objective contract and repository scope;
- isolated worktree;
- bounded runtime and concurrency;
- model/provider budget;
- no direct protected-branch push;
- test and diff receipts;
- verifier before merge.

### UCC-10 `desktop.stream@1`

Read-only stream for long visual tasks:

- adaptive frame rate;
- content-aware diffs;
- redaction;
- short raw retention;
- bandwidth ceilings;
- explicit user-session indication.

### UCC-11 takeover workflow v1

Compose the above. Do **not** enable a raw `desktop.takeover@1` that bypasses them.

## 5. Computer-use control loop

For each visual step:

1. capture bounded state;
2. infer UI objects and confidence;
3. prefer semantic control;
4. bind action to expected state;
5. execute one bounded action or atomic sequence;
6. capture post-state;
7. verify intended change;
8. stop or replan on divergence.

The loop must not spray clicks until something looks right, the traditional automation strategy of people who enjoy incident response.

## 6. Learning unfamiliar software

Fire may learn through:

- observing Jerry's demonstrations;
- accessibility-tree exploration;
- official documentation;
- safe sandbox exploration;
- recording successful procedures as candidate skills;
- replaying candidate skills under changed state;
- independent verification before promotion.

A learned skill is versioned, scoped, tested, and tied to application versions. It does not become authority merely because Jerry once demonstrated it.

## 7. Acceptance standard for human-level control

A domain is mature when Fire can:

- complete representative tasks without handcrafted scripts;
- recover from at least ten classes of unexpected UI state;
- choose structured versus visual control correctly;
- operate while Jerry is absent;
- pause immediately on manual conflict;
- prove effects;
- survive node and control-plane restart;
- stay within scope and budget;
- learn and retain procedures without silent privilege growth.

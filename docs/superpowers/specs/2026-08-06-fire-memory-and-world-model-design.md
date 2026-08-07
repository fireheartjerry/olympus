# Perception, Memory, and World Model

## 1. Objective

Fire should remain continuously aware of Jerry's relevant digital environment and eventually selected physical context. Continuous awareness must not be confused with permanent raw recording.

The architecture is:

```text
sensor/event -> bounded raw buffer -> event segmentation -> semantic extraction
-> provenance and trust labeling -> salience/goal scoring -> memory proposal
-> reconciliation -> durable memory or expiry
```

## 2. Perception streams

### Digital

- screen/window state;
- filesystem changes;
- terminal and IDE events;
- browser state;
- messages, email, calendar;
- Git and cloud operations;
- device and application health;
- financial and work systems where authorized.

### Physical, later

- microphone;
- phone and room cameras;
- location;
- wearable/health signals;
- smart-home state;
- nearby-device context.

Each stream has separate consent, sensitivity, retention, and processing policy.

## 3. Raw buffers

Raw media should generally live in encrypted circular buffers with strict expiry:

- screen diffs: seconds to minutes;
- interaction traces: minutes to hours for active jobs;
- audio: short rolling buffer sufficient for wake phrase/context;
- camera/video: event-triggered or manually elevated retention;
- application logs: task-scoped retention.

A memory workflow may pin a segment only when policy permits and its future utility justifies it. The pin itself is audited.

## 4. Event extraction

Perception workers convert streams into typed events:

- active project changed;
- build failed with error digest;
- Jerry selected option B;
- a deadline appeared;
- a message created a commitment;
- a user demonstrated a procedure;
- an application entered an unexpected state;
- a security anomaly occurred.

Events carry timestamps, source identity, content digest, trust label, confidence, entities, sensitivity, and references to any still-live raw buffer.

## 5. Memory classes

### Working memory

Current objective, recent observations, active hypotheses, and short-lived scratch context.

### Episodic memory

What happened: projects, decisions, interactions, successes, failures, and turning points.

### Semantic memory

Stable facts and relationships distilled from episodes.

### Procedural memory

How to perform tasks, including application version, preconditions, expected states, and verification.

### Relational memory

People, communication history, commitments, boundaries, and context.

### Jerry-model memory

Evidence signals and confirmed preferences used to predict Jerry.

### Fire self-memory

Fire's own operational experiences, failure patterns, tool reliability, and improvement history.

## 6. Canonical memory record

A durable memory needs:

- immutable ID and digest;
- structured content and optional embedding;
- source event IDs;
- provenance;
- confidence;
- sensitivity;
- valid-time and recorded-time;
- supersession and contradiction links;
- retention policy;
- access policy;
- model/version that extracted it.

Vector retrieval is an index, not the canonical record.

## 7. Memory promotion

A candidate's score uses:

- salience;
- relevance to active and long-horizon goals;
- novelty;
- likely future utility;
- confidence;
- sensitivity cost;
- recurrence;
- Jerry-model value.

High sensitivity does not automatically mean “never remember.” It means stronger encryption, access restriction, retention review, and minimization.

## 8. Contradictions and truth maintenance

Fire must not overwrite memories silently. It records:

- new evidence;
- whether it supports, contradicts, or supersedes prior memory;
- confidence updates;
- unresolved conflicts;
- owner corrections.

Queries return the current best-supported view plus material uncertainty.

## 9. World model

The world model is a time-aware graph of:

- people;
- projects;
- devices;
- services;
- files;
- tasks;
- commitments;
- resources;
- goals;
- locations;
- current states and causal relationships.

It supports queries such as:

- What is Jerry currently trying to finish?
- Which machine contains the authoritative uncommitted changes?
- What commitments were created by yesterday's conversation?
- Which services are blocking the launch?
- What does Fire expect Jerry to do next?

## 10. Privacy and bystanders

Continuous perception will encounter other people's information. Fire should:

- process locally where practical;
- retain meaning rather than indefinite raw media;
- isolate sensitive relational memory;
- avoid exposing inferred facts gratuitously;
- support context-specific privacy modes;
- obey applicable recording and consent laws;
- never convert bystander speech into authority.

## 11. First implementation sequence

1. event contracts and provenance;
2. task-scoped screen/filesystem/browser events;
3. short-term working-memory store;
4. semantic memory proposals and manual review;
5. contradiction and supersession model;
6. procedural skill extraction from demonstrations;
7. selective raw-buffer retention;
8. richer audio/video perception;
9. continuous world-model maintenance.

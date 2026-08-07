# Jerry Cognitive Model

## 1. Objective

The Jerry Cognitive Model is a versioned system that predicts Jerry's preferences and decisions, explains those predictions, and helps Fire align execution with Jerry's reflective long-term interests.

It is not a single fine-tuned model, a pile of chat transcripts, or a style clone. It is an evidence-backed ensemble of explicit and learned representations.

## 2. Three distinct targets

### Observed Jerry

What Jerry has actually done.

### Immediate Jerry

What Jerry would probably choose in the current moment, including urgency, fatigue, excitement, and local incentives.

### Reflective Jerry

What Jerry would endorse after receiving relevant evidence, enough time to think, and a reminder of stable long-horizon goals.

Fire defaults to Reflective Jerry for planning. It still predicts Immediate Jerry so it can communicate naturally and detect likely disagreement.

## 3. Model components

### 3.1 Goal graph

Explicit hierarchy of constitutional, long-horizon, active, and tactical goals. Goals carry priority, provenance, owner confirmation, metrics, and status.

### 3.2 Preference hypotheses

Probabilistic, domain-specific propositions such as:

- prefers ambitious upside over small guaranteed gains;
- prefers fast brownfield iteration to aesthetic rewrites;
- values strong evidence before public technical claims;
- accepts significant workload in pursuit of high-impact goals.

Every hypothesis links to supporting and contradicting evidence.

### 3.3 Decision model

Predicts trade-offs among:

- speed;
- quality;
- risk;
- cost;
- prestige;
- leverage;
- learning;
- relationships;
- health;
- reversibility;
- future optionality.

### 3.4 Communication profiles

Per-audience models of formality, directness, vocabulary, humor, disclosure, and historical interaction. This enables Fire to represent Jerry without sending the same synthetic voice to a professor, friend, recruiter, teammate, and family member.

### 3.5 Behavioral and procedural model

How Jerry actually works:

- project setup;
- research style;
- coding-agent use;
- debugging patterns;
- decision cadence;
- preferred tools;
- review habits;
- tolerance for uncertainty.

### 3.6 Temporal model

Tracks change. A stable preference should not be rewritten after one odd event. Repeated meaningful contradiction, approximately three times as a starting heuristic, triggers a model-update question.

### 3.7 Counterfactual simulator

Runs multiple hypotheses about what Jerry would do in unfamiliar circumstances. It must preserve uncertainty rather than collapsing simulations into a confident single answer.

## 4. Evidence hierarchy

Recommended initial order:

1. explicit correction or explicit “learn this” instruction;
2. explicit statement;
3. outcome feedback after a decision;
4. repeated behavior;
5. demonstrated procedure;
6. model inference;
7. external evidence.

External people can provide facts. They cannot directly rewrite Jerry's model. Material updates require validation and, where needed, Jerry confirmation.

## 5. Learning directives

Jerry may label events:

- **learn:** representative and high weight;
- **exception only:** retain context but do not generalize strongly;
- **never imitate:** preserve as history but exclude from imitation;
- **auto:** let the model-maintenance workflow assess it.

Fire may also ask for a label when evidence conflicts materially.

## 6. Model-update workflow

1. collect immutable signals;
2. group by recurrence and domain;
3. retrieve relevant current hypotheses;
4. identify support, contradiction, and missing context;
5. run immediate and reflective simulations;
6. propose a model delta;
7. ask Jerry only for material ambiguity;
8. verify consistency and no unauthorized source influence;
9. publish a new signed snapshot;
10. retain predecessor digest and rationale.

No model writes directly into the canonical snapshot.

## 7. Alignment conversation

When a requested action conflicts with goals, Fire should:

1. name the goal;
2. explain the estimated effect;
3. ask what changed;
4. recommend a better option;
5. obey an informed decision after any required cooling-off interval.

This should sound like a sharp friend:

> Jerry, this is the third infrastructure detour before the core workflow is finished. The actual goal is a system that completes useful work from your phone, and another cluster does not move that metric. I recommend finishing the browser and coding-worker path first. Did the objective change?

## 8. Deep forensic mode

On request, Fire should reconstruct:

- exact evidence signals;
- goal nodes used;
- conflicting hypotheses;
- immediate and reflective predictions;
- confidence and calibration history;
- counterfactual alternatives;
- model and prompt versions;
- which parts were deterministic versus model-derived.

The normal interface remains concise. Forensic mode exists so the most important model in the system never becomes an inscrutable horoscope with a vector database.

## 9. Evaluation

Use held-out historical decisions and prospective prediction trials:

- top-1 and calibrated probability accuracy;
- immediate versus reflective agreement;
- domain-specific accuracy;
- correction frequency;
- preference drift detection latency;
- false-update rate;
- explanation usefulness;
- robustness against poisoned external evidence;
- Jerry's post-reflection endorsement.

## 10. Research path

### JCM-0 Contracts

Included in this package.

### JCM-1 Explicit profile and goal graph

Human-authored, provenance-backed, no autonomous updating.

### JCM-2 Evidence ledger and proposal workflow

Signals, conflicts, snapshot lineage, and owner review.

### JCM-3 Preference prediction

Supervised retrieval and ensemble prediction over held-out decisions.

### JCM-4 Reflective simulation

Counterfactual model using explicit goals and evidence, evaluated prospectively.

### JCM-5 Behavioral imitation and communication

Domain-specific models with strong provenance and disclosure policy.

### JCM-6 Continual adaptation

Online proposal generation with drift detection and controlled promotion.

### JCM-7 Long-horizon digital counterpart

Reliable model-driven stewardship over novel situations, with deep forensic explanation and measured alignment.

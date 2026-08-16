# Precision Architecture

ReconForge's primary quality objective is **useful investigation precision**. Tool count is secondary.

## Evidence hierarchy

1. Direct, target-specific observation
2. Independent corroboration from a different source class
3. Historical confirmation
4. Application/code-context confirmation
5. Generic pattern/signature match

Higher levels should dominate weaker generic signals.

## Candidate lifecycle

```text
RAW OBSERVATION
      |
      v
CANONICAL OBSERVATION
      |
      +--> duplicate / known-benign / out-of-scope ----> SUPPRESS
      |
      v
SECURITY-RELEVANT CANDIDATE
      |
      v
CORRELATED HYPOTHESIS
      |
      +--> conflicting evidence -----------------------> DOWNGRADE
      |
      v
HUNTER QUEUE
      |
      v
HUMAN VALIDATION
```

## False-positive controls

### Source independence

Two outputs from the same underlying source should not count as two independent confirmations. For example, two parsers reading the same HTTP response do not create two independent evidence channels.

### Duplicate collapse

Equivalent URLs, routes, assets and observations are assigned stable identities. Repeated observations increase freshness/coverage rather than confidence by simple counting.

### Negative evidence

The scorer supports evidence that should lower confidence, including:

- known framework/static routes
- identical behavior across unrelated contexts
- non-controllable identifiers
- confirmed ownership relationship
- expected public exposure
- duplicate/known issue fingerprints
- expired or stale historical evidence

### Freshness

Historical evidence decays with time unless reconfirmed. An endpoint last observed years ago should not receive the same weight as a currently reachable endpoint.

### Explainability

Every Hunter Queue item must expose:

```text
why it exists
why it is prioritized
what evidence supports it
what evidence weakens it
which sources contributed
what manual question should be answered
```

## Adaptive orchestration

ReconForge should run the minimum useful set of sensors required to resolve uncertainty.

Example:

```text
Candidate API discovered
      |
      +--> Is HTTP behavior known? ------ no --> httpx
      |
      +--> Is route context known? ------ no --> Katana / archive sources
      |
      +--> JS references it? ------------ unknown --> JS adapter
      |
      +--> Object identifier present? --- no --> classifier only
      |
      +--> Auth context exists? --------- yes --> authorization hypothesis
```

This avoids both under-collection and tool-spam.

## Quality metrics

ReconForge must track:

- Top-5 precision
- Top-10 precision
- Top-20 precision
- candidate-to-investigation conversion
- useful-hypothesis rate
- duplicate rate
- N/A rate
- false-positive rate
- source contribution value
- median validation time
- stale-evidence rate

Do not advertise a success percentage until the benchmark methodology and corpus are public and reproducible.

## Security-research feedback

A researcher can label a candidate as:

```text
useful
not useful
false positive
duplicate
out of scope
validated vulnerability
needs more evidence
```

Feedback changes adapter/signal weights through versioned configuration rather than silently mutating the scoring model.

## Safety boundary

ReconForge is for authorized assessments. Automatic exploitation, credential attacks, account takeover, mass state-changing actions, and uncontrolled fuzzing are not part of the precision engine. Active sensors are policy-gated and must honor target scope and rate limits.

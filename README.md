# ReconForge

> Precision-first reconnaissance and security research framework for authorized testing.

ReconForge is built around one principle:

**Do not maximize findings. Maximize the probability that the next researcher action is worthwhile.**

It combines established reconnaissance sensors with a stateful evidence graph, semantic endpoint intelligence, workflow modeling, temporal analysis, differential evidence, explainable ranking, and researcher feedback.

## What makes ReconForge different

- **Evidence-first:** observations are facts; hypotheses remain hypotheses until human validation.
- **Precision-first:** multiple observations from the same source are not counted as independent corroboration.
- **Negative evidence:** evidence can reduce confidence, not only increase it.
- **Stateful:** repeated runs create deltas and identity continuity instead of scanner duplication.
- **Tool-agnostic:** Subfinder, Amass, DNS tooling, HTTPX, Katana, GAU, Wayback, Naabu, Nmap, Nuclei, and future sensors feed the same evidence model.
- **Research-oriented:** the Hunter Queue ranks investigation opportunities and explains why each item matters.
- **Feedback-aware:** researcher outcomes can calibrate signal weights without introducing an opaque black-box model.
- **Scope-conscious:** active collection is explicit and all hypotheses remain subject to authorization and program rules.

## Architecture

```text
Scope / Policy
      |
      v
Tool Discovery -----> Execution Profiles
      |
      v
Sensor Adapters
      |
      v
Observation Bus
      |
      +---- passive asset discovery
      +---- HTTP / service discovery
      +---- crawling / JS intelligence
      +---- historical sources
      +---- targeted active enrichment
      |
      v
Canonicalization + Deduplication
      |
      v
Asset / Evidence Graph
      |
      +---- endpoints
      +---- parameters
      +---- objects / identifiers
      +---- technologies
      +---- workflows
      +---- temporal state
      |
      v
Cross-source Correlation
      |
      +---- positive evidence
      +---- negative evidence
      +---- source independence
      |
      v
Hypothesis Engine
      |
      v
Confidence / Novelty / Quality
      |
      v
Hunter Queue
      |
      v
Human Validation
      |
      v
Feedback -> calibration
```

## Current capabilities

### Reconnaissance fabric

Real process-backed adapters and tool discovery for passive and explicitly active reconnaissance. Tool output is parsed into provenance-aware observations.

### Asset intelligence

Graph-backed identities connect hosts, URLs, endpoints, technologies, JavaScript, objects, and related observations. Historical sources are kept distinct from current evidence.

### Endpoint intelligence

ReconForge classifies APIs, GraphQL, authentication, administration, files, invitations, billing, account/team surfaces, object references, sensitive parameters, and state-changing operations.

### JavaScript intelligence

Client-side request references such as `fetch`, Axios calls, API paths, GraphQL routes, and absolute URLs are extracted as structured route evidence.

### Workflow intelligence

Related operations are grouped into workflow families such as invitation, file, billing, account, and team flows. Ordering hints provide manual research questions without automatically executing workflow abuse.

### Historical and temporal intelligence

ReconForge distinguishes new, persistent, historical-only, and disappeared observations. Historical existence is never treated as proof of current exposure.

### Authorized differential research

Researchers can compare explicitly supplied response fixtures across authorized contexts. Status, headers, body fingerprints, schema keys, and researcher-supplied object-reference overlap become evidence for an authorization hypothesis—not an automatic vulnerability verdict.

### Researcher feedback

Useful, noisy, and duplicate outcomes can be recorded against individual signals. ReconForge uses conservative, interpretable priors so feedback improves ranking without turning the engine into an unexplained model.

## CLI

```bash
# Inspect installed sensors
reconforge doctor

# Passive-first scan
reconforge scan example.com

# Explicitly enable active collection for an authorized target
reconforge scan example.com --active

# Show prioritized investigations
reconforge queue --limit 20

# Compare current and historical URL inventories
reconforge history-diff current.txt historical.txt

# Compare two authorized response fixtures
reconforge auth-diff account-a.json account-b.json \
  --endpoint https://example.com/api/object/123 \
  --object-overlap
```

## Safety boundary

ReconForge is intended for systems and data you are authorized to assess. It does not automatically perform account takeover, destructive actions, mass exploitation, or definitive vulnerability confirmation. Active collection should be used only within explicit scope, rate limits, and program rules.

## Measuring quality

ReconForge does not claim a universal vulnerability success rate. The project is designed to make that measurable. Releases should track top-N investigation precision, false-positive rate, duplicate rate, N/A rate, time to useful hypothesis, and the proportion of queue items a researcher accepts as worth manual investigation.

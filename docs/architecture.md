# ReconForge architecture

ReconForge is a stateful evidence-processing system. External collectors are interchangeable; the internal data model is stable.

```text
                         SCOPE POLICY
                              |
                              v
                      ORCHESTRATOR / RUN
                              |
         +--------------------+--------------------+
         |                    |                    |
         v                    v                    v
     PASSIVE               ACTIVE               CODE/WEB
   DISCOVERY               PROBING             INTELLIGENCE
         |                    |                    |
         +--------------------+--------------------+
                              |
                              v
                      OBSERVATION BUS
                              |
                              v
                        NORMALIZATION
                              |
                              v
                       DEDUP / IDENTITY
                              |
                              v
                         ASSET GRAPH
                              |
               +--------------+--------------+
               |              |              |
               v              v              v
          ENDPOINTS        OBJECTS        WORKFLOWS
               |              |              |
               +--------------+--------------+
                              |
                              v
                    CORRELATION / CONTEXT
                              |
                    +---------+---------+
                    |                   |
                    v                   v
               POSITIVE              NEGATIVE
               EVIDENCE              EVIDENCE
                    |                   |
                    +---------+---------+
                              v
                       HYPOTHESIS ENGINE
                              |
                              v
                      CONFIDENCE ENGINE
                              |
                              v
                        HUNTER QUEUE
                              |
                              v
                      HUMAN VALIDATION
                              |
                              v
                       FEEDBACK / LABELS
                              |
                              +------> recalibration
```

## Design rules

### Evidence is immutable
An observation records what a collector saw, where it came from, and when it was seen. Downstream components can derive new interpretations without mutating the original evidence.

### Stable identity prevents inflation
Assets and observations receive canonical identities. Multiple equivalent URLs, repeated crawls, and overlapping collectors should collapse into the same entity before ranking.

### Provenance is preserved
Each observation records collector/source, run ID, time, and evidence hash. Correlation must be able to distinguish independent sources from duplicated pipelines.

### Current state beats historical state
Historical evidence increases context and novelty, but historical-only observations cannot be treated as current vulnerabilities or current exposure.

### Context beats keywords
`/admin`, `?id=`, `upload`, `graphql`, or a framework version are useful features, not vulnerability verdicts.

### Hypotheses are explicit research questions
A hypothesis records its type, supporting evidence, counter-evidence, confidence, novelty, and status.

### Human validation remains authoritative
ReconForge prioritizes what to investigate. It must not silently turn heuristics into confirmed vulnerabilities.

## Major subsystems

- `adapters/`: translate external collector output into observations.
- `intelligence/normalize.py`: deterministic canonicalization.
- `intelligence/classify.py`: semantic endpoint/parameter/object classification.
- `intelligence/correlate.py`: evidence fusion and graph relationships.
- `intelligence/score.py`: explainable confidence and prioritization.
- `storage/`: durable state for repeated reconnaissance.
- `queue/`: ranked investigation work items.
- `policy/`: authorization scope, exclusions, rate limits, and collection safety.
- `feedback/`: researcher outcomes used to measure and recalibrate ranking.

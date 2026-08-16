# ReconForge

> Precision-first reconnaissance and security research framework for authorized testing.

ReconForge is designed around a simple principle:

**Do not maximize findings. Maximize the probability that a researcher should investigate the next item.**

It combines discovery, HTTP/endpoint intelligence, JavaScript analysis, historical correlation, evidence modeling, explainable confidence scoring, and a focused Hunter Queue.

## Design goals

- Low false-positive rate through multi-signal correlation and negative evidence.
- High-value prioritization instead of raw URL volume.
- Evidence-first observations with provenance, timestamps, and source attribution.
- Explainable scoring: every priority decision can be traced to evidence.
- Human-led validation: ReconForge generates hypotheses, not automatic vulnerability claims.
- Stateful reconnaissance: repeated runs produce deltas instead of duplicate noise.
- Adapter-based architecture so established tools can be integrated without becoming hard dependencies.
- Explicit scope boundaries for authorized security research.

## Core model

```text
Scope
  -> Discovery
  -> Observation
  -> Normalization
  -> Classification
  -> Correlation
  -> Hypothesis
  -> Confidence / Novelty
  -> Hunter Queue
  -> Human Validation
  -> Feedback
```

## Repository layout

```text
reconforge/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── architecture.md
│   ├── scoring.md
│   └── roadmap.md
├── src/
│   └── reconforge/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── observation.py
│       │   ├── hypothesis.py
│       │   └── target.py
│       ├── storage/
│       │   ├── __init__.py
│       │   └── sqlite.py
│       ├── intelligence/
│       │   ├── __init__.py
│       │   ├── normalize.py
│       │   ├── classify.py
│       │   ├── correlate.py
│       │   └── score.py
│       └── adapters/
│           └── __init__.py
└── tests/
    └── test_models.py
```

## Current status

**Phase 0 — foundation**

The initial repository establishes stable domain models, deterministic normalization, an explainable scoring contract, and a SQLite storage boundary. Tool adapters and active collection will be added on top of these contracts.

## Safety boundary

ReconForge is intended for assets you are authorized to assess. It does not attempt automatic account takeover, mass exploitation, or automatic vulnerability confirmation. High-confidence research hypotheses remain subject to human validation and program scope.

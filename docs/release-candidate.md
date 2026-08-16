# ReconForge Release Candidate

## Quality standard

ReconForge is release-candidate quality when the implementation preserves:

- strict target scope
- evidence provenance and immutable evidence identity
- source-aware deduplication
- secret redaction in logs and audit events
- resumable execution
- bounded, interpretable feedback calibration
- executable regression coverage
- empirical Top-N precision measurements
- researcher-readable investigation rationale

## Deliberate non-goals

ReconForge does not automatically declare a vulnerability from a pattern match. Authorization, business-logic, secret, and object signals remain hypotheses until validated in an authorized research context.

## Release metrics

Every release should publish:

- Top-5 / Top-10 / Top-20 queue precision
- useful / noisy / duplicate / N/A rates
- false-positive regression status
- mean time to useful hypothesis
- signal-family utility
- collection cost per accepted hypothesis
- resumability and audit coverage

## Enterprise scaling path

The distributed worker seam is intentionally declarative: workers exchange scoped jobs and normalized observations, while the evidence model remains centralized. A production backend can be added without changing the researcher-facing intelligence contracts.

# ReconForge release-quality gates

A release should not be called research-grade merely because more adapters were added.

## Required gates

1. Scope gate: active adapters require explicit authorized scope and opt-in policy.
2. Evidence gate: observations have provenance and stable identity.
3. Deduplication gate: repeated sensor output does not inflate confidence.
4. Regression gate: known noisy cases remain suppressed.
5. Precision gate: Top-N queue quality is measured on a stable labeled corpus.
6. Audit gate: tool selection, run stages, and outcomes are reconstructable.
7. Secret-handling gate: sensitive values are redacted from normal logs and benchmark fixtures.
8. Resume gate: interrupted long-running scans can continue without restarting completed stages.

## Success metrics

- Top-5 / Top-10 / Top-20 investigation precision
- useful-hypothesis rate
- false-positive rate
- duplicate rate
- N/A rate
- mean time to useful hypothesis
- cost per accepted hypothesis

ReconForge reports measured results rather than claiming a universal vulnerability success percentage.

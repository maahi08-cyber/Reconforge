# ReconForge Benchmark Corpus

The benchmark is designed to measure **investigation quality**, not raw scanner volume.

Each case should contain:

- target/application family
- authorized scope metadata
- observations available to ReconForge
- expected security-relevant signals
- known-noise signals
- labeled Hunter Queue usefulness

## Required metrics

- Top-5 precision
- Top-10 precision
- Top-20 precision
- useful-hypothesis rate
- duplicate rate
- N/A rate
- mean time to useful hypothesis

## Labels

`useful` — worth focused manual investigation

`noisy` — technically valid observation but low research value

`duplicate` — already represented by stronger evidence

`n/a` — not actionable for the target/context

## Principle

A benchmark must not reward ReconForge for generating more candidates. A release is better only when the highest-ranked candidates become more useful or when equivalent usefulness is reached with less analyst time.

# ReconForge false-positive regression corpus

This corpus protects precision when classifiers and ranking rules evolve.

Each case should contain:

- `input`: the observation or snippet that triggered a signal
- `expected`: `useful`, `noisy`, `duplicate`, or `n/a`
- `expected_family`: signal family that should or should not fire
- `reason`: why the case is a useful regression

High-value regression cases include:

- documentation/example API keys
- public JWT examples
- random UUIDs with no ownership context
- framework/admin routes that are intentionally public
- duplicate discoveries from multiple passive sources
- Splunk-like strings that are not HEC credentials
- real credential-shaped values inside non-secret test fixtures
- endpoints whose object IDs are server-generated and non-controllable

Do not store live credentials in the corpus.

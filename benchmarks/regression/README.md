# ReconForge false-positive regression corpus

This corpus protects precision when classifiers, correlation rules, and ranking rules evolve.

Each case should contain:

- `id`: stable regression identifier
- `family`: authorization, secretintel, input_surface, business_logic, or exposure
- `input`: sanitized observation or snippet
- `expected`: `useful`, `noisy`, `duplicate`, or `n/a`
- `must_not`: hypotheses that must not be emitted
- `reason`: why the case is a useful regression

High-value cases include:

- documentation/example API keys
- public JWT examples
- random UUIDs without ownership context
- framework/admin routes intentionally public
- duplicate discoveries from multiple passive sources
- Splunk-like strings that are not HEC credentials
- credential-shaped values inside synthetic test fixtures
- object IDs that are server-generated and non-controllable
- parameters that look like redirect/callback inputs but are never interpreted as URLs

Regression fixtures must use synthetic values. Never store live credentials, session
material, customer data, private URLs, or production request bodies.

A new confirmed false positive should become a regression case before the ranking rule
that produced it is considered fixed.

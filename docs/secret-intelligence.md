# ReconForge Sensitive-Data Intelligence

ReconForge treats client-side sensitive-data exposure as a first-class research signal.

## What it looks for

The JavaScript intelligence layer recognizes high-confidence credential formats such as AWS access-key IDs, GitHub tokens, Google API keys, Stripe live keys, Slack tokens, SendGrid keys, Twilio-style API keys, JWTs, private-key headers, and Splunk HEC-style authorization tokens.

It also has a conservative generic detector for high-entropy values that appear beside secret-like identifiers such as `api_key`, `token`, `secret`, `authorization`, `bearer`, or `hec`.

## Precision rules

- Strong provider-specific formats receive the highest base confidence.
- Generic high-entropy strings require secret-like context.
- Test/example/dummy JWT-like values are downgraded.
- Duplicate candidates are collapsed.
- Raw secret values are never printed by the CLI; findings are redacted.
- A secret-shaped string is an observation, not proof of validity, privilege, or exploitability.
- Context determines research priority: a token beside an active-looking API endpoint is more interesting than an isolated placeholder in a bundle.

## Splunk HEC example

A source such as:

```text
Authorization: Splunk <token>
```

is classified as a `splunk_hec_authorization` candidate. ReconForge records the type, confidence, line, context and a redacted fingerprint rather than copying the token into normal output.

## CLI

```bash
reconforge js-analyze app.js
reconforge js-analyze app.js --base-url https://example.com
```

The command reports both route intelligence and sensitive-data candidates, allowing the Hunter Queue to prioritize genuinely interesting client-side exposures.

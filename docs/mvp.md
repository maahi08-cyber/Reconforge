# ReconForge MVP

## Objective

Turn large-scale reconnaissance into a small, explainable Hunter Queue with low false-positive pressure.

## Pipeline

```text
Target + Scope
    -> tool discovery
    -> passive asset discovery
    -> URL/history collection
    -> normalization
    -> endpoint classification
    -> graph ingestion
    -> source-aware correlation
    -> workflow extraction
    -> hypothesis generation
    -> confidence / novelty scoring
    -> SQLite persistence
    -> Hunter Queue
```

## First-class modules

### Real adapters

- Subfinder: passive subdomain enumeration.
- Amass: asset/relationship discovery.
- GAU / Waybackurls: historical URL evidence.
- HTTPX: HTTP status/title/technology/web-server fingerprinting.
- Katana: crawl and JavaScript/route discovery.
- DNSx: DNS resolution and validation.
- Naabu: controlled port discovery.
- Nmap: targeted service/version context.
- Nuclei: reproducible template signals; never direct findings.

### Intelligence

- Stable observation identities.
- Source-family aware deduplication.
- Endpoint and parameter feature extraction.
- Asset graph and relationships.
- Historical current-vs-archive deltas.
- Workflow family inference.
- Authorized-context differential fingerprints.
- Explainable confidence scoring.

## Precision rules

A single keyword, template match, object ID, or scanner output cannot independently produce a high-confidence research hypothesis. Independent evidence must be correlated, and negative evidence can downgrade or suppress a candidate.

Historical observations are not treated as current exposure unless current evidence corroborates them.

Authenticated differential analysis accepts researcher-supplied response fingerprints or captured fixtures. It does not automatically test another account's objects or attempt exploitation.

## CLI

```bash
reconforge doctor
reconforge scan example.com
reconforge scan https://example.com --active
reconforge queue --limit 20
```

Use active mode only for an authorized target and only when the engagement permits active probing.

# ReconForge engineering principles

## Sensor philosophy

ReconForge treats each external tool as a specialized sensor. A sensor is valuable only when its output can be normalized, attributed, correlated, and used to answer a research question.

### Subdomain and asset sensors
- **Subfinder**: broad passive subdomain enumeration and source attribution.
- **Amass**: attack-surface mapping and relationship discovery.
- **Certificate Transparency**: certificate-derived hostname relationships.
- **dnsx / puredns / shuffledns**: resolution, validation, and controlled candidate expansion.

### HTTP and web sensors
- **httpx**: reachability, status, TLS, headers, titles, technology fingerprints.
- **Katana**: route discovery, forms, JS/XHR/fetch observations, and optional headless exploration.
- **GAU / Wayback**: historical routes and parameter vocabulary.
- **Hakrawler**: additional lightweight crawl coverage.

### Service sensors
- **Naabu**: port discovery to establish service surface.
- **Nmap**: targeted service/version identification after candidate ports are known.

### Research-signal sensors
- **Nuclei**: reproducible template signals and technology/exposure hints. Template matches are never treated as vulnerability confirmation.
- **JS endpoint extraction**: route and API vocabulary enrichment.

## Capability-driven execution

The orchestrator should not run every sensor on every target. It selects sensors based on the current target state and missing evidence.

Examples:

```text
Only domains known
  -> passive asset collection
  -> DNS validation
  -> HTTP probing

New authenticated web application
  -> crawl
  -> JS/XHR extraction
  -> endpoint classification
  -> historical correlation

Open non-HTTP service discovered
  -> targeted Nmap service/version pass
```

This makes execution cheaper, safer, and more precise.

## Source independence

Multiple observations are not automatically multiple confirmations. ReconForge tracks `source_family` so two adapters backed by the same underlying dataset cannot inflate corroboration.

## Negative evidence

Negative observations reduce candidate confidence. Examples include historical-only routes with no current confirmation, known public/static resources, non-controllable identifiers, or an endpoint whose behavior is already explained by established application context.

## Researcher feedback

A future validation loop will label Hunter Queue items as useful, benign, duplicate, out-of-scope, or confirmed. The ranking engine should learn source reliability and pattern reliability from these labels while keeping the decision process explainable.

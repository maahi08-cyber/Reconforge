# ReconForge tooling strategy

ReconForge uses external tools as **evidence producers**, not as the product itself. Each adapter emits normalized observations with provenance, timestamps, and confidence metadata.

## Discovery and asset inventory

| Tool/source | Role | Primary evidence |
|---|---|---|
| subfinder | passive subdomain discovery | discovered names, source attribution |
| amass | passive/active asset correlation | names, DNS relations, infrastructure links |
| crt.sh / CT feeds | certificate transparency | hostnames, certificate relationships |
| dnsx | DNS resolution and validation | resolved hosts, records |
| shuffledns | controlled DNS permutation resolution | discovered/resolved names |
| puredns | high-throughput DNS resolution | validated DNS candidates |

## HTTP and web surface mapping

| Tool/source | Role | Primary evidence |
|---|---|---|
| httpx | HTTP probing/fingerprinting | status, title, tech, TLS, headers |
| katana | crawling and route discovery | endpoints, forms, links, JS assets |
| gau | historical URL collection | historical endpoints and parameters |
| waybackurls | historical URL collection | archived route evidence |
| hakrawler | lightweight crawl signal | links/forms/assets |

## JavaScript and API intelligence

| Tool/source | Role | Primary evidence |
|---|---|---|
| subjs | JS discovery | script inventory |
| LinkFinder | endpoint extraction | routes, API references |
| SecretFinder | candidate secret/credential references | contextual secret-like strings |
| nuclei | template-based security signals | versioned, reproducible observations |

## Port and service context

| Tool/source | Role | Primary evidence |
|---|---|---|
| naabu | controlled port discovery | open TCP ports |
| nmap | targeted service/version identification | services, versions, banners |

## Intelligence and enrichment

| Source | Role |
|---|---|
| Censys / compatible APIs | internet exposure and certificate context |
| SecurityTrails / compatible APIs | DNS and passive DNS context |
| URLScan | historical/current web observations |
| ProjectDiscovery APIs where available | enrichment and managed data |

## Important architecture rule

No external tool is allowed to directly create a `finding`.

The pipeline is:

```text
external tool
  -> adapter
  -> observation
  -> normalization
  -> deduplication
  -> correlation
  -> negative-evidence filter
  -> hypothesis
  -> confidence scoring
  -> Hunter Queue
```

## Precision rules

1. Repeated observations from the same source do not count as independent corroboration.
2. Two adapters consuming the same underlying source do not count as independent corroboration.
3. Template matches are evidence, not confirmation.
4. Historical-only observations are never treated as current exposure without current evidence.
5. A security-relevant URL pattern by itself cannot create a high-confidence authorization or business-logic hypothesis.
6. Negative evidence can suppress or downgrade candidates.
7. Every Hunter Queue item must expose the evidence chain and the reason it was ranked.

## Operational safety

ReconForge is designed for authorized assessments. Active discovery must honor configured scope, rate limits, exclusions, and safe-request policies before execution.
